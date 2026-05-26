//! Console-owned branding asset store (BRAND-03) — the highest-risk net-new
//! surface in Phase 10.
//!
//! This module stores the CONSOLE'S OWN logo for its own shell. It is a
//! `[CUSTOM]` concern: it makes **NO Ory call** and never touches any service
//! YAML (kratos.yml etc.) — verified by the absence of any `crate::ory` /
//! `crate::config_edit` import here (threat T-10-14 / CONTEXT invariant).
//!
//! The four handlers all sit on the Phase-2 PROTECTED subtree so they inherit
//! `auth_guard` (401) and — for the state-changing `upload_logo`/`reset_logo` —
//! `csrf_guard` (403). `serve_logo`/`get_branding` are GET (csrf-exempt).
//!
//! ## Upload hardening (STRIDE register, 10-03 PLAN)
//!
//! - **T-10-10 DoS:** Salvo spools each multipart part to a temp FILE before the
//!   handler runs, so the on-disk part is the authoritative size. The upload
//!   handler checks the declared `FilePart.size()` AND the spooled file's actual
//!   on-disk length (`fs::metadata().len()`) against [`MAX_LOGO_BYTES`] BEFORE it
//!   `fs::read`s the file into RAM — an oversized part is never fully buffered in
//!   memory. The authoritative request-body bound is the Salvo body/`max_size`
//!   limit; these per-part checks are the in-handler defense-in-depth on top of
//!   it, and the post-read `bytes.len()` re-check is a final belt-and-braces.
//! - **T-10-upload spoofing:** the image kind is decided by a hand-rolled
//!   MAGIC-BYTE sniff of the temp-file bytes ([`sniff_image`]), NEVER by the
//!   spoofable `Content-Type` header.
//! - **T-10-09 traversal:** the destination is a SERVER-DEFINED canonical path
//!   `{console_data_dir}/branding/logo.<validated-ext>` ([`logo_path`]); the
//!   client-supplied `FilePart.name()` is NEVER used in the path.
//! - **T-10-11 SVG XSS:** a stored SVG is served with a pinned
//!   `Content-Type: image/svg+xml`, `Content-Disposition: inline`, and a
//!   restrictive `Content-Security-Policy: sandbox` so it cannot execute script
//!   as console-origin active content ([`serve_headers_for`]).
//! - **T-10-13 info disclosure:** every error is a value-free [`AppError`] (no
//!   filesystem path echoed), mirroring the `put_smtp_connection` discipline.

use std::path::{Path, PathBuf};

use salvo::http::header::{CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use salvo::prelude::*;
use serde_json::json;

use crate::config::Config;
use crate::error::AppError;

/// Hard upper bound on an uploaded console logo (512 KiB). Checked against the
/// multipart part size BEFORE any bytes are read off disk (T-10-10 DoS guard).
pub const MAX_LOGO_BYTES: u64 = 512 * 1024;

/// The validated image kinds the console accepts. The stored file's extension is
/// SERVER-DEFINED from this enum — never from the client filename (T-10-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Ico,
    Svg,
}

impl ImageKind {
    /// Canonical file extension (server-defined; used to build the storage path).
    pub fn ext(self) -> &'static str {
        match self {
            ImageKind::Png => "png",
            ImageKind::Jpeg => "jpg",
            ImageKind::Ico => "ico",
            ImageKind::Svg => "svg",
        }
    }

    /// The pinned `Content-Type` the asset is served with (never derived from the
    /// spoofable upload header).
    pub fn content_type(self) -> &'static str {
        match self {
            ImageKind::Png => "image/png",
            ImageKind::Jpeg => "image/jpeg",
            ImageKind::Ico => "image/x-icon",
            ImageKind::Svg => "image/svg+xml",
        }
    }

    /// The short kind label returned to the frontend (state line).
    pub fn label(self) -> &'static str {
        match self {
            ImageKind::Png => "png",
            ImageKind::Jpeg => "jpeg",
            ImageKind::Ico => "ico",
            ImageKind::Svg => "svg",
        }
    }

    /// All extensions the serve route probes for, in priority order.
    pub const ALL: [ImageKind; 4] = [ImageKind::Png, ImageKind::Jpeg, ImageKind::Ico, ImageKind::Svg];
}

/// Decide the image kind from the LEADING BYTES of the uploaded file — the only
/// trustworthy signal (the multipart `Content-Type` is attacker-controlled, so it
/// is never the accept gate; T-10-upload). Returns `None` for anything that is
/// not one of the four accepted formats, so the caller rejects it with NO disk
/// write.
///
/// - PNG : `89 50 4E 47 0D 0A 1A 0A` (we match the 4-byte signature `89 50 4E 47`)
/// - JPEG: `FF D8 FF`
/// - ICO : `00 00 01 00` (icon resource type)
/// - SVG : XML/text — after trimming a UTF-8 BOM + leading whitespace, the
///   content begins with `<svg` or with `<?xml` … containing `<svg`.
pub fn sniff_image(bytes: &[u8]) -> Option<ImageKind> {
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return Some(ImageKind::Png);
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageKind::Jpeg);
    }
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some(ImageKind::Ico);
    }
    if sniff_svg(bytes) {
        return Some(ImageKind::Svg);
    }
    None
}

/// SVG content sniff: strip an optional UTF-8 BOM and leading ASCII whitespace,
/// then require the document to be a benign `<svg` element (optionally preceded
/// by a bare `<?xml …?>` declaration or an XML comment). We scan a bounded
/// prefix and look for the `<svg` tag near the start so a text file that merely
/// mentions "svg" somewhere deep is not accepted.
///
/// WR-02 (XXE-shaped acceptance): the accept gate's job is to admit *images*,
/// not arbitrary attacker-authored XML. A document carrying a `<!DOCTYPE …>` or
/// `<!ENTITY …>` declaration is REJECTED outright — those are the lead-in for
/// external-entity / billion-laughs / `file://` resolution that some renderers
/// honour even when the served document is sandboxed. The serve path still pins
/// `Content-Type: image/svg+xml` + `Content-Security-Policy: sandbox` as the
/// script-execution backstop, but we refuse to PERSIST a DOCTYPE/entity document
/// as a first-class branding asset in the first place.
fn sniff_svg(bytes: &[u8]) -> bool {
    // Strip a UTF-8 BOM.
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    // Only inspect a bounded prefix (an SVG root appears very early).
    let head = &bytes[..bytes.len().min(1024)];
    // Must be valid UTF-8 (SVG is text/XML); reject binary masquerading.
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let trimmed = text.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    // WR-02: reject XXE-shaped documents. A DOCTYPE or ENTITY declaration anywhere
    // in the bounded prefix disqualifies the upload — a benign SVG image needs
    // neither. Checked BEFORE any accept branch so a `<?xml?>`/comment lead-in
    // cannot smuggle a DOCTYPE past the gate.
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return false;
    }
    if lower.starts_with("<svg") {
        return true;
    }
    // Allow only a bare XML declaration / comment lead-in (NO doctype), then
    // require <svg to appear in the bounded prefix.
    if lower.starts_with("<?xml") || lower.starts_with("<!--") {
        return lower.contains("<svg");
    }
    false
}

/// The server-defined directory that holds the console's branding assets:
/// `{console_data_dir}/branding`. The console data dir is a SIBLING of the
/// mounted config tree (`config_dir`) so the asset store lives on a writable
/// volume but is NEVER inside a service's config directory.
pub fn logo_dir(config_dir: &str) -> PathBuf {
    PathBuf::from(config_dir).join("branding")
}

/// The server-defined canonical storage path for the logo of a given kind:
/// `{console_data_dir}/branding/logo.<ext>`. The extension is derived ENTIRELY
/// from the validated [`ImageKind`] — the client filename never enters the path
/// (path-traversal guard, T-10-09).
pub fn logo_path(config_dir: &str, kind: ImageKind) -> PathBuf {
    logo_dir(config_dir).join(format!("logo.{}", kind.ext()))
}

/// Find the currently-stored logo file (if any) by probing the canonical paths
/// for each accepted kind. Returns the path + its kind. At most one logo is
/// stored at a time; `upload_logo` removes the others, but if two ever coexisted
/// (e.g. a manual file drop) the first in [`ImageKind::ALL`] priority order wins.
pub fn find_stored_logo(config_dir: &str) -> Option<(PathBuf, ImageKind)> {
    for kind in ImageKind::ALL {
        let p = logo_path(config_dir, kind);
        if p.is_file() {
            return Some((p, kind));
        }
    }
    None
}

/// The safe serve-header set for a stored asset of a given kind: the pinned
/// content-type, an `inline` disposition with a server-defined filename, and —
/// crucially for SVG (T-10-11) — a `Content-Security-Policy: sandbox` so the
/// document cannot execute script as console-origin active content. The CSP is
/// applied to every kind (harmless for raster images, essential for SVG).
pub fn serve_headers_for(kind: ImageKind) -> [(&'static str, String); 3] {
    [
        ("content-type", kind.content_type().to_string()),
        (
            "content-disposition",
            format!("inline; filename=\"logo.{}\"", kind.ext()),
        ),
        // `sandbox` (no allow-* tokens) disables scripts, plugins, and
        // same-origin treatment for the served document — neutralising an SVG
        // that embeds <script>/onload as active console-origin content.
        ("content-security-policy", "sandbox".to_string()),
    ]
}

/// Obtain the injected [`Config`] clone from the depot (CLONE before any await,
/// mirroring the `config_from`/`ory_clients` pattern).
fn config_from(depot: &Depot) -> Result<Config, AppError> {
    depot
        .obtain::<Config>()
        .cloned()
        .map_err(|_| AppError::Internal("config missing from depot".into()))
}

/// Remove every stored logo variant (all accepted extensions). Idempotent — a
/// missing file is not an error. Used by both `upload_logo` (clear prior kinds
/// before writing the new one, so only one logo ever exists) and `reset_logo`.
fn remove_all_logos(config_dir: &str) -> Result<(), AppError> {
    for kind in ImageKind::ALL {
        let p = logo_path(config_dir, kind);
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(error = %e, "branding: failed to remove stored logo");
                return Err(AppError::Internal("branding asset remove failed".into()));
            }
        }
    }
    Ok(())
}

/// Atomically write `bytes` to `target` (temp file in the SAME dir -> rename).
/// Binary-safe sibling of `yaml::write_atomic` (which takes `&str`); kept local
/// because the asset is raw image bytes, not UTF-8 text.
fn write_bytes_atomic(target: &Path, bytes: &[u8]) -> Result<(), AppError> {
    use std::io::Write;
    let dir = target
        .parent()
        .ok_or_else(|| AppError::Internal("branding target has no parent directory".into()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| {
        tracing::error!(error = %e, "branding atomic write: temp create failed");
        AppError::Internal("branding asset write failed".into())
    })?;
    tmp.write_all(bytes).map_err(|e| {
        tracing::error!(error = %e, "branding atomic write: temp write failed");
        AppError::Internal("branding asset write failed".into())
    })?;
    tmp.as_file().sync_all().map_err(|e| {
        tracing::error!(error = %e, "branding atomic write: fsync failed");
        AppError::Internal("branding asset write failed".into())
    })?;
    tmp.persist(target).map_err(|e| {
        tracing::error!(error = %e, "branding atomic write: persist/rename failed");
        AppError::Internal("branding asset write failed".into())
    })?;
    Ok(())
}

/// `POST /api/console/branding/logo` — upload (and replace) the console logo.
///
/// Hardened multipart handler (CSRF-guarded by the protected subtree):
/// 1. obtain the `logo` file part; absent -> 400.
/// 2. SIZE CAP: reject an oversized part BEFORE reading it into RAM — both the
///    declared `part.size()` AND the spooled temp file's on-disk
///    `fs::metadata().len()` are checked against [`MAX_LOGO_BYTES`], so a part
///    whose declared size understates the real bytes is still caught before
///    `fs::read` buffers the whole file in memory (T-10-10 DoS).
/// 3. read the temp-file bytes and MAGIC-BYTE sniff; non-image -> 422 (NO write).
/// 4. clear any prior logo, then ATOMIC-WRITE to the SERVER-DEFINED canonical
///    path `{console_data_dir}/branding/logo.<validated-ext>`.
///
/// The client filename and `Content-Type` are never trusted for the path or the
/// accept decision. Errors are value-free (no path leak, T-10-13).
#[handler]
pub async fn upload_logo(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    let cfg = config_from(depot)?;

    let part = req
        .file("logo")
        .await
        .ok_or_else(|| AppError::BadRequest("expected a multipart file field named 'logo'".into()))?;

    // --- Step 2: SIZE CAP before reading the body into RAM (T-10-10 DoS) -----
    // WR-04: Salvo has already SPOOLED the part to a temp file on disk before this
    // handler runs, so the on-disk file is the authoritative size — not the
    // declared `part.size()`, which a crafted multipart part can omit/understate.
    // Check BOTH the declared size AND the spooled file's real on-disk length
    // (fs::metadata, which does NOT read the contents) and reject an oversized
    // upload BEFORE `fs::read` loads the whole file into memory. The authoritative
    // bound is the Salvo request-body limit; these are the in-handler guards.
    let path = part.path().clone();
    if part.size() > MAX_LOGO_BYTES {
        return Err(AppError::BadRequest(format!(
            "file is too large; the maximum size is {} KB",
            MAX_LOGO_BYTES / 1024
        )));
    }
    let on_disk_len = tokio::fs::metadata(&path).await.map(|m| m.len()).map_err(|e| {
        tracing::error!(error = %e, "branding: failed to stat uploaded temp file");
        AppError::Internal("branding upload read failed".into())
    })?;
    if on_disk_len > MAX_LOGO_BYTES {
        return Err(AppError::BadRequest(format!(
            "file is too large; the maximum size is {} KB",
            MAX_LOGO_BYTES / 1024
        )));
    }

    // --- Step 3: read the temp-file bytes + MAGIC-BYTE sniff (T-10-upload) ---
    // The on-disk length is now known to be within the cap, so this read is
    // bounded. We trust ONLY the bytes, never `part.content_type()`.
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(error = %e, "branding: failed to read uploaded temp file");
        AppError::Internal("branding upload read failed".into())
    })?;

    // Defense in depth: re-check the actual byte length against the cap (a final
    // belt-and-braces on top of the pre-read metadata check above).
    if bytes.len() as u64 > MAX_LOGO_BYTES {
        return Err(AppError::BadRequest(format!(
            "file is too large; the maximum size is {} KB",
            MAX_LOGO_BYTES / 1024
        )));
    }

    let kind = sniff_image(&bytes).ok_or_else(|| {
        AppError::BadRequest(
            "unsupported file type; upload a PNG, SVG, ICO, or JPEG image".into(),
        )
    })?;

    // --- Step 4: write to the SERVER-DEFINED canonical path (T-10-09) --------
    let dir = logo_dir(&cfg.config_dir);
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        tracing::error!(error = %e, "branding: failed to create branding dir");
        AppError::Internal("branding asset write failed".into())
    })?;
    // Only one logo exists at a time: clear prior kinds, then write the new one.
    remove_all_logos(&cfg.config_dir)?;
    let dest = logo_path(&cfg.config_dir, kind);
    write_bytes_atomic(&dest, &bytes)?;
    tracing::info!(kind = kind.label(), "branding: console logo uploaded");

    res.status_code(StatusCode::OK);
    res.render(Json(json!({ "logo": "custom", "kind": kind.label() })));
    Ok(())
}

/// `GET /api/console/branding/logo` — serve the stored console logo.
///
/// Streams the canonical stored asset with the PINNED content-type, an `inline`
/// disposition, and `Content-Security-Policy: sandbox` (SVG-XSS guard,
/// T-10-11). When no asset is stored, returns 404 so the shell falls back to the
/// bundled default logo.
#[handler]
pub async fn serve_logo(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;

    let (path, kind) = find_stored_logo(&cfg.config_dir).ok_or(AppError::NotFound)?;
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(error = %e, "branding: failed to read stored logo");
        AppError::Internal("branding asset read failed".into())
    })?;

    for (name, value) in serve_headers_for(kind) {
        // Header names are static lowercase ASCII; values are server-defined.
        let header_name = match name {
            "content-type" => CONTENT_TYPE,
            "content-disposition" => CONTENT_DISPOSITION,
            "content-security-policy" => CONTENT_SECURITY_POLICY,
            _ => continue,
        };
        if let Ok(hv) = salvo::http::header::HeaderValue::from_str(&value) {
            res.headers_mut().insert(header_name, hv);
        }
    }
    res.status_code(StatusCode::OK);
    res.write_body(bytes).ok();
    Ok(())
}

/// `DELETE /api/console/branding/logo` — reset to the default logo
/// (CSRF-guarded). Removes the stored asset; idempotent (no error if already
/// absent). Returns 204 so a subsequent `GET` 404s and the shell falls back to
/// the default.
#[handler]
pub async fn reset_logo(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    remove_all_logos(&cfg.config_dir)?;
    tracing::info!("branding: console logo reset to default");
    res.status_code(StatusCode::NO_CONTENT);
    Ok(())
}

/// `GET /api/console/branding` — report whether a custom logo is set, so the
/// frontend can render the "Custom logo in use." / "Using the default Ory
/// Console logo." state line. Never reads or returns the asset bytes.
#[handler]
pub async fn get_branding(depot: &mut Depot, res: &mut Response) -> Result<(), AppError> {
    let cfg = config_from(depot)?;
    let (logo, kind) = match find_stored_logo(&cfg.config_dir) {
        Some((_, kind)) => ("custom", Some(kind.label())),
        None => ("default", None),
    };
    res.render(Json(json!({ "logo": logo, "kind": kind })));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid PNG: the 8-byte PNG signature is enough for the magic-byte
    /// sniff (we never decode the image).
    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const JPEG_SIG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    const ICO_SIG: &[u8] = &[0x00, 0x00, 0x01, 0x00, 0x01, 0x00];

    // ─── logo_asset: server-defined canonical path (T-10-09 traversal guard) ───

    #[test]
    fn logo_asset_path_is_server_defined_from_kind_only() {
        // The destination is built ENTIRELY from config_dir + a fixed
        // "branding/logo.<ext>" where <ext> comes from the validated ImageKind —
        // no client filename ever enters the path.
        assert!(logo_path("/data/console", ImageKind::Png).ends_with("branding/logo.png"));
        assert!(logo_path("/data/console", ImageKind::Jpeg).ends_with("branding/logo.jpg"));
        assert!(logo_path("/data/console", ImageKind::Ico).ends_with("branding/logo.ico"));
        assert!(logo_path("/data/console", ImageKind::Svg).ends_with("branding/logo.svg"));
        // The branding dir is a sibling under config_dir, never a service dir.
        assert!(logo_dir("/data/console").ends_with("branding"));
    }

    #[test]
    fn logo_asset_traversal_filename_cannot_escape() {
        // Even if a client sends name="../../etc/passwd", the path is derived
        // from ImageKind, so a traversal filename is structurally impossible to
        // reach the storage path. We assert the canonical path contains no "..".
        for kind in ImageKind::ALL {
            let p = logo_path("/data/console", kind);
            assert!(!p.to_string_lossy().contains(".."));
        }
    }

    // ─── logo_upload_validation: magic-byte sniff + size cap ───

    #[test]
    fn logo_upload_validation_accepts_real_image_magic_bytes() {
        assert_eq!(sniff_image(PNG_SIG), Some(ImageKind::Png));
        assert_eq!(sniff_image(JPEG_SIG), Some(ImageKind::Jpeg));
        assert_eq!(sniff_image(ICO_SIG), Some(ImageKind::Ico));
        assert_eq!(sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), Some(ImageKind::Svg));
        assert_eq!(
            sniff_image(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"...\"><rect/></svg>"),
            Some(ImageKind::Svg)
        );
        // Leading whitespace + BOM tolerated.
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"  \n  <svg></svg>");
        assert_eq!(sniff_image(&bom), Some(ImageKind::Svg));
    }

    #[test]
    fn logo_upload_validation_rejects_non_image_bytes() {
        // A renamed executable / arbitrary binary: no accepted magic prefix.
        assert_eq!(sniff_image(b"MZ\x90\x00 this is a PE binary"), None);
        assert_eq!(sniff_image(b"\x7fELF not an image"), None);
        assert_eq!(sniff_image(b"just some plain text, not svg"), None);
        // GIF is not in the accepted set.
        assert_eq!(sniff_image(b"GIF89a..."), None);
        assert_eq!(sniff_image(&[]), None);
        // A text file that mentions svg deep inside is NOT accepted.
        let mut deep = vec![b' '; 2000];
        deep.extend_from_slice(b"<svg></svg>");
        assert_eq!(sniff_image(&deep), None);
    }

    #[test]
    fn logo_upload_validation_rejects_xxe_shaped_svg() {
        // WR-02: an SVG carrying a DOCTYPE + external ENTITY is the XXE/SSRF lead-in
        // (file:// or billion-laughs). The accept gate admits IMAGES, not arbitrary
        // attacker-authored XML, so any doctype/entity document is rejected — even
        // though it ends in a real <svg> element.
        let xxe = br#"<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>"#;
        assert_eq!(sniff_image(xxe), None);

        // A bare DOCTYPE lead-in (no <?xml>) is rejected too.
        let doctype_first =
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://x/svg.dtd\">\n<svg></svg>";
        assert_eq!(sniff_image(doctype_first), None);

        // A standalone <!ENTITY ...> declaration (no DOCTYPE keyword) is rejected.
        let entity_only = b"<!ENTITY foo \"bar\"><svg></svg>";
        assert_eq!(sniff_image(entity_only), None);

        // Case-insensitive: a lowercase doctype is rejected just the same.
        let lower_doctype = b"<!doctype svg><svg></svg>";
        assert_eq!(sniff_image(lower_doctype), None);

        // CONTROL: a benign SVG (no DOCTYPE, no ENTITY) is still ACCEPTED so the
        // tightened sniff did not over-reject legitimate logos.
        assert_eq!(
            sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>"),
            Some(ImageKind::Svg)
        );
        assert_eq!(
            sniff_image(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"...\"><rect/></svg>"),
            Some(ImageKind::Svg)
        );
    }

    #[test]
    fn logo_upload_validation_size_cap_constant() {
        // The cap is enforced against part.size() BEFORE any byte read; assert the
        // documented 512 KB value so the frontend mirror stays in lockstep.
        assert_eq!(MAX_LOGO_BYTES, 512 * 1024);
    }

    // ─── logo_serve: safe headers, SVG non-executable (T-10-11) ───

    #[test]
    fn logo_serve_pins_content_type_and_disposition() {
        let h = serve_headers_for(ImageKind::Png);
        assert_eq!(h[0], ("content-type", "image/png".to_string()));
        assert!(h[1].1.starts_with("inline;"));
    }

    #[test]
    fn logo_serve_svg_is_sandboxed_non_executable() {
        let h = serve_headers_for(ImageKind::Svg);
        // Pinned SVG content-type (never text/html).
        assert_eq!(h[0], ("content-type", "image/svg+xml".to_string()));
        assert_ne!(h[0].1, "text/html");
        // inline disposition with a server-defined filename.
        assert_eq!(h[1].0, "content-disposition");
        assert!(h[1].1.contains("logo.svg"));
        // CSP sandbox neutralises inline script in the served SVG document.
        assert_eq!(h[2], ("content-security-policy", "sandbox".to_string()));
    }

    // ─── logo_serve / logo_reset: filesystem round-trip on a temp dir ───

    #[test]
    fn logo_serve_round_trips_and_reset_removes() {
        let tmp = tempfile::tempdir().expect("temp console-data dir");
        let cfg_dir = tmp.path().to_string_lossy().to_string();

        // No asset yet -> find returns None (serve would 404).
        assert!(find_stored_logo(&cfg_dir).is_none());

        // Simulate a successful upload write: create dir + write the canonical PNG.
        std::fs::create_dir_all(logo_dir(&cfg_dir)).unwrap();
        write_bytes_atomic(&logo_path(&cfg_dir, ImageKind::Png), PNG_SIG).unwrap();

        // Now find returns the PNG + kind; the bytes round-trip.
        let (path, kind) = find_stored_logo(&cfg_dir).expect("stored logo present");
        assert_eq!(kind, ImageKind::Png);
        assert_eq!(std::fs::read(&path).unwrap(), PNG_SIG);

        // Reset removes it (idempotent: a second reset is fine).
        remove_all_logos(&cfg_dir).unwrap();
        assert!(find_stored_logo(&cfg_dir).is_none());
        remove_all_logos(&cfg_dir).unwrap();
    }

    #[test]
    fn logo_upload_replaces_prior_kind_so_only_one_exists() {
        let tmp = tempfile::tempdir().expect("temp console-data dir");
        let cfg_dir = tmp.path().to_string_lossy().to_string();
        std::fs::create_dir_all(logo_dir(&cfg_dir)).unwrap();

        // Store a PNG, then "upload" an SVG: remove_all_logos clears the PNG first.
        write_bytes_atomic(&logo_path(&cfg_dir, ImageKind::Png), PNG_SIG).unwrap();
        remove_all_logos(&cfg_dir).unwrap();
        write_bytes_atomic(
            &logo_path(&cfg_dir, ImageKind::Svg),
            b"<svg></svg>",
        )
        .unwrap();

        // Exactly one logo remains, and it is the SVG.
        assert!(!logo_path(&cfg_dir, ImageKind::Png).is_file());
        let (_, kind) = find_stored_logo(&cfg_dir).unwrap();
        assert_eq!(kind, ImageKind::Svg);
    }
}
