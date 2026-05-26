# Secrets

Files in this directory are mounted as Docker secrets into the stack. **Never
commit a real secret** — only the `*.example` placeholders are tracked; the real
files are gitignored.

## Observability profile (Phase 16, OBS-05)

The opt-in `observability` compose profile's Grafana reads its admin password
from a secret file instead of the insecure default `admin/admin`
(`GF_SECURITY_ADMIN_PASSWORD=$__file{/run/secrets/grafana_admin_password}`), and
its login form is disabled (`GF_AUTH_DISABLE_LOGIN_FORM=true`) — Grafana is
reachable only through the authenticated backend reverse-proxy (plan 16-02).

Before running `docker compose --profile observability up`, create the secret:

```sh
cp secrets/grafana_admin_password.example secrets/grafana_admin_password
# then edit secrets/grafana_admin_password and set a strong, unique value
```

A plain `docker compose up` (no `--profile observability`) does NOT start Grafana
and does NOT require this file.
