// PERM-02 — shared relation-tuple types for the Relationships surface.
//
// Mirrors the ory-keto-client v26.2.0 `Relationship` model (and the backend's
// JSON pass-through): namespace/object/relation are always present; the subject
// is EITHER a direct subject_id OR a subject_set (namespace:object#relation),
// never both. The list endpoint wraps these in `relation_tuples` with an opaque
// `next_page_token` (empty string on the last page).

/** A subject-set reference: another relation rendered as ns:object#relation. */
export type SubjectSet = {
  namespace: string;
  object: string;
  relation: string;
};

/** A single Keto relation tuple (matches the crate `Relationship` model). */
export type RelationTuple = {
  namespace: string;
  object: string;
  relation: string;
  subject_id?: string;
  subject_set?: SubjectSet;
};

/** The paginated list response (`Relationships` model). */
export type RelationshipsResponse = {
  next_page_token?: string;
  relation_tuples?: RelationTuple[];
};

/**
 * Render a tuple's subject for display: a direct subject_id verbatim, or a
 * subject_set as `namespace:object#relation`. Returns "—" if neither is set
 * (should not happen — the backend enforces exactly one).
 */
export function subjectLabel(tuple: {
  subject_id?: string;
  subject_set?: SubjectSet;
}): string {
  if (tuple.subject_id) return tuple.subject_id;
  if (tuple.subject_set) {
    const s = tuple.subject_set;
    return `${s.namespace}:${s.object}#${s.relation}`;
  }
  return "—";
}
