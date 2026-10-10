-- Additive public experiment only. The deployment pipeline must apply this schema explicitly.
-- singleton keeps the first experiment exclusive; no takeover or automatic reset.
CREATE TABLE ci_reboot_sessions (
  session TEXT PRIMARY KEY,
  singleton INTEGER NOT NULL UNIQUE CHECK(singleton=1),
  binding_json TEXT NOT NULL,
  origin_json TEXT NOT NULL,
  controller_public_key TEXT NOT NULL,
  observer_public_key TEXT,
  version INTEGER NOT NULL,
  sequence INTEGER NOT NULL,
  state TEXT NOT NULL,
  nonce TEXT,
  events_json TEXT NOT NULL,
  signatures_json TEXT NOT NULL
);
