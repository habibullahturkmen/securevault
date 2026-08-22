-- Add an inactivity deadline alongside the absolute expires_at deadline.
-- Existing sessions fail closed: their last known activity is creation time,
-- and their old absolute deadline is clamped to four hours after creation.
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz;

UPDATE sessions
SET last_seen_at = created_at,
    expires_at = LEAST(expires_at, created_at + interval '4 hours');

ALTER TABLE sessions
    ALTER COLUMN last_seen_at SET DEFAULT now(),
    ALTER COLUMN last_seen_at SET NOT NULL;
