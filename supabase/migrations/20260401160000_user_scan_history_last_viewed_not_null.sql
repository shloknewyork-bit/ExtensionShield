-- Ensure user scan history rows always have last_viewed_at populated so
-- authenticated /api/history ordering is stable for both new and existing scans.

ALTER TABLE public.user_scan_history
  ADD COLUMN IF NOT EXISTS last_viewed_at timestamptz;

UPDATE public.user_scan_history
SET last_viewed_at = COALESCE(last_viewed_at, created_at, now())
WHERE last_viewed_at IS NULL;

ALTER TABLE public.user_scan_history
  ALTER COLUMN last_viewed_at SET DEFAULT now();

ALTER TABLE public.user_scan_history
  ALTER COLUMN last_viewed_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS user_scan_history_user_last_viewed_idx
  ON public.user_scan_history (user_id, last_viewed_at DESC);
