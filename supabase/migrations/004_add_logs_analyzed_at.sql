ALTER TABLE public.logs
    ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_logs_analyzed_at ON public.logs (analyzed_at);
