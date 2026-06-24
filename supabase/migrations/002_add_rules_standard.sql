ALTER TABLE public.rules
    ADD COLUMN IF NOT EXISTS standard TEXT;

CREATE INDEX IF NOT EXISTS idx_rules_standard ON public.rules (standard);
