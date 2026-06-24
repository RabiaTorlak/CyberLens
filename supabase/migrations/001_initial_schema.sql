-- Detection Engineering platform: initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS public.rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    rule_type TEXT NOT NULL DEFAULT 'custom',
    content TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT,
    event_type TEXT,
    hostname TEXT,
    username TEXT,
    raw_data JSONB NOT NULL DEFAULT '{}'::JSONB,
    event_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES public.rules(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    matched_log_id UUID REFERENCES public.logs(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_created_at ON public.rules (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON public.logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_event_time ON public.logs (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON public.alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON public.alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON public.alerts (status);

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS rules_updated_at ON public.rules;
CREATE TRIGGER rules_updated_at
    BEFORE UPDATE ON public.rules
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS alerts_updated_at ON public.alerts;
CREATE TRIGGER alerts_updated_at
    BEFORE UPDATE ON public.alerts
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow all for rules" ON public.rules;
CREATE POLICY "Allow all for rules"
    ON public.rules
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

DROP POLICY IF EXISTS "Allow all for logs" ON public.logs;
CREATE POLICY "Allow all for logs"
    ON public.logs
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

DROP POLICY IF EXISTS "Allow all for alerts" ON public.alerts;
CREATE POLICY "Allow all for alerts"
    ON public.alerts
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);
