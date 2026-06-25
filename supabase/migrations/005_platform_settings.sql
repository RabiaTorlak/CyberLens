-- Global platform policies (SOAR toggle, etc.)

CREATE TABLE IF NOT EXISTS public.platform_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS platform_settings_updated_at ON public.platform_settings;
CREATE TRIGGER platform_settings_updated_at
    BEFORE UPDATE ON public.platform_settings
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();

INSERT INTO public.platform_settings (key, value)
VALUES ('global_policy', '{"soar_enabled": false}'::JSONB)
ON CONFLICT (key) DO NOTHING;

ALTER TABLE public.platform_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow all for platform_settings" ON public.platform_settings;
CREATE POLICY "Allow all for platform_settings"
    ON public.platform_settings
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);
