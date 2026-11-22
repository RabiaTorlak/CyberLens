-- CyberLens — isteğe bağlı RLS sıkılaştırma (OTOMATİK UYGULANMAZ)
--
-- supabase/migrations/ içindeki varsayılan politikalar laboratuvar kolaylığı için
-- "Allow all" (USING TRUE) şeklindedir: anon anahtarına sahip herkes tüm tabloları
-- okuyup yazabilir. Bu dosya o politikaları kaldırır. RLS açık kaldığı ve hiçbir
-- politika olmadığı için anon/authenticated rolleri artık hiçbir satıra erişemez;
-- yalnızca RLS'i atlayan service_role anahtarı erişebilir.
--
-- Uygulamadan sonra:
--   * .env içindeki SUPABASE_KEY değerini service_role anahtarı yapın.
--   * Streamlit sunucu tarafında çalıştığı için anahtar tarayıcıya gönderilmez;
--     yine de .env dosyasını asla commit etmeyin ve paylaşmayın.
--
-- Uygulama: Supabase Dashboard > SQL Editor içine yapıştırıp çalıştırın.

DROP POLICY IF EXISTS "Allow all for rules" ON public.rules;
DROP POLICY IF EXISTS "Allow all for logs" ON public.logs;
DROP POLICY IF EXISTS "Allow all for alerts" ON public.alerts;
DROP POLICY IF EXISTS "Allow all for platform_settings" ON public.platform_settings;

ALTER TABLE public.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_settings ENABLE ROW LEVEL SECURITY;
