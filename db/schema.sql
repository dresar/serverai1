-- =============================================================================
-- Skema kanonis (Neon / PostgreSQL) — salin seluruh file ke SQL Editor.
-- =============================================================================
--
-- API Data (berita, cuaca, finansial, Hugging Face, RapidAPI, dll.) TIDAK punya
-- tabel terpisah: simpan di public.provider_credentials dengan:
--   provider_type = 'data'   (UI/dashboard; backend juga menerima 'ai' untuk LLM)
--   provider_name = slug     (lihat daftar di bawah)
--   credentials  = jsonb     (kunci API per penyedia; lihat kolom JSON)
--
-- Slug AI / media (contoh):
--   gemini, groq, apify, cloudinary, imagekit
--
-- Slug Data (gateway proxy + injeksi kredensial):
--   newsapi      → credentials: { "api_key" }
--   gnews        → { "api_key" } atau { "token" }
--   mediastack   → { "access_key" }
--   openweather  → { "appid" }
--   alphavantage → { "api_key" }
--   huggingface  → { "api_key" }
--   rapidapi     → { "api_key", "rapidapi_host" }  (host contoh: api-football-v1.p.rapidapi.com)
--
-- api_clients.allowed_providers dan api_keys.allowed_providers: text[] berisi
-- slug yang sama (mis. '{newsapi,openweather,rapidapi}').
--
-- =============================================================================

-- Users (login dashboard + tenant untuk API key)
CREATE TABLE IF NOT EXISTS public.users (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text,
  display_name text,
  hmac_secret text,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Kredensial penyedia (AI + data); satu baris per kombinasi user + provider + set kunci
CREATE TABLE IF NOT EXISTS public.provider_credentials (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  provider_name text NOT NULL,
  provider_type text NOT NULL DEFAULT 'ai',
  label text,
  credentials jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'active',
  total_requests bigint NOT NULL DEFAULT 0,
  failed_requests bigint NOT NULL DEFAULT 0,
  cooldown_until timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_provider_credentials_user ON public.provider_credentials(user_id, created_at DESC);

COMMENT ON TABLE public.provider_credentials IS $$Kunci API per tenant: provider_name = slug (gemini, newsapi, rapidapi, ...); credentials = JSON fleksibel.$$;

-- Klien API (dashboard / model lama)
CREATE TABLE IF NOT EXISTS public.api_clients (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT 'Unnamed',
  api_key text,
  is_active boolean NOT NULL DEFAULT true,
  rate_limit integer NOT NULL DEFAULT 100,
  allowed_providers text[] DEFAULT '{}',
  created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_clients_user ON public.api_clients(user_id, created_at DESC);

-- Kunci gateway (HMAC / quota); dipakai logging & proxy
CREATE TABLE IF NOT EXISTS public.api_keys (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  key_hash text NOT NULL UNIQUE,
  api_key_plain text,
  status text NOT NULL DEFAULT 'active',
  grace_until timestamp with time zone,
  rotated_from uuid REFERENCES public.api_keys(id) ON DELETE SET NULL,
  quota_per_minute integer NOT NULL DEFAULT 1000,
  allowed_providers text[] DEFAULT '{}',
  name text,
  client_username text,
  client_password_hash text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON public.api_keys(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON public.api_keys(key_hash);

-- Log permintaan gateway (observability)
CREATE TABLE IF NOT EXISTS public.gateway_request_logs (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  api_key_id uuid NOT NULL REFERENCES public.api_keys(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  provider text NOT NULL,
  method text NOT NULL DEFAULT 'GET',
  status_code integer,
  response_time_ms integer,
  origin_domain text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  request_path text,
  error_type text,
  error_message text,
  credential_id uuid REFERENCES public.provider_credentials(id) ON DELETE SET NULL,
  client_auth_used boolean NOT NULL DEFAULT false,
  rate_limited boolean NOT NULL DEFAULT false,
  breaker_open boolean NOT NULL DEFAULT false,
  upstream_status integer,
  detected_anomaly_types text[] NOT NULL DEFAULT '{}',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_gateway_logs_api_key_created ON public.gateway_request_logs(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_logs_tenant_created ON public.gateway_request_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_logs_provider_created ON public.gateway_request_logs(provider, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_logs_status_created ON public.gateway_request_logs(status_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_logs_credential_created ON public.gateway_request_logs(credential_id, created_at DESC);

-- Alert gateway (monitoring dashboard)
CREATE TABLE IF NOT EXISTS public.gateway_alerts (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  severity text NOT NULL,
  category text NOT NULL,
  title text NOT NULL,
  message text NOT NULL,
  provider text,
  api_key_id uuid REFERENCES public.api_keys(id) ON DELETE SET NULL,
  credential_id uuid REFERENCES public.provider_credentials(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'active',
  dedupe_key text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  acknowledged_at timestamp with time zone,
  read_at timestamp with time zone,
  resolved_at timestamp with time zone
);
CREATE INDEX IF NOT EXISTS idx_gateway_alerts_tenant_created ON public.gateway_alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_alerts_tenant_status ON public.gateway_alerts(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_alerts_dedupe ON public.gateway_alerts(tenant_id, dedupe_key, created_at DESC);

CREATE TABLE IF NOT EXISTS public.request_logs (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  error_message text,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_request_logs_user_created ON public.request_logs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS public.system_settings (
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  setting_key text NOT NULL,
  setting_value text,
  PRIMARY KEY (user_id, setting_key)
);

CREATE TABLE IF NOT EXISTS public.upload_expiry (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  credential_id uuid NOT NULL REFERENCES public.provider_credentials(id) ON DELETE CASCADE,
  provider text NOT NULL,
  external_id text NOT NULL,
  delete_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_upload_expiry_delete_at ON public.upload_expiry(delete_at);

-- Model playground (daftar model per provider; diselaraskan dengan app.services.ai_models)
CREATE TABLE IF NOT EXISTS public.ai_models (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  provider text NOT NULL,
  model_id text NOT NULL,
  display_name text,
  is_default boolean NOT NULL DEFAULT false,
  supports_vision boolean NOT NULL DEFAULT false,
  sort_order int NOT NULL DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  UNIQUE (provider, model_id)
);
CREATE INDEX IF NOT EXISTS idx_ai_models_provider ON public.ai_models(provider, sort_order);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_models_one_default ON public.ai_models(provider) WHERE (is_default = true);

INSERT INTO public.ai_models (provider, model_id, display_name, is_default, supports_vision, sort_order)
SELECT v.provider, v.model_id, v.display_name, v.is_default, v.supports_vision, v.sort_order
FROM (
  VALUES
    ('gemini'::text, 'gemini-2.5-flash'::text, 'Gemini 2.5 Flash'::text, true, true, 0),
    ('groq'::text, 'llama-3.2-3b-preview'::text, 'Llama 3.2 3B Instant'::text, true, false, 0),
    ('groq'::text, 'llama-3.1-70b-versatile'::text, 'Llama 3.1 70B Versatile'::text, false, false, 1),
    ('groq'::text, 'llama-3.2-90b-vision-preview'::text, 'Llama 3.2 90B Vision'::text, false, true, 2),
    ('groq'::text, 'llama-3.1-8b-instant'::text, 'Llama 3.1 8B Instant'::text, false, false, 3)
) AS v(provider, model_id, display_name, is_default, supports_vision, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM public.ai_models LIMIT 1);
