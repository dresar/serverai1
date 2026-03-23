"""Port server1/src/services/observabilitySchema.js"""
from __future__ import annotations

from app.db import Database


async def ensure_observability_schema(db: Database) -> None:
    stmts = [
        """alter table public.gateway_request_logs add column if not exists request_path text""",
        """alter table public.gateway_request_logs add column if not exists error_type text""",
        """alter table public.gateway_request_logs add column if not exists error_message text""",
        """alter table public.gateway_request_logs add column if not exists credential_id uuid references public.provider_credentials(id) on delete set null""",
        """alter table public.gateway_request_logs add column if not exists client_auth_used boolean not null default false""",
        """alter table public.gateway_request_logs add column if not exists rate_limited boolean not null default false""",
        """alter table public.gateway_request_logs add column if not exists breaker_open boolean not null default false""",
        """alter table public.gateway_request_logs add column if not exists upstream_status integer""",
        """alter table public.gateway_request_logs add column if not exists detected_anomaly_types text[] not null default '{}'""",
        """alter table public.gateway_request_logs add column if not exists metadata jsonb not null default '{}'::jsonb""",
        """create index if not exists idx_gateway_logs_provider_created on public.gateway_request_logs(provider, created_at desc)""",
        """create index if not exists idx_gateway_logs_status_created on public.gateway_request_logs(status_code, created_at desc)""",
        """create index if not exists idx_gateway_logs_credential_created on public.gateway_request_logs(credential_id, created_at desc)""",
        """create table if not exists public.gateway_alerts (
      id uuid not null default gen_random_uuid() primary key,
      tenant_id uuid not null references public.users(id) on delete cascade,
      severity text not null,
      category text not null,
      title text not null,
      message text not null,
      provider text,
      api_key_id uuid references public.api_keys(id) on delete set null,
      credential_id uuid references public.provider_credentials(id) on delete set null,
      status text not null default 'active',
      dedupe_key text,
      metadata jsonb not null default '{}'::jsonb,
      created_at timestamp with time zone not null default now(),
      updated_at timestamp with time zone not null default now(),
      acknowledged_at timestamp with time zone,
      read_at timestamp with time zone,
      resolved_at timestamp with time zone
    )""",
        """create index if not exists idx_gateway_alerts_tenant_created on public.gateway_alerts(tenant_id, created_at desc)""",
        """create index if not exists idx_gateway_alerts_tenant_status on public.gateway_alerts(tenant_id, status, created_at desc)""",
        """create index if not exists idx_gateway_alerts_dedupe on public.gateway_alerts(tenant_id, dedupe_key, created_at desc)""",
    ]
    for sql in stmts:
        await db.query(sql)
