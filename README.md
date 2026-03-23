# Unified AI Gateway — Python API

Backend **FastAPI** + **asyncpg** + **Uvicorn**, kompatibel dengan frontend folder **`../unified`** (port dev **8787**). Ringkasan monorepo: [`../README.md`](../README.md).

## Setup

```bash
cd server
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
copy .env.example .env    # isi DATABASE_URL & JWT_SECRET
```

## Migrasi & seed

```bash
python -m scripts.migrate
set ENABLE_DEV_SEED=true
python -m scripts.seed
```

### Reset database (hapus semua data + migrasi + dummy)

**Hanya non-production.** Menghapus isi tabel (`TRUNCATE`), menjalankan migrasi/ensure, lalu seed seperti di atas.

```bash
set ENABLE_DEV_RESET=true
set ENABLE_DEV_SEED=true
python -m scripts.reset_and_seed
```

Setelah seed, contoh akun:

| | |
|--|--|
| Email | `admin@example.com` |
| Password | `password123` (default; bisa diubah lewat `SEED_ADMIN_PASSWORD`) |
| Gateway API key (plain) | `dev_apikey_change_me` (atau `SEED_GATEWAY_API_KEY`) |
| `/api/auth/dev-login` | Tanpa body memakai email/password default di atas |

Variabel opsional: `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_GATEWAY_API_KEY`.

## Menjalankan server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8787 --reload
```

- Health: `GET /`, `/ping`, `/healthz`
- OpenAPI: `/docs`, `/openapi.json` (jika `EXPOSE_OPENAPI=true`)
- WebSocket: `/ws?token=<JWT>`

## Variabel lingkungan utama

Lihat `.env.example`. Penting: `DATABASE_URL`, `JWT_SECRET`, `CORS_ALLOW_ALL` / `CORS_ORIGINS`, `ENABLE_RUNTIME_MIGRATIONS`, `ENABLE_DEV_LOGIN`, `ENABLE_INTERNAL_TEST_ROUTES`.

## Opsi performa

Untuk throughput mentah bisa dieksplorasi **Litestar + Granian**; stack default ini memilih dokumentasi + parity cepat (FastAPI + Uvicorn).
