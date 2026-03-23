# Rencana migrasi: Node (`server1`) → Python (`pythonserver`)

## Ringkasan analisis `server1`

| Area | Isi |
|------|-----|
| **Entry** | `index.js` — Hono + `@hono/node-server`, WebSocket `ws`, graceful shutdown |
| **App** | `app.js` — ~1.7k baris: CORS, JWT, rate limit, OpenAPI, dashboard API, gateway proxy |
| **DB** | PostgreSQL (`pg`), pool, `schema.sql` + migrasi runtime (`ensureApiKeySchema`, `observabilitySchema`, `ai_models`) |
| **Auth** | JWT (jose, HS256, iss/aud), bcrypt password, HMAC opsional untuk gateway |
| **Gateway** | API key + Basic client auth, HMAC, proxy ke Gemini/Groq/Apify/Cloudinary/ImageKit, circuit breaker, cache L1/L2 |
| **Lain** | Prometheus metrics, upload cleanup interval, observability (logs, alerts, anomaly) |

---

## Stack rekomendasi (2026 — API cepat & modern)

| Lapisan | Pilihan | Alasan |
|---------|---------|--------|
| **Framework** | **FastAPI** | Async native, validasi Pydantic v2, OpenAPI otomatis, ekosistem besar |
| **Server ASGI** | **Uvicorn** + `[standard]` (uvloop + httptools di Linux/macOS) | Throughput tinggi untuk I/O-bound |
| **DB async** | **asyncpg** | Driver PostgreSQL async paling cepat untuk Python |
| **HTTP klien** | **HTTPX** (async) | Proxy upstream & pemanggilan Gemini/Groq |
| **JWT** | **PyJWT** | Kompatibel dengan token yang diterbitkan Node (HS256, iss/aud) |
| **Password** | **bcrypt** | Selaras dengan `bcryptjs` di Node |
| **Upload** | **cloudinary** (SDK) + httpx untuk ImageKit | Sama dengan perilaku Node |
| **Metrics** | **prometheus_client** | `/metrics` Prometheus |
| **Config** | **pydantic-settings** | Env + validasi |

**Catatan:** **Litestar** / **Granian** juga sangat cepat; FastAPI dipilih untuk produktivitas + dokumentasi kompatibel dengan frontend yang sudah ada.

---

## Fase rencana (banyak tahap)

### Fase 0 — Prasyarat
- [x] Salin `db/schema.sql` ke `pythonserver/db/`
- [x] Python 3.11+ (disarankan 3.12)
- [x] Variabel env sama dengan Node: `DATABASE_URL`, `JWT_SECRET`, `PORT`, dll.

### Fase 1 — Kerangka proyek
- [x] `requirements.txt` / struktur paket `app/`
- [x] `config.py` (mirror `server1/src/config.js`)
- [x] `db.py` — pool asyncpg, lifespan

### Fase 2 — Keamanan
- [x] JWT encode/decode (sub, email, displayName, iss, aud, 7 hari)
- [x] HMAC SHA-256 hex (pesan sama dengan Node)
- [x] Dependency `get_current_user` (Bearer)

### Fase 3 — Infrastruktur lokal
- [x] `memory_store` + rate limit (sliding window seperti Node)
- [x] `circuit_breaker` untuk upstream gateway
- [x] Cache API key in-memory (TTL positif/negatif)

### Fase 4 — Migrasi DB
- [x] Jalankan `schema.sql` + `ensure_*` (api_keys, gateway logs, observability, ai_models)

### Fase 5 — Layanan domain
- [x] `api_keys_service` — create, list, get, rotate
- [x] `ai_models_service`
- [x] `playground_service` — chat Gemini/Groq, upload Cloudinary/ImageKit
- [x] `observability_service` — log gateway, list logs/alerts, monitoring, analytics

### Fase 6 — Router HTTP
- [x] `/`, `/ping`, `/healthz`, `/metrics`
- [x] `/api/auth/*` (login, register, dev-login, me, profile, change-password)
- [x] `/api/keys/*`, dashboard keys, stats, logs, alerts, monitoring
- [x] `/api/credentials/*`, `/api/clients/*`, `/api/settings`
- [x] `/api/playground/*`

### Fase 7 — Gateway publik
- [x] `/gateway/verify`
- [x] `/gateway/cloudinary/upload`, `/gateway/imagekit/upload`
- [x] `/gateway/gemini/chat`, `/gateway/groq/chat`
- [x] `/gateway/{provider}/{path:path}` — proxy ALL

### Fase 8 — WebSocket
- [x] `/ws?token=JWT` — broadcast tenant (untuk realtime alerts opsional)

### Fase 9 — Background
- [x] Interval cleanup `upload_expiry` (asyncio)
- [x] Health refresh interval (opsional)

### Fase 10 — Skrip operasional
- [x] `python -m scripts.migrate` / `seed` (mirip npm)

### Fase 11 — Integrasi frontend
- [x] Update `unified-ai-gateway/package.json` — `dev:server` → uvicorn
- [x] Proxy Vite → port 8787
- [x] Dokumentasi README

### Fase 12 — Penghapusan Node
- [x] Hapus folder `server1` setelah parity fungsional

### Fase 13 — Uji & hardening (lanjutan)
- [ ] Tes integrasi endpoint kritikal
- [ ] Samakan pesan error persis dengan Node (opsional)
- [ ] Redis untuk rate limit multi-instance (opsional produksi)

---

## Parity API (checklist)

Semua path yang dipakai frontend + gateway client harus tersedia dengan method & response shape yang kompatibel.

---

## Cara jalan lokal

```bash
cd pythonserver
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
copy .env.example .env    # isi DATABASE_URL & JWT_SECRET
python -m scripts.migrate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8787
```

Di folder `unified-ai-gateway`: `npm run dev` (frontend + backend Python).
