"""Port server1/src/services/playground.js — Gemini, Groq, Cloudinary, ImageKit."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import quote

import cloudinary
import cloudinary.uploader
import httpx

from app.db import Database
from app.services import ai_models as am

NO_SYMBOL = (
    "Aturan format jawaban: Jangan gunakan simbol asterisk (*) atau ** untuk bullet maupun bold. "
    "Untuk daftar/poin gunakan angka saja: 1, 2, 3, 4, dst. Tulis dalam teks biasa tanpa markdown atau simbol pemformat."
)


def _sanitize(text: str) -> str:
    if not isinstance(text, str):
        return text
    return re.sub(r"\*+|•+|\u2022+|_{3,}", "", text)


def _cred(obj: Any) -> dict:
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, str):
        try:
            return json.loads(obj)
        except json.JSONDecodeError:
            return {}
    return {}


async def chat_with_provider(
    db: Database,
    *,
    user_id: str,
    credential_id: str,
    prompt: str,
    image_base64: str = "",
    model_id: str | None = None,
) -> dict:
    r = await db.query(
        """select id, provider_name, credentials from public.provider_credentials
           where id = $1 and user_id = $2 and status = 'active' limit 1""",
        (credential_id, user_id),
    )
    if not r.rows:
        return {"error": "Credential not found or inactive"}
    cred = r.rows[0]
    credentials = _cred(cred["credentials"])
    provider = (cred.get("provider_name") or "").lower()
    resolved = (model_id or "").strip() or None
    if not resolved:
        resolved = await am.get_default_model_id(db, provider)
    if not resolved:
        return {"error": "Model tidak tersedia. Pilih model dari daftar."}
    if not await am.is_model_allowed(db, provider, resolved):
        return {"error": "Model tidak tersedia. Pilih model dari daftar."}

    if provider == "gemini":
        api_key = credentials.get("api_key") or credentials.get("apiKey")
        if not api_key:
            return {"error": "Gemini API key not set in credential"}
        model = resolved
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={quote(str(api_key), safe='')}"
        parts: list[dict] = [{"text": prompt or "Hello"}]
        if image_base64:
            b64 = re.sub(r"^data:image/\w+;base64,", "", image_base64)
            parts.append({"inline_data": {"mime_type": "image/jpeg", "data": b64}})
        body = {
            "contents": [{"role": "user", "parts": parts}],
            "systemInstruction": {"parts": [{"text": NO_SYMBOL}]},
            "generationConfig": {"temperature": 0.7, "maxOutputTokens": 2048},
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            res = await client.post(url, json=body)
        data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
        if res.status_code >= 400:
            return {"error": data.get("error", {}).get("message") or "Gemini API error", "raw": data}
        raw_text = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [{}])[0].get("text") or ""
        return {"text": _sanitize(raw_text), "model": model}

    if provider == "groq":
        api_key = credentials.get("api_key") or credentials.get("apiKey")
        if not api_key:
            return {"error": "Groq API key not set in credential"}
        groq_model = resolved
        has_img = bool(image_base64)
        if has_img:
            if not await am.get_model_supports_vision(db, "groq", groq_model):
                vm = await am.get_vision_model_id(db, "groq")
                if vm:
                    groq_model = vm
        content: list[dict] = [{"type": "text", "text": prompt or "Hello"}]
        if has_img:
            b64 = re.sub(r"^data:image/\w+;base64,", "", image_base64)
            content.append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}})
        body = {
            "model": groq_model,
            "messages": [
                {"role": "system", "content": NO_SYMBOL},
                {"role": "user", "content": content},
            ],
            "max_tokens": 2048,
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            res = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
        data = res.json() if res.content else {}
        if res.status_code >= 400:
            return {"error": data.get("error", {}).get("message") or "Groq API error", "raw": data}
        raw_text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        return {"text": _sanitize(raw_text), "model": data.get("model") or groq_model}

    return {"error": "Unsupported provider for chat. Use Gemini or Groq."}


def _short_cloudinary_url(full: str) -> str:
    if not isinstance(full, str):
        return full
    prefix = "https://res.cloudinary.com/"
    if full.startswith(prefix):
        return full[len(prefix) :]
    return full


def _short_public_id() -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b = secrets.token_bytes(10)
    return "".join(chars[x % len(chars)] for x in b)


async def upload_to_cloud(
    db: Database,
    *,
    user_id: str,
    credential_id: str,
    provider: str,
    buffer: bytes,
    mime_type: str,
    original_name: str,
) -> dict:
    r = await db.query(
        """select id, provider_name, credentials from public.provider_credentials
           where id = $1 and user_id = $2 and status = 'active' limit 1""",
        (credential_id, user_id),
    )
    if not r.rows:
        return {"error": "Credential not found or inactive"}
    cred = r.rows[0]
    credentials = _cred(cred["credentials"])
    prov = (cred.get("provider_name") or "").lower()

    if prov == "cloudinary":
        cloud_name = str(credentials.get("cloud_name") or credentials.get("cloudName") or "").strip()
        api_key = str(credentials.get("api_key") or credentials.get("apiKey") or "").strip()
        api_secret = str(credentials.get("api_secret") or credentials.get("apiSecret") or "").strip()
        if not cloud_name or not api_key or not api_secret:
            return {"error": "Cloudinary credential incomplete (cloud_name, api_key, api_secret)"}
        cloudinary.config(cloud_name=cloud_name, api_key=api_key, api_secret=api_secret)
        public_id = _short_public_id()
        try:
            result = cloudinary.uploader.upload(
                io.BytesIO(buffer),
                folder="playground",
                public_id=public_id,
                resource_type="auto",
            )
        except Exception as e:
            return {"error": str(e) or "Cloudinary upload failed"}
        short_url = _short_cloudinary_url(result.get("secure_url") or "")
        return {
            "url": short_url,
            "cdn_url": short_url,
            "width": result.get("width"),
            "height": result.get("height"),
            "bytes": result.get("bytes"),
            "format": result.get("format"),
            "external_id": result.get("public_id"),
        }

    if prov == "imagekit":
        public_key = str(credentials.get("public_key") or "").strip()
        private_key = str(credentials.get("private_key") or "").strip()
        url_endpoint = str(credentials.get("url_endpoint") or "").strip()
        if not public_key or not private_key or not url_endpoint:
            return {"error": "ImageKit credential incomplete"}
        expire = int(time.time()) + 30 * 60
        token = secrets.token_hex(16)
        to_sign = token + str(expire)
        signature = hmac.new(private_key.encode(), to_sign.encode(), hashlib.sha1).hexdigest()
        fname = (original_name or "upload").strip() or "upload"
        files = {"file": (fname, buffer, mime_type or "application/octet-stream")}
        data = {
            "fileName": fname,
            "publicKey": public_key,
            "signature": signature,
            "token": token,
            "expire": str(expire),
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            res = await client.post("https://upload.imagekit.io/api/v1/files/upload", data=data, files=files)
        try:
            jd = res.json()
        except Exception:
            jd = {}
        if res.status_code >= 400:
            return {"error": jd.get("message") or "ImageKit upload failed", "raw": jd}
        cdn = jd.get("url") or (
            f"{url_endpoint.rstrip('/')}/{jd['filePath']}" if url_endpoint and jd.get("filePath") else None
        )
        ext_id = jd.get("fileId") or jd.get("filePath")
        return {
            "url": jd.get("url"),
            "cdn_url": cdn or jd.get("url"),
            "width": jd.get("width"),
            "height": jd.get("height"),
            "size": jd.get("size"),
            "external_id": ext_id,
        }

    return {"error": "Unsupported provider for upload. Use Cloudinary or ImageKit."}


async def delete_from_cloud(
    db: Database,
    *,
    credential_id: str,
    user_id: str,
    provider: str,
    external_id: str,
) -> dict:
    if not external_id:
        return {"error": "external_id required"}
    r = await db.query(
        """select id, provider_name, credentials from public.provider_credentials
           where id = $1 and user_id = $2 and status = 'active' limit 1""",
        (credential_id, user_id),
    )
    if not r.rows:
        return {"error": "Credential not found"}
    credentials = _cred(r.rows[0]["credentials"])
    prov = (r.rows[0].get("provider_name") or "").lower()
    if prov == "cloudinary":
        cn = str(credentials.get("cloud_name") or credentials.get("cloudName") or "").strip()
        ak = str(credentials.get("api_key") or credentials.get("apiKey") or "").strip()
        asec = str(credentials.get("api_secret") or credentials.get("apiSecret") or "").strip()
        if not cn or not ak or not asec:
            return {"error": "Cloudinary credential incomplete"}
        cloudinary.config(cloud_name=cn, api_key=ak, api_secret=asec)
        try:
            cloudinary.uploader.destroy(external_id, invalidate=True)
        except Exception as e:
            return {"error": str(e)}
        return {"ok": True}
    if prov == "imagekit":
        pk = credentials.get("private_key")
        if not pk:
            return {"error": "ImageKit private_key required"}
        auth = base64.b64encode(f"{pk}:".encode()).decode()
        async with httpx.AsyncClient(timeout=60.0) as client:
            res = await client.delete(
                f"https://api.imagekit.io/v1/files/{quote(str(external_id), safe='')}",
                headers={"Authorization": f"Basic {auth}"},
            )
        if res.status_code >= 400:
            return {"error": res.text or f"ImageKit delete failed: {res.status_code}"}
        return {"ok": True}
    return {"error": "Unsupported provider for delete"}
