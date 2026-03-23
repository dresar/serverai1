"""cPanel Passenger WSGI entrypoint for FastAPI."""
from __future__ import annotations

from a2wsgi import ASGIMiddleware

from app.main import app as asgi_app

# cPanel Passenger mencari variabel WSGI bernama `application`.
application = ASGIMiddleware(asgi_app)

