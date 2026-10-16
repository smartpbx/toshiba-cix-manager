"""Loopback token + Origin/Host guard — the first and most important PR.

Today's ``/api/save`` and ``/api/restore`` sit on a well-known port with no
auth: any web page the tech visits could POST to ``127.0.0.1:8765`` and write a
PBX (a DNS-rebinding write path). This closes it (DESIGN_PLAN 2.2, 14.6):

* a 32-byte launch **token**, generated per run and delivered once to the UI as
  a URL fragment, is required as ``X-CIX-Token`` on every ``/api`` call;
* the ``Host`` header must be loopback and any ``Origin`` must be loopback too,
  so a rebound attacker page (whose ``Origin`` is its own domain) is refused
  even if it somehow guessed the token; there is no CORS.

Static assets (the SPA itself) are served without a token so the browser can
load the page and read the fragment. The guard is **disabled when no token is
set** (``token=None``) — that is the mode the offline test harness and
``launcher.start_server`` run in, so nothing regresses.

The token is accepted as the ``X-CIX-Token`` header **or** as a ``Set-Cookie``
the ``/`` load plants (``cix_token``, ``SameSite=Strict``). The cookie means a
same-origin ``fetch`` authenticates with nothing added to the request — so the
existing SPA keeps working the moment auth is switched on — while a rebound
cross-site page is refused by both ``SameSite`` (the cookie is withheld) and
the Origin check (its Origin is not loopback).
"""

from __future__ import annotations

import secrets

COOKIE_NAME = "cix_token"


def _cookie_token(cookie_header: str) -> str | None:
    """Pull ``cix_token`` out of a raw ``Cookie:`` header (no http.cookies dep)."""
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME:
            return value or None
    return None

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


def generate_token() -> str:
    """A fresh URL-safe launch token (32 bytes of entropy)."""
    return secrets.token_urlsafe(32)


def _host_only(value: str) -> str:
    """Strip a scheme and port: ``http://127.0.0.1:8765`` -> ``127.0.0.1``."""
    v = (value or "").strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    # keep a bracketed IPv6 literal intact, else drop a :port suffix
    if v.startswith("["):
        return v.split("]", 1)[0] + "]"
    return v.split(":", 1)[0] if ":" in v and v.count(":") == 1 else v


def is_loopback_host(value: str) -> bool:
    return _host_only(value) in _LOOPBACK_HOSTS


class LoopbackAuth:
    """Token + Origin/Host check. ``token=None`` disables it (dev/test)."""

    def __init__(self, token: str | None = None):
        self.token = token

    @property
    def enabled(self) -> bool:
        return bool(self.token)

    def check(self, *, headers, path: str):
        """Return ``(ok, status, message)`` for a request.

        ``headers`` is anything with ``.get(name)`` (an ``http.client`` message
        or a plain dict). Static (non-``/api``) paths always pass.
        """
        if not self.enabled:
            return True, 200, ""
        if not path.startswith("/api"):
            return True, 200, ""
        host = headers.get("Host")
        if host and not is_loopback_host(host):
            return False, 403, "non-loopback Host"
        origin = headers.get("Origin")
        if origin and not is_loopback_host(origin):
            return False, 403, "cross-origin request refused"
        token = (headers.get("X-CIX-Token") or headers.get("x-cix-token")
                 or _cookie_token(headers.get("Cookie") or ""))
        if not token or not secrets.compare_digest(str(token), str(self.token)):
            return False, 401, "missing or invalid launch token"
        return True, 200, ""

    def cookie_header(self) -> str | None:
        """The ``Set-Cookie`` value the ``/`` load plants, or ``None`` if off."""
        if not self.enabled:
            return None
        return (f"{COOKIE_NAME}={self.token}; Path=/; SameSite=Strict; "
                "HttpOnly")


__all__ = ["LoopbackAuth", "generate_token", "is_loopback_host", "COOKIE_NAME"]
