"""Manager-bridge client: Conduit deep-link → connection fetch + cloud save.

The *manager bridge* (shared CONTRACT, conduit#manager-bridge, the Frameroom PR)
lets a tech open Switchroom pre-filled from a Conduit system and save a backup
back into Conduit, without Conduit vendoring the SNMP engine.

Two one-way HTTP calls to Conduit, both **engine-side** (not browser-side) so
there is no CORS and the short-lived bearer token never reaches page JS:

* :func:`fetch_connection` — ``GET  <conduit>/api/manager-bridge/connection?component=<id>``
  with ``Authorization: Bearer <tok>``; maps the returned ``connection`` into
  the Connect-drawer form shape (host/community/port/reach).
* :func:`post_backup`     — ``POST <conduit>/api/manager-bridge/backup?component=<id>``
  with the token; body ``{filename, content_b64, content_type, summary}``.

Pure stdlib (``urllib``), I/O-injectable (every call takes an ``_http`` seam) so
the whole module is unit-testable with no network. The verifying TLS context is
reused from :mod:`toshiba_cix.update` (the CA-bundle resolver that already copes
with the frozen builds' empty trust store) — a bare import so the single-file
amalgam resolves it as a flattened global.

Every module-level name here is bridge-prefixed or unique so the amalgam (which
flattens the whole package into one namespace) cannot clobber another module's
globals — in particular ``update.USER_AGENT``.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

from . import __version__
from .update import _ssl_context

# Our own URL scheme + user-agent. The scheme is registered by the Tauri
# deep-link plugin (desktop/src-tauri) and by the installed .desktop MimeHandler.
SCHEME = "switchroom"
BRIDGE_USER_AGENT = f"switchroom-manager-bridge/{__version__}"
BRIDGE_SCOPE = "manager_bridge"
_BRIDGE_TIMEOUT = 20.0


class BridgeError(Exception):
    """A malformed deep-link / bad Conduit base. Operational failures (Conduit
    down, token expired) are returned as ``{"ok": False, ...}`` dicts, never
    raised — a save that fails must surface a message, not a stack trace."""


# --------------------------------------------------------------------------
# deep-link parsing (switchroom://open?conduit=&component=&token=)
# --------------------------------------------------------------------------
def parse_deeplink(url):
    """Parse ``switchroom://open?conduit=<urlenc base>&component=&token=``.

    Returns ``{action, conduit, component, token}`` or ``None`` if it is not a
    well-formed ``switchroom://`` link with all three params. ``conduit`` is
    URL-decoded by :func:`parse_qs`, so a percent-encoded base comes back whole.
    """
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return None
    if parts.scheme != SCHEME:
        return None
    q = parse_qs(parts.query)

    def one(key):
        vals = q.get(key) or []
        return vals[0] if vals else None

    conduit, component, token = one("conduit"), one("component"), one("token")
    if not (conduit and component and token):
        return None
    action = parts.netloc or (parts.path.strip("/") or "open")
    return {"action": action, "conduit": conduit.strip(),
            "component": component.strip(), "token": token.strip()}


def pop_deeplink_arg(argv):
    """Pull the first ``switchroom://…`` entry out of ``argv``.

    Returns ``(argv_without_it, url_or_None)`` so a launcher can route a
    browser-launched deep link to the engine without tripping argparse on an
    unknown positional. Only the first such arg is taken.
    """
    kept = []
    url = None
    for arg in argv or []:
        if url is None and isinstance(arg, str) and arg.startswith(SCHEME + "://"):
            url = arg
        else:
            kept.append(arg)
    return kept, url


# --------------------------------------------------------------------------
# connection → Connect-drawer form mapping
# --------------------------------------------------------------------------
def connection_to_form(connection, *, system_name=None):
    """Map a Conduit ``connection`` block into the Connect-drawer form fields.

    The contract's toshiba_cix connection is ``{host, via, port, community}``;
    the drawer wants ``{ip, community, port, reach, site}``. ``via`` ∈
    ``rsm|overlay|remote|agent`` all mean "reach over the overlay" → ``remote``.
    """
    conn = connection or {}
    via = str(conn.get("via") or "direct").lower()
    reach = "remote" if via in ("rsm", "overlay", "remote", "agent") else "direct"
    try:
        port = int(conn.get("port") or 161)
    except (TypeError, ValueError):
        port = 161
    community = str(conn.get("community") or "communityName").strip() or "communityName"
    return {
        "ip": str(conn.get("host") or "").strip(),
        "community": community,
        "port": port,
        "reach": reach,
        "site": system_name or "",
    }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def _normalize_conduit_base(conduit):
    """Validate + normalise the Conduit base URL (http(s), no query/fragment)."""
    raw = (conduit or "").strip().rstrip("/")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise BridgeError("the Conduit base must be an http(s) URL")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _bridge_http(method, url, token, *, body=None, timeout=_BRIDGE_TIMEOUT):
    """One bearer-authed request. Returns ``(status, parsed_json_or_None, text)``.

    An ``HTTPError`` (401 expired token, 404 wrong component, 400 …) is caught so
    Conduit's own ``{"error": ...}`` body becomes the message; a transport error
    (connection refused, DNS, TLS) propagates to the caller, which wraps it.
    """
    headers = {
        "User-Agent": BRIDGE_USER_AGENT,
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = _ssl_context() if url.lower().startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            raw = resp.read()
    except urllib.error.HTTPError as exc:  # 4xx/5xx carry a body we want to show
        status = exc.code
        try:
            raw = exc.read()
        except Exception:  # noqa: BLE001
            raw = b""
    text = raw.decode("utf-8", "replace") if raw else ""
    parsed = None
    if text:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    return status, parsed, text


def _bridge_error_from(status, data, text):
    if isinstance(data, dict) and data.get("error"):
        return str(data["error"])
    if isinstance(data, dict) and data.get("detail"):
        return str(data["detail"])
    snippet = (text or "").strip().replace("\n", " ")[:160]
    return f"Conduit returned HTTP {status}" + (f": {snippet}" if snippet else "")


def fetch_connection(conduit, component, token, *, _http=None):
    """GET the connection for ``component`` from Conduit and shape it for the UI.

    Returns ``{ok, kind, system_name, component_id, connection, form}`` on
    success, or ``{ok: False, error, status?}`` on any failure (never raises).
    """
    http = _http or _bridge_http
    try:
        base = _normalize_conduit_base(conduit)
    except BridgeError as exc:
        return {"ok": False, "error": str(exc)}
    url = f"{base}/api/manager-bridge/connection?component={quote(str(component))}"
    try:
        status, data, text = http("GET", url, token)
    except Exception as exc:  # noqa: BLE001 — transport: wrap, never raise
        return {"ok": False, "error": f"could not reach Conduit: {exc}"}
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        return {"ok": False, "error": _bridge_error_from(status, data, text),
                "status": status}
    connection = data.get("connection") or {}
    return {
        "ok": True,
        "kind": data.get("kind"),
        "system_name": data.get("system_name"),
        "component_id": data.get("component_id") or str(component),
        "connection": connection,
        "form": connection_to_form(connection, system_name=data.get("system_name")),
    }


def post_backup(conduit, component, token, *, filename, content, content_type,
                summary=None, _http=None):
    """POST a backup to Conduit, which attaches it to ``component`` as a Document.

    Returns ``{ok, document_id}`` on success or ``{ok: False, error, status?}``.
    The bytes are base64-encoded into ``content_b64`` per the contract.
    """
    http = _http or _bridge_http
    try:
        base = _normalize_conduit_base(conduit)
    except BridgeError as exc:
        return {"ok": False, "error": str(exc)}
    url = f"{base}/api/manager-bridge/backup?component={quote(str(component))}"
    payload = {
        "filename": filename,
        "content_b64": base64.b64encode(content).decode("ascii"),
        "content_type": content_type,
    }
    if summary:
        payload["summary"] = summary
    try:
        status, data, text = http("POST", url, token, body=payload)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"could not reach Conduit: {exc}"}
    if status not in (200, 201) or not isinstance(data, dict) or not data.get("ok"):
        return {"ok": False, "error": _bridge_error_from(status, data, text),
                "status": status}
    return {"ok": True, "document_id": data.get("document_id")}


__all__ = [
    "SCHEME", "BRIDGE_SCOPE", "BridgeError",
    "parse_deeplink", "pop_deeplink_arg", "connection_to_form",
    "fetch_connection", "post_backup",
]
