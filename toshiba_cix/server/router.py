"""A tiny method + path router with ``{param}`` segments.

The legacy webapp dispatched with a chain of ``if path == ...``; this replaces
it with a table so new routes (``/api/sites/{id}``) register declaratively and
the handler stays dumb. Matching is exact on the static segments; a single
``{name}`` segment captures one path component into ``params``. No regex, no
dependency, order-independent (longest static prefix wins on a tie so
``/api/jobs`` and ``/api/jobs/{id}`` coexist).
"""

from __future__ import annotations


class Router:
    def __init__(self):
        # method -> list of (segments, handler, has_param)
        self._routes: dict[str, list] = {}

    def add(self, method: str, pattern: str, handler) -> None:
        segs = _split(pattern)
        self._routes.setdefault(method.upper(), []).append(
            (segs, handler, any(_is_param(s) for s in segs)))

    def get(self, pattern, handler):
        self.add("GET", pattern, handler)

    def post(self, pattern, handler):
        self.add("POST", pattern, handler)

    def put(self, pattern, handler):
        self.add("PUT", pattern, handler)

    def delete(self, pattern, handler):
        self.add("DELETE", pattern, handler)

    def patch(self, pattern, handler):
        self.add("PATCH", pattern, handler)

    def match(self, method: str, path: str):
        """Return ``(handler, params)`` or ``None``.

        A static match wins over a parameterised one at the same length, so a
        literal route is never shadowed by a ``{param}`` sibling.
        """
        want = _split(path)
        candidates = []
        for segs, handler, has_param in self._routes.get(method.upper(), []):
            if len(segs) != len(want):
                continue
            params = {}
            ok = True
            for s, w in zip(segs, want):
                if _is_param(s):
                    params[s[1:-1]] = w
                elif s != w:
                    ok = False
                    break
            if ok:
                candidates.append((has_param, handler, params))
        if not candidates:
            return None
        # static (has_param False) sorts before parameterised
        candidates.sort(key=lambda c: c[0])
        _, handler, params = candidates[0]
        return handler, params

    def methods_for(self, path: str) -> list[str]:
        """Methods that *would* match ``path`` (for a 405 vs 404 decision)."""
        want = _split(path)
        out = []
        for method, routes in self._routes.items():
            for segs, _h, _p in routes:
                if len(segs) == len(want) and all(
                        _is_param(s) or s == w for s, w in zip(segs, want)):
                    out.append(method)
                    break
        return out


def _split(path: str) -> list[str]:
    return [p for p in path.split("?", 1)[0].split("/") if p != ""]


def _is_param(seg: str) -> bool:
    return len(seg) >= 2 and seg[0] == "{" and seg[-1] == "}"


__all__ = ["Router"]
