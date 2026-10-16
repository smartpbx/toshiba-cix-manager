"""Render a :class:`CIXReader` document as a human-readable text report.

Plain monospace text so it drops straight into a Conduit Document, a
ticket, or a terminal. No dependencies.
"""

from __future__ import annotations

from . import decode as D


def _hr(title: str, char: str = "=") -> str:
    return f"{title}\n{char * max(len(title), 8)}"


def render(doc: dict, *, redact_secrets: bool = False) -> str:
    lines: list[str] = []
    dev = doc.get("device", {})
    sysd = doc.get("system", {})

    lines.append(_hr("Toshiba Strata CIX — programming read"))
    lines.append(f"Device       : {dev.get('ip')}:{dev.get('port')}")
    lines.append(f"Community    : {dev.get('community')}")
    lines.append(f"Read at      : {dev.get('read_at')}")
    lines.append(f"Software id  : {sysd.get('software_id', '?')}")
    lines.append(f"Chassis MAC  : {sysd.get('chassis_mac', '?')}")
    lines.append(f"OIDs read    : {dev.get('oids_read')}")
    if dev.get("walk_error"):
        lines.append(f"WALK ERROR   : {dev['walk_error']} (output may be partial)")
    lines.append("")

    # Security findings first — they are the point of a factory-default audit.
    findings = doc.get("security_findings", [])
    if findings:
        lines.append(_hr("Security findings", "-"))
        for f in findings:
            lines.append(f"  [{f['severity'].upper()}] {f['code']}: {f['detail']}")
        lines.append("")

    # Station directory.
    stations = doc.get("stations", [])
    lines.append(_hr(f"Station directory ({len(stations)} stations)", "-"))
    if stations:
        lines.append(f"  {'DN':<8}{'Extension':<12}{'Port':<12}{'Type':<8}"
                     f"{'Name':<20}Keys")
        lines.append(f"  {'-'*6:<8}{'-'*9:<12}{'-'*10:<12}{'-'*6:<8}"
                     f"{'-'*18:<20}{'-'*4}")
        for st in stations:
            port = st.get("equipment_port")
            port = D.format_port(port) if isinstance(port, str) else (port or "")
            name = st.get("name")
            name = "" if name in (None, D.MISSING) else str(name)
            lines.append(
                f"  {st.get('dn',''):<8}"
                f"{str(st.get('extension') or ''):<12}"
                f"{str(port):<12}"
                f"{str(st.get('type') or ''):<8}"
                f"{name:<20}"
                f"{len(st.get('keys', []))}"
            )
    else:
        lines.append("  (none returned)")
    lines.append("")

    # Equipment.
    equip = doc.get("equipment", [])
    lines.append(_hr(f"Equipment / cabinet rows ({len(equip)})", "-"))
    for row in equip:
        cols = ", ".join(f"{k}={v}" for k, v in row.items() if k != "index")
        lines.append(f"  index {row.get('index')}: {cols or '(all empty)'}")
    if not equip:
        lines.append("  (none returned)")
    lines.append("")

    # System numbering / feature config (Program 579).
    numbering = sysd.get("numbering_config", {})
    if numbering:
        lines.append(_hr("System numbering / feature config (Program 579)", "-"))
        for k in sorted(numbering):
            lines.append(f"  {k:<12} = {numbering[k]}")
        lines.append("")

    # System status scalars.
    status = sysd.get("status", {})
    if status:
        lines.append(_hr("System status scalars (.7.*)", "-"))
        for k in sorted(status):
            lines.append(f"  {k:<12} = {status[k]}")
        lines.append("")

    # Network / FTP access.
    net = doc.get("network_access", [])
    if net:
        lines.append(_hr("Network / FTP access (.2.3.1.1)", "-"))
        for row in net:
            user = row.get("username", "")
            pw = row.get("password", "")
            if redact_secrets and pw not in ("", D.MISSING):
                pw = "********"
            lines.append(
                f"  row {row.get('index')}: user={user}  "
                f"password={pw}  path={row.get('path','')}"
            )
        lines.append("")

    # Per-station detail cross-reference (which extra programs touch each DN).
    detailed = [st for st in stations if st.get("programs")]
    if detailed:
        lines.append(_hr("Per-station program detail (raw passthrough)", "-"))
        for st in detailed:
            progs = ", ".join(
                f"{p}({st['programs'][p].get('name','')})"
                for p in sorted(st["programs"])
            )
            lines.append(f"  DN {st['dn']}: {progs}")
        lines.append("")

    # Raw / undecoded programs.
    raw = doc.get("raw_programs", {})
    if raw:
        lines.append(_hr("Undocumented programs (raw passthrough)", "-"))
        for prog in sorted(raw):
            bucket = raw[prog]
            lines.append(f"  Program {prog} — {bucket.get('name','')}: "
                         f"{len(bucket.get('rows', {}))} row(s)")
        lines.append("")

    stats = doc.get("stats", {})
    lines.append(_hr("Totals", "-"))
    for k in sorted(stats):
        lines.append(f"  {k:<22}: {stats[k]}")

    return "\n".join(lines) + "\n"


__all__ = ["render"]
