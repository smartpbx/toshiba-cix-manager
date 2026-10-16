# Toshiba CIX Manager

A modern, cross-platform tool to **read, back up, diff, restore, and program Toshiba Strata CIX / CTX**
phone systems over SNMP — **no eManager and no Windows VM required**. Run it from any laptop, plugged
directly into the PBX or remotely over your network.

> **Not affiliated with, endorsed by, or supported by Toshiba.** The Toshiba Strata CIX / CTX line is
> end-of-life — Toshiba no longer sells, services, maintains, or supports it. This is an independent,
> community tool provided **as-is, with no warranty of any kind**. Use it at your own risk, only on
> systems you are authorized to manage. "Toshiba", "Strata", and "CIX" are trademarks of their
> respective owners.

## What it does

- **Read** the full system programming — 186 programs / 2,300+ fields — over SNMP (v1), community-string auth.
- **Back up** the configuration to an open, human-readable **JSON** format you own (not a vendor blob).
- **View** a backup — browse programs, stations, trunks, and every field by name.
- **Diff** two backups to see exactly what changed.
- **Restore** a backup (or a subset) back to a system — **writable fields only**, batched, and
  **read-back-verified**, behind an explicit confirmation.
- Works **direct** (laptop ↔ PBX on the voice LAN) and **remote** (over a tunnel / jump host).
- A small **local web UI** plus a **CLI**.

It's driven by a catalog derived from the system's own SNMP object model (the field→OID map), so every
field is addressed by its real OID rather than guessed.

## Status & safety

- Reading and backup are safe and covered by the test suite.
- **Writes / restore are gated** (off by default; require explicit `--confirm`), never touch read-only
  fields, and verify every change by reading it back.
- Text-field writes are protocol-proven; some numeric field wire-types are catalog-derived and flagged.
- **Reboot persistence of a restore has not yet been independently verified** — treat restore as
  "apply to live RAM + verify" until you've confirmed it on your own bench.

## Install / run

Pure Python, **no third-party runtime dependencies** (Python 3.8+). Pre-built single-file executables
for Windows and Linux are on the [Releases](../../releases) page.

```bash
# back up a system
python3 manage.py backup --host <pbx-ip> --community <community> --out system.json

# view / diff
python3 manage.py view system.json
python3 manage.py diff before.json after.json

# restore (previews by default; applies only with --confirm)
python3 manage.py restore system.json --confirm

# local web UI
python3 app.py        # then open the printed http://127.0.0.1:... URL
```

Run any command with `--help` for options.

## Roadmap

- Voicemail (Stratagy) management from the same app.
- Friendly dropdown labels for enumerated fields.
- Verified reboot-persistent restore.

## Contributing

Issues and pull requests welcome.

## License

[Apache-2.0](./LICENSE).
