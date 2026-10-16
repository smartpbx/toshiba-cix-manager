# webui/ — Switchroom frontend (React 19 + TS + Vite + shadcn/ui)

This is the source for the single-file UI the Python engine serves. The build
output is the **committed** artifact `../toshiba_cix/webui.html` — one
self-contained HTML file with every script and stylesheet inlined (zero CDN,
system font stack, inline SVG), so it works offline on a PBX voice LAN exactly
as the old hand-rolled UI did.

Node/npm are **dev-only**. They never ship in the AppImage / `.exe` / amalgam —
those serve the committed `webui.html`.

## Stack

- React 19 + TypeScript + Vite 6, bundled to one file by `vite-plugin-singlefile`.
- shadcn/ui components (vendored in `src/components/ui/`), Radix primitives,
  themed with **ui.md's design tokens, unchanged** (`src/index.css` → Tailwind).
- State: `zustand` (`src/store/useStore.ts`).
- Grid virtualization: `@tanstack/react-virtual`. Command palette: `cmdk`.

## Develop

```bash
cd webui
npm install
# Run the Python engine in another terminal so /api/* is live:
#   python3 -m toshiba_cix.webapp --no-browser --port 8765
npm run dev              # Vite dev server on :5173, proxies /api -> :8765
VITE_API_PROXY=http://127.0.0.1:8800 npm run dev   # override the API target
```

## Build (regenerate the committed artifact)

```bash
cd webui
npm ci                   # exact install from the lockfile (reproducible)
npm run build            # tsc --noEmit + vite build + copy to ../toshiba_cix/webui.html
```

Then commit `toshiba_cix/webui.html`. CI (`.github/workflows/webui.yml`) rebuilds
and fails if the committed file is not byte-identical to a fresh build:

```bash
npm run check:webui      # the same check, locally
```

The build is deterministic (pinned deps + lockfile + Node 22), so two builds on
the same toolchain produce identical bytes.

## Layout

```
src/
  main.tsx, App.tsx          app root, view routing, theme, boot (/api/health, /api/catalog)
  index.css                  ui.md tokens (the only styling source) + Tailwind layers
  lib/        api.ts         typed fetch wrapper for the engine's JSON API
              types.ts       API response shapes (current + enriched, both tolerated)
              normalize.ts    program -> columns/cells; menu-area grouping (generic)
  store/      useStore.ts    zustand: connection / doc / backup / catalog / ui slices
  components/ ui/            vendored shadcn/ui components
              DataGrid.tsx    virtualized grid, correct sticky header + pinned key column
              RecordGrid.tsx  generic grid over an array of flat records
              shell/          TopBar, NavRail, StatusBar, ConnectionPill, ModeBadge,
                              ThemeToggle, CommandPalette
  views/      Connect, Overview, Stations, Equipment, System, Network, Programs,
              BackupDiff, Export
```

## Rendering is generic (named fields)

Program tables render each cell's **`field_name` as the column header** and
**`display_value` in the cell** — never a bare OID. `src/lib/normalize.ts`
accepts both the current engine shape (`row.fields = {name: value}`) and the
enriched shape (`{col, field_name, oid, raw_value, display_value}` per cell, and
`{program_number, program_name, menu_area}` per program), and degrades
gracefully on older responses.
