import * as React from "react";
import {
  Boxes,
  Cpu,
  Download,
  Hash,
  Home,
  LayoutGrid,
  Network,
  Phone,
  Plug,
  Save,
} from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { useStore, type ViewId } from "@/store/useStore";

const NAV: Array<{ id: ViewId; label: string; icon: typeof Home; hint: string }> = [
  { id: "overview", label: "Overview", icon: Home, hint: "Connected Equipment Details" },
  { id: "stations", label: "Stations", icon: LayoutGrid, hint: "Station Assignments (200…)" },
  { id: "equipment", label: "Equipment", icon: Boxes, hint: "Hardware Info and Control" },
  { id: "system", label: "System", icon: Cpu, hint: "System Data (105)" },
  { id: "network", label: "Network / FTP", icon: Network, hint: "CIX Processor IP (916)" },
  { id: "programs", label: "Programs", icon: Hash, hint: "Browse by eManager menu area" },
  { id: "backup", label: "Backup & Diff", icon: Save, hint: "Catalog backup / compare" },
  { id: "export", label: "Export", icon: Download, hint: "Download JSON / report" },
  { id: "connect", label: "Connect", icon: Plug, hint: "Reach a CIX over SNMP" },
];

export function CommandPalette() {
  const { open, setOpen, setView, doc, setStationFilter } = useStore((s) => ({
    open: s.paletteOpen,
    setOpen: s.setPaletteOpen,
    setView: s.setView,
    doc: s.doc,
    setStationFilter: s.setStationFilter,
  }));
  const [query, setQuery] = React.useState("");

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(!open);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, setOpen]);

  const go = (id: ViewId) => {
    setView(id);
    setOpen(false);
    setQuery("");
  };

  // DN jump: numeric query matches station DNs/names (snapshot-first, instant).
  const stationMatches = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q || !doc?.stations) return [];
    return doc.stations
      .filter(
        (s) =>
          s.dn.toLowerCase().includes(q) ||
          (s.name ?? "").toLowerCase().includes(q),
      )
      .slice(0, 8);
  }, [query, doc]);

  const jumpToStation = (dn: string) => {
    setStationFilter(dn);
    setView("stations");
    setOpen(false);
    setQuery("");
  };

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput
        placeholder="Search programs, DNs, or jump to a page…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <CommandEmpty>No matches.</CommandEmpty>
        {stationMatches.length > 0 && (
          <CommandGroup heading="Stations">
            {stationMatches.map((s) => (
              <CommandItem
                key={s.dn}
                value={`dn-${s.dn}-${s.name ?? ""}`}
                onSelect={() => jumpToStation(s.dn)}
              >
                <Phone className="h-4 w-4 text-fg-2" />
                <span className="font-mono tnum">{s.dn}</span>
                <span className="text-fg-2">{s.name ?? "(unnamed)"}</span>
                <span className="ml-auto text-2xs text-fg-3">{s.type ?? ""}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        <CommandGroup heading="Go to">
          {NAV.map((n) => (
            <CommandItem key={n.id} value={`nav-${n.label}`} onSelect={() => go(n.id)}>
              <n.icon className="h-4 w-4 text-fg-2" />
              <span>{n.label}</span>
              <span className="ml-auto text-2xs text-fg-3">{n.hint}</span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
