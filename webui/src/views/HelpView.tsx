import { PageHeader } from "@/components/PageHeader";

// Help › "Coming from eManager?" (DESIGN_PLAN §6, P4). A plain mapping from the
// words a Strata tech already knows to where the same thing lives in
// Switchroom. No Toshiba term is renamed — this page is the bridge, not a
// glossary of new names.
const MAP: Array<{ emanager: string; here: string; note?: string }> = [
  {
    emanager: "Connect / Client Equipment Setup",
    here: "Connect drawer (top-left) + Sites",
    note: "A snapshot is read on every connect; browse it even with the switch off.",
  },
  {
    emanager: "Connected Equipment Details",
    here: "Home",
    note: "Task-first: jump to a DN, open a program, resume a draft.",
  },
  {
    emanager: "Station Assignments (200)",
    here: "Station › Assignments — the grid + record pane",
    note: "Click Edit on a record to stage a change; it never writes directly.",
  },
  {
    emanager: "Submit",
    here: "Review & Write dialog",
    note: "Every change is shown base → live → proposed and read back after; unsendable ops are listed with the reason, never silently dropped.",
  },
  {
    emanager: "StationCopyTemplate / the Template dropdown",
    here: "Templates (row templates)",
    note: "Now a readable file with identity/secrets stripped; Compare = drift.",
  },
  {
    emanager: "Add Station / Delete Station wizards",
    here: "Wizards — same steps, same program list per step",
    note: "The last step is the Review & Write dialog.",
  },
  {
    emanager: "CIX Data Backup (910)",
    here: "Backups › Take a backup",
    note: "The 910 vendor image is stored inside the same .cixbak as the catalog snapshot.",
  },
  {
    emanager: "Find a DN / where is this used",
    here: "Command palette (Ctrl K) + Where-used chips",
    note: "Any DN, name, digit string or OID resolves to every program that holds it.",
  },
  {
    emanager: "SNMP community / passwords",
    here: "Problems panel flags the defaults",
    note: "Secrets are masked and never leave the review as values.",
  },
  {
    emanager: "Voice Mail Manager (Stratagy)",
    here: "Voice Mail tab",
    note: "Read side is live; the halting Backup Utility stays for restore-to-hardware.",
  },
];

export function HelpView() {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="Coming from eManager?"
        subtitle="Where the thing you already know lives in Switchroom"
      />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="mx-auto max-w-3xl overflow-hidden rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-surface-2 text-left text-2xs uppercase text-fg-3">
              <tr>
                <th className="w-1/3 px-3 py-2 font-medium">In eManager</th>
                <th className="px-3 py-2 font-medium">In Switchroom</th>
              </tr>
            </thead>
            <tbody>
              {MAP.map((m) => (
                <tr key={m.emanager} className="border-t border-border/60 align-top">
                  <td className="px-3 py-2 font-medium">{m.emanager}</td>
                  <td className="px-3 py-2">
                    <div>{m.here}</div>
                    {m.note && (
                      <div className="mt-0.5 text-2xs text-fg-3">{m.note}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="px-3 py-3 text-2xs text-fg-3">
            Nothing is renamed: program numbers, field names and menu paths are
            Toshiba's, verbatim. The only new thing is that every write is staged
            and reviewed before it leaves this machine.
          </p>
        </div>
      </div>
    </div>
  );
}
