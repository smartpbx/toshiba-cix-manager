import * as React from "react";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 border-b border-border px-4 py-2.5">
      <div className="min-w-0">
        <h1 className="truncate text-lg font-semibold leading-tight">{title}</h1>
        {subtitle && <div className="truncate text-xs text-fg-2">{subtitle}</div>}
      </div>
      {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex h-full items-center justify-center p-10 text-sm text-fg-2">
      {message}
    </div>
  );
}
