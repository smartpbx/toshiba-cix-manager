/** @type {import('tailwindcss').Config} */
// shadcn/ui is themed with ui.md's tokens (adopted unchanged): the design's
// CSS custom properties are the single source of truth (defined in index.css),
// and Tailwind colours reference them directly rather than shadcn's defaults.
export default {
  darkMode: ["class", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // shadcn semantic slots -> ui.md tokens
        background: "var(--bg)",
        foreground: "var(--fg)",
        border: "var(--line)",
        input: "var(--line)",
        ring: "var(--focus)",
        card: { DEFAULT: "var(--surface)", foreground: "var(--fg)" },
        popover: { DEFAULT: "var(--surface)", foreground: "var(--fg)" },
        primary: { DEFAULT: "var(--accent)", foreground: "var(--accent-fg)" },
        secondary: { DEFAULT: "var(--surface-2)", foreground: "var(--fg)" },
        muted: { DEFAULT: "var(--surface-2)", foreground: "var(--fg-2)" },
        accent: { DEFAULT: "var(--surface-2)", foreground: "var(--fg)" },
        destructive: { DEFAULT: "var(--bad)", foreground: "#ffffff" },
        // ui.md direct tokens (addressable as e.g. text-ok, bg-warn-tint)
        surface: {
          DEFAULT: "var(--surface)",
          2: "var(--surface-2)",
          3: "var(--surface-3)",
        },
        "line-strong": "var(--line-strong)",
        "fg-2": "var(--fg-2)",
        "fg-3": "var(--fg-3)",
        "accent-hover": "var(--accent-hover)",
        "accent-tint": "var(--accent-tint)",
        ok: { DEFAULT: "var(--ok)", tint: "var(--ok-tint)" },
        warn: { DEFAULT: "var(--warn)", tint: "var(--warn-tint)" },
        bad: { DEFAULT: "var(--bad)", tint: "var(--bad-tint)" },
        remote: { DEFAULT: "var(--remote)", tint: "var(--remote-tint)" },
      },
      borderRadius: {
        lg: "var(--r-3)",
        md: "var(--r-2)",
        sm: "var(--r-1)",
      },
      fontFamily: {
        sans: "var(--font-ui)",
        mono: "var(--font-mono)",
      },
      fontSize: {
        "2xs": "var(--fs-0)",
        xs: "var(--fs-1)",
        sm: "var(--fs-2)",
        base: "var(--fs-3)",
        lg: "var(--fs-4)",
        xl: "var(--fs-5)",
      },
      height: {
        row: "var(--row-h)",
        ctl: "var(--ctl-h)",
        topbar: "var(--topbar-h)",
        statusbar: "var(--statusbar-h)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.15s ease-out",
        "accordion-up": "accordion-up 0.15s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
