/** @type {import('tailwindcss').Config} */
export default {
  // Class strategy: dark mode activates only when `.dark` is on <html>.
  // The class is the single source of truth. `lib/theme.ts` is its only writer
  // (seeded before first paint by public/theme-init.js), and the dashboard's
  // chart colors follow the same signal (see features/dashboard/lib/useIsDark).
  // Deliberately no media query anywhere: a live `prefers-color-scheme` listener
  // is what would let a chart render dark on a light page.
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Semantic tokens backed by the custom properties in index.css, which
        // the `.dark` class flips. `<alpha-value>` is what keeps opacity
        // modifiers (bg-surface/50) working; it only substitutes correctly
        // because the properties hold raw channel triplets, not hex.
        bg: 'rgb(var(--bg) / <alpha-value>)',
        surface: 'rgb(var(--surface) / <alpha-value>)',
        sunken: 'rgb(var(--sunken) / <alpha-value>)',
        'sunken-strong': 'rgb(var(--sunken-strong) / <alpha-value>)',
        track: 'rgb(var(--track) / <alpha-value>)',

        ink: 'rgb(var(--ink) / <alpha-value>)',
        'ink-strong': 'rgb(var(--ink-strong) / <alpha-value>)',
        'ink-soft': 'rgb(var(--ink-soft) / <alpha-value>)',
        'ink-mid': 'rgb(var(--ink-mid) / <alpha-value>)',
        muted: 'rgb(var(--muted) / <alpha-value>)',
        faint: 'rgb(var(--faint) / <alpha-value>)',

        'hairline-soft': 'rgb(var(--hairline-soft) / <alpha-value>)',
        hairline: 'rgb(var(--hairline) / <alpha-value>)',
        'hairline-strong': 'rgb(var(--hairline-strong) / <alpha-value>)',

        // Card and nav borders carry a per-theme alpha as well as a per-theme
        // channel, so they resolve their own opacity and take no modifier.
        'card-border': 'rgb(var(--card-border) / var(--card-border-alpha))',
        'nav-bg': 'rgb(var(--nav-bg) / <alpha-value>)',
        'nav-border': 'rgb(var(--nav-border) / var(--nav-border-alpha))',

        // Accent palette — the dashboard's teal (Tailwind `teal` ramp). ACCENT
        // (#14B8A6) is teal-500 and ACCENT_TEXT_LIGHT (#0F766E) is teal-700, kept
        // in lockstep with features/dashboard/lib/colors.ts. The `certus` token
        // name is retained so existing class usages stay valid.
        certus: {
          50: '#f0fdfa',
          100: '#ccfbf1',
          200: '#99f6e4',
          300: '#5eead4',
          400: '#2dd4bf',
          500: '#14b8a6',
          600: '#0d9488',
          700: '#0f766e',
          800: '#115e59',
          900: '#134e4a',
          950: '#042f2e',
        },
      },
    },
  },
  plugins: [],
}
