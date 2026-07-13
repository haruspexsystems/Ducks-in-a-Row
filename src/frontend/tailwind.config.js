/** @type {import('tailwindcss').Config} */
export default {
  // Class strategy: dark mode activates only when `.dark` is on <html>.
  // No toggle ships in this MVP, so the app stays light; the dashboard's
  // chart colors follow the same signal (see features/dashboard/lib/useIsDark).
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
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
