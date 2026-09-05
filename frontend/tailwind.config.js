/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'tn-dark': '#0a0e17',
        'tn-darker': '#060a12',
        'tn-card': '#111827',
        'tn-border': '#1e293b',
        'tn-accent': '#3b82f6',
        'tn-danger': '#ef4444',
        'tn-warning': '#f59e0b',
        'tn-success': '#10b981',
        'tn-critical': '#dc2626',
      },
    },
  },
  plugins: [],
}
