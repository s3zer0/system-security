/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors:{
        border: '#e5e7eb',
        'text-main': '#111827',
        'text-muted': '#6b7280',

        primary: '#2563eb',
        'primary-soft': '#dbeafe',
        'primary-text': '#1d4ed8',

        'risk-CRITICAL-text': '#d32f2f',
        'risk-HIGH-text': '#fb8c00',
        'risk-MEDIUM-text': '#fbc02d',
        'risk-LOW-text': '#388e3c',
        'risk-SAFE-text': '#615656'
      },
      borderRadius:{
        'lg': '8px',
        'xl': '12px',
        '2xl': '16px',
        '3xl': '24px',
        'panel': '18px',
        'card': '14px',
      },
    },
  },
  plugins: [],
}

