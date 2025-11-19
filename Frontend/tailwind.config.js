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

        'risk-CRITICAL-text': '#ac0202',
        'risk-HIGH-text': '#bd1c00',
        'risk-MEDIUM-text': '#cd5311',
        'risk-LOW-text': '#137333',
        'risk-INFO-text': '#195396',
        'risk-NA-text' : '#000000',

        'risk-CRITICAL-bg': '#bd000040',
        'risk-HIGH-bg': '#ff590040',
        'risk-MEDIUM-bg': '#ebb20040',
        'risk-LOW-bg': '#13733340',
        'risk-INFO-bg': '#0071a240',
        'risk-NA-bg': '#00000040',

        'risk-IMMEDIATE-text': '#ac0202',
        'risk-PLANNED-text': '#195396', 

        'risk-IMMEDIATE-bg': '#bd000040',
        'risk-PLANNED-bg': '#0071a240',
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

