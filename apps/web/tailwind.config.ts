import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0b0f19',
        panel: '#131a2a',
        panelup: '#1b2438',
        edge: '#243049',
        accent: '#38bdf8',
        good: '#34d399',
        warn: '#fbbf24',
        bad: '#f87171',
        muted: '#8b98b5',
      },
    },
  },
  plugins: [],
};

export default config;
