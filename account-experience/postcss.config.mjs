// Tailwind CSS v4 PostCSS plugin (CSS-first config — no tailwind.config.js in v4;
// theme tokens live in app/globals.css via @theme). Mirrors frontend/postcss.config.mjs.
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
}

export default config
