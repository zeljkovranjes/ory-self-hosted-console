// Tailwind CSS v4 PostCSS plugin (CSS-first config — there is NO tailwind.config.js
// in v4; theme tokens live in app/globals.css via @theme/@theme inline). See
// 05-RESEARCH Pitfall 3.
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
