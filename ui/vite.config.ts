import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The built page is served by FastAPI at /ui (api_server._mount_visualiser), so every asset URL
// has to be relative to that prefix rather than to the site root.
//
// In dev, `npm run dev` serves the page itself and proxies the API calls to a running
// `talos serve`, which is what lets the page be developed against the real pipeline instead of
// a mock -- the trace is the product, and a mocked trace would prove nothing.
export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/trace": "http://127.0.0.1:8000",
      "/reports": "http://127.0.0.1:8000",
      "/healthz": "http://127.0.0.1:8000",
    },
  },
});
