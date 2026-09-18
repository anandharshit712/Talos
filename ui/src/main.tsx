import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { TracePage } from "./trace_page";
import "./index.css";

const root = document.getElementById("root");
if (!root) throw new Error("index.html is missing #root");

createRoot(root).render(
  <StrictMode>
    <TracePage />
  </StrictMode>,
);
