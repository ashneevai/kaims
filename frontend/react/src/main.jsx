import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ExperienceShell from "./experience/ExperienceShell";
import "./styles.css";
import "./datamatics-base.css";
import "./datamatics-light.css";
import "./datamatics-dark.css";
import "./experience/experience.css";
import "./experience/visual-primitives.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ExperienceShell>
      <App />
    </ExperienceShell>
  </React.StrictMode>
);
