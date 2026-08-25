import { useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "kaims.experience.view.v1";
const VIEW_VALUES = new Set(["simple", "detail"]);

function readInitialView() {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return VIEW_VALUES.has(stored) ? stored : "simple";
  } catch {
    return "simple";
  }
}

function classifyDenseContent(root) {
  if (!root) return;

  root.querySelectorAll("pre, code").forEach((node) => {
    node.setAttribute("data-kai-detail-density", "technical");
  });

  root.querySelectorAll("table").forEach((table) => {
    const rows = table.querySelectorAll("tbody tr").length;
    const columns = table.querySelectorAll("thead th").length;
    if (rows > 10 || columns > 7) {
      table.setAttribute("data-kai-detail-density", "dense-table");
    }
  });

  root
    .querySelectorAll(
      '[class*="trace" i], [class*="debug" i], [class*="payload" i], [class*="json" i], [class*="technical" i], [class*="raw" i]'
    )
    .forEach((node) => node.setAttribute("data-kai-detail-density", "technical"));

  root.querySelectorAll("p, li").forEach((node) => {
    const text = (node.textContent || "").trim();
    if (text.length > 520) {
      node.setAttribute("data-kai-long-copy", "true");
    }
  });
}

function ViewIcon({ mode }) {
  if (mode === "simple") {
    return (
      <svg viewBox="0 0 20 20" aria-hidden="true">
        <rect x="2.5" y="3" width="15" height="4" rx="1.5" />
        <rect x="2.5" y="9" width="7" height="8" rx="1.5" />
        <rect x="11" y="9" width="6.5" height="3" rx="1.5" />
        <rect x="11" y="14" width="6.5" height="3" rx="1.5" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <rect x="2.5" y="2.5" width="15" height="15" rx="2" />
      <path d="M6 6.5h8M6 10h8M6 13.5h5" />
    </svg>
  );
}

export default function ExperienceShell({ children }) {
  const [view, setView] = useState(readInitialView);

  const description = useMemo(
    () =>
      view === "simple"
        ? "Simple View prioritizes health, impact, decisions and visual explanations."
        : "Detail View exposes full evidence, telemetry, payloads and engineering depth.",
    [view]
  );

  useEffect(() => {
    document.documentElement.dataset.kaiView = view;
    try {
      window.localStorage.setItem(STORAGE_KEY, view);
    } catch {
      // Storage may be disabled by browser policy. The in-memory preference still works.
    }
  }, [view]);

  useEffect(() => {
    const root = document.getElementById("root");
    if (!root) return undefined;

    classifyDenseContent(root);
    const observer = new MutationObserver(() => classifyDenseContent(root));
    observer.observe(root, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  return (
    <div className="kai-experience-shell" data-view={view}>
      <div className="kai-view-switcher" role="group" aria-label="Information density">
        <div className="kai-view-switcher__label">
          <span className="kai-view-switcher__eyebrow">Experience</span>
          <span className="kai-view-switcher__hint">{description}</span>
        </div>
        <div className="kai-view-switcher__controls">
          <button
            type="button"
            className={view === "simple" ? "is-active" : ""}
            aria-pressed={view === "simple"}
            onClick={() => setView("simple")}
            title="Show the operational story with less technical density"
          >
            <ViewIcon mode="simple" />
            <span>Simple</span>
          </button>
          <button
            type="button"
            className={view === "detail" ? "is-active" : ""}
            aria-pressed={view === "detail"}
            onClick={() => setView("detail")}
            title="Show full engineering evidence and technical detail"
          >
            <ViewIcon mode="detail" />
            <span>Detail</span>
          </button>
        </div>
      </div>
      {children}
    </div>
  );
}
