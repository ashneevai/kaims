function clampPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, number));
}

export function StatusRing({ value, label, detail, tone = "intelligence" }) {
  const percent = clampPercent(value);
  return (
    <div className="kai-status-visual" aria-label={`${label}: ${percent}%`}>
      <div className={`kai-status-ring kai-tone-${tone}`} style={{ "--value": percent }}>
        <strong>{Math.round(percent)}%</strong>
      </div>
      <div className="kai-status-visual__copy">
        <strong>{label}</strong>
        {detail ? <span>{detail}</span> : null}
      </div>
    </div>
  );
}

export function ConfidenceMeter({ value, label = "Kai confidence", detail }) {
  const percent = clampPercent(Number(value) <= 1 ? Number(value) * 100 : value);
  return (
    <div className="kai-meter" aria-label={`${label}: ${Math.round(percent)}%`}>
      <div className="kai-meter__header">
        <span>{label}</span>
        <strong>{Math.round(percent)}%</strong>
      </div>
      <div className="kai-meter__track" aria-hidden="true">
        <span style={{ width: `${percent}%` }} />
      </div>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

export function LifecycleRail({ steps = [] }) {
  const normalized = Array.isArray(steps) ? steps : [];
  return (
    <div
      className="kai-flow-rail"
      style={{ "--kai-flow-count": Math.max(1, normalized.length) }}
      aria-label="Lifecycle"
    >
      {normalized.map((step, index) => (
        <div
          className={`kai-flow-step is-${step.state || "pending"}`}
          key={step.id || step.label || index}
        >
          <small>{String(index + 1).padStart(2, "0")}</small>
          <strong>{step.label}</strong>
          {step.detail ? <span>{step.detail}</span> : null}
        </div>
      ))}
    </div>
  );
}

export function MiniTrend({ values = [], label = "Trend" }) {
  const numbers = values.map(Number).filter(Number.isFinite);
  if (numbers.length < 2) {
    return <span className="kai-mini-trend__empty">No trend yet</span>;
  }
  const min = Math.min(...numbers);
  const max = Math.max(...numbers);
  const range = max - min || 1;
  const points = numbers
    .map((value, index) => {
      const x = (index / (numbers.length - 1)) * 100;
      const y = 28 - ((value - min) / range) * 24;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg className="kai-mini-trend" viewBox="0 0 100 32" role="img" aria-label={label} preserveAspectRatio="none">
      <polyline points={points} />
    </svg>
  );
}

export function VisualSummary({ title, subtitle, children }) {
  return (
    <section className="kai-visual-card kai-visual-summary">
      <header>
        <div>
          <span className="kai-visual-summary__eyebrow">At a glance</span>
          <h2>{title}</h2>
        </div>
        {subtitle ? <p>{subtitle}</p> : null}
      </header>
      <div className="kai-visual-summary__body">{children}</div>
    </section>
  );
}

export function ExplainableCard({ title, summary, details, icon, status }) {
  return (
    <article className="kai-visual-card kai-explainable-card">
      <div className="kai-explainable-card__header">
        {icon ? <span className="kai-explainable-card__icon">{icon}</span> : null}
        <div>
          <strong>{title}</strong>
          {status ? <span className="kai-explainable-card__status">{status}</span> : null}
        </div>
      </div>
      {summary ? <p>{summary}</p> : null}
      {details ? (
        <details>
          <summary>Why / technical detail</summary>
          <div>{details}</div>
        </details>
      ) : null}
    </article>
  );
}
