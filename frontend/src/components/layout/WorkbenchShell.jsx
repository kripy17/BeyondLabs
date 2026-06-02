export function WorkbenchPage({ children, className = "", fixed = false }) {
  return (
    <div className={`ba-workbench-page ba-anim-page-in ba-stagger ${fixed ? "ba-workbench-page-fixed" : ""} ${className}`}>
      {children}
    </div>
  )
}

export function WorkbenchHeader({ title, subtitle, eyebrow, icon: Icon, chips, actions }) {
  return (
    <header className="ba-workbench-header ba-page-header-compact ba-workbench-topbar">
      <div className="ba-workbench-header-main">
        {eyebrow && <p className="ba-workbench-eyebrow">{eyebrow}</p>}
        <div className="ba-workbench-title-row">
          {Icon && (
            <span className="ba-workbench-title-icon">
              <Icon className="h-5 w-5" />
            </span>
          )}
          <h1>{title}</h1>
        </div>
        {subtitle && <p className="ba-workbench-subtitle">{subtitle}</p>}
        {chips?.length ? (
          <div className="ba-workbench-chip-row">
            {chips.map((chip) => (
              <span key={chip.label || chip} className={`ba-chip ${chip.tone ? `ba-status-${chip.tone}` : ""}`}>
                {chip.label || chip}
              </span>
            ))}
          </div>
        ) : null}
      </div>
      {actions && <div className="ba-workbench-header-actions">{actions}</div>}
    </header>
  )
}

export function WorkbenchPanel({ children, className = "", soft = false }) {
  return (
    <section className={`${soft ? "ba-workbench-panel-soft" : "ba-workbench-panel"} ${className}`}>
      {children}
    </section>
  )
}
