import { Inbox } from "lucide-react"

export default function BaEmptyState({ icon: Icon, title, description, action, className = "" }) {
  const I = Icon || Inbox
  return (
    <div className={`ba-empty-state ${className}`}>
      <I className="ba-empty-icon" />
      <strong>{title}</strong>
      {description && <p>{description}</p>}
      {action && <button type="button" className="ba-button-primary" onClick={action.onClick}>{action.label}</button>}
    </div>
  )
}
