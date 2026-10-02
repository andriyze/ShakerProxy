import { isStaleBuildError, reloadForNewVersion } from "../lib/staleBuild"
import React from "react"
import { viewsFor, type WorkspaceID } from "../features"

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main>
      <div className="brand">
        <span className="mark">S</span>
        <span>SHAKERPROXY</span>
        <span className="version">PRE-ALPHA</span>
      </div>
      <section className="panel">{children}</section>
    </main>
  )
}

export function Card({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <article className="card">
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  )
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error" role="alert">
      {message}
      {onRetry && (
        <button type="button" className="quiet error-retry" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function Notice({ children, tone = "info" }: { children: React.ReactNode; tone?: "info" | "warn" | "good" }) {
  return (
    <p className={`notice notice-${tone}`} role="status">
      {children}
    </p>
  )
}

export function EmptyState({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <section className="empty-state">
      <h2>{title}</h2>
      {children}
    </section>
  )
}

type BoundaryProps = { title: string; children: React.ReactNode }
type BoundaryState = { error: Error | null }

// FeatureBoundary keeps one failing feature module from taking down the page.
export class FeatureBoundary extends React.Component<BoundaryProps, BoundaryState> {
  state: BoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error }
  }

  componentDidCatch(error: Error) {
    if (isStaleBuildError(error)) reloadForNewVersion()
  }

  render() {
    if (this.state.error && isStaleBuildError(this.state.error)) {
      return (
        <div className="error" role="alert">
          ShakerProxy was updated. Reload the page to use the new version.
          <button type="button" className="quiet error-retry" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      )
    }
    if (this.state.error) {
      return (
        <div className="error" role="alert">
          “{this.props.title}” could not be shown: {this.state.error.message || "unexpected error"}. The rest of this
          page still works.
          <button type="button" className="quiet error-retry" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// FeatureViews renders the feature modules registered for a workspace
// (features/registry.ts viewsFor), in their declared order.
export function FeatureViews({ workspace }: { workspace: WorkspaceID }) {
  const views = viewsFor(workspace)
  if (views.length === 0) return null
  return (
    <>
      {views.map((view) => (
        <section key={view.id} className="feature-view" aria-label={view.title} data-feature={view.id}>
          <FeatureBoundary title={view.title}>
            <view.Component />
          </FeatureBoundary>
        </section>
      ))}
    </>
  )
}

export function hasFeatureViews(workspace: WorkspaceID): boolean {
  return viewsFor(workspace).length > 0
}
