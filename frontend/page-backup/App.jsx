import { Component, Suspense, lazy, useMemo, useEffect, useState } from "react"
import { AlertTriangle, Home, Loader2, RefreshCcw } from "lucide-react"
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from "react-router-dom"
import "./index.css"
import HomePage from "./components/home/HomePage"
import Topbar from "./components/layout/Topbar"
import BaBackendBanner from "./components/layout/BaBackendBanner"

const AttachmentTriagePage = lazy(() => import("./pages/triage/AttachmentTriagePage"))
const CyberChefPage = lazy(() => import("./pages/tools/CyberChefPage"))
const DetectionMitrePage = lazy(() => import("./pages/detection/DetectionMitrePage"))
const IdsBuilderPage = lazy(() => import("./pages/tools/IdsBuilderPage"))
const InvestigationTimelinePage = lazy(() => import("./pages/detection/InvestigationTimelinePage"))
const LogsAlertsPage = lazy(() => import("./pages/siem/LogsAlertsPage"))
const NmapRunnerPage = lazy(() => import("./pages/recon/NmapRunnerPage"))
const OsintToolsPage = lazy(() => import("./pages/recon/OsintToolsPage"))
const PhishingTriagePage = lazy(() => import("./pages/triage/PhishingTriagePage"))
const ReconExposurePage = lazy(() => import("./pages/recon/ReconExposurePage"))
const SafeUrlAnalyzerPage = lazy(() => import("./pages/triage/SafeUrlAnalyzerPage"))
const SettingsPage = lazy(() => import("./pages/settings/SettingsPage"))
const SiemWorkspacePage = lazy(() => import("./pages/siem/SiemWorkspacePage"))
const SmartParserPage = lazy(() => import("./pages/triage/SmartParserPage"))
const SocGuidePage = lazy(() => import("./pages/detection/SocGuidePage"))
import { InvestigationProvider } from "./context/InvestigationContext"
import { applyTheme, loadThemePreference } from "./lib/theme"
import { WORKSPACES, ALL_WORKSPACES, ROUTE_TO_PAGE, navigateToPage } from "./lib/navigation"
import useShortcuts from "./lib/useShortcuts"
import { recordPageVisit } from "./lib/navigationTracker"

function LoadingWorkbench() {
  return (
    <section className="ba-route-loading" aria-live="polite" aria-busy="true">
      <Loader2 className="h-5 w-5 animate-spin" />
      <span>Loading workspace...</span>
    </section>
  )
}

function BootScreen({ visible }) {
  if (!visible) return null
  return (
    <section className="ba-boot-screen" aria-label="BeyondArch boot screen">
      <div className="ba-boot-panel">
        <div className="ba-boot-spinner" />
        <div>
          <p>BeyondArch</p>
          <span>loading …</span>
        </div>
      </div>
    </section>
  )
}

const PAGE_TITLES = {
  home: "Home",
  "smart-parser": "Artifact Intake",
  "phishing-triage": "Phishing Triage",
  "safe-url-analyzer": "Safe URL Analyzer",
  "recon-exposure": "Recon & Exposure",
  "osint-tools": "OSINT Tools",
  "nmap-runner": "Nmap Runner",
  "cyberchef": "CyberChef",
  "ids-builder": "IDS Builder",
  "logs-alerts": "Logs & Alerts",
  "siem": "SIEM Workspace",
  "attachment-triage": "Attachment Triage",
  "detection-mitre": "Detection & MITRE",
  "soc-guide": "SOC Guide",
  "case-timeline": "Case Timeline",
  "settings": "Settings",
}

function NotFoundPage() {
  return (
    <div className="space-y-4 p-3">
      <div className="flex items-center gap-3">
        <AlertTriangle className="h-6 w-6 text-amber-100" />
        <div>
          <p className="text-[0.65rem] font-black uppercase tracking-[0.14em] text-zinc-400">404</p>
          <h1 className="text-2xl font-black text-zinc-50">Page not found</h1>
        </div>
      </div>
      <p className="text-sm leading-6 text-zinc-300">The route you requested does not exist. Use the workspace menu above to navigate to a BeyondArch page.</p>
    </div>
  )
}

class PageErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }
  static getDerivedStateFromError(error) {
    return { error }
  }
  componentDidUpdate(previousProps) {
    if (previousProps.page !== this.props.page && this.state.error) {
      this.setState({ error: null })
    }
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <section className="ba-route-error" role="alert">
        <div className="ba-route-error-title">
          <AlertTriangle className="h-5 w-5" />
          <h2>Workspace failed to render</h2>
        </div>
        <p>This page hit a frontend rendering error. The shell is still running.</p>
        <pre>{this.state.error?.message || String(this.state.error)}</pre>
        <div className="ba-route-error-actions">
          <button type="button" className="ba-button-primary" onClick={() => this.setState({ error: null })}>
            <RefreshCcw className="h-4 w-4" /> Retry page
          </button>
          <button type="button" className="ba-button-secondary" onClick={() => this.props.navigate?.("/")}>
            <Home className="h-4 w-4" /> Go home
          </button>
        </div>
      </section>
    )
  }
}

function AppRoutes() {
  const navigate = useNavigate()
  const location = useLocation()
  const [theme, setTheme] = useState(() => loadThemePreference())
  const [bootVisible, setBootVisible] = useState(true)

  const page = ROUTE_TO_PAGE[location.pathname] || "404"
  const isHomePage = page === "home"

  useEffect(() => {
    document.title = `BeyondArch — ${PAGE_TITLES[page] || page}`
    recordPageVisit(page)
  }, [page])

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  useEffect(() => {
    const prefersReduced = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches
    const id = window.setTimeout(() => setBootVisible(false), prefersReduced ? 50 : 320)
    return () => window.clearTimeout(id)
  }, [])

  useEffect(() => {
    function handleThemeChange(event) {
      setTheme(event.detail?.theme || loadThemePreference())
    }
    window.addEventListener("beyondarch-theme-change", handleThemeChange)
    window.addEventListener("storage", handleThemeChange)
    return () => {
      window.removeEventListener("beyondarch-theme-change", handleThemeChange)
      window.removeEventListener("storage", handleThemeChange)
    }
  }, [])

  const shortcuts = useMemo(() => [
    { key: "gh", action: () => navigateToPage(navigate, "home") },
    { key: "ga", action: () => navigateToPage(navigate, "smart-parser") },
    { key: "gp", action: () => navigateToPage(navigate, "phishing-triage") },
    { key: "gu", action: () => navigateToPage(navigate, "safe-url-analyzer") },
    { key: "gr", action: () => navigateToPage(navigate, "recon-exposure") },
    { key: "gs", action: () => navigateToPage(navigate, "settings") },
    { key: "gl", action: () => navigateToPage(navigate, "logs-alerts") },
    { key: "gd", action: () => navigateToPage(navigate, "detection-mitre") },
    { key: "gc", action: () => navigateToPage(navigate, "cyberchef") },
    { key: "gt", action: () => navigateToPage(navigate, "case-timeline") },
    { key: "/", action: () => {
      window.dispatchEvent(new CustomEvent("beyondarch:open-command-palette"))
    }},
  ], [navigate])
  useShortcuts(shortcuts)

  function renderPage() {
    switch (page) {
      case "home":
        return <HomePage />
      case "cyberchef":
        return <CyberChefPage />
      case "osint-tools":
        return <OsintToolsPage />
      case "nmap-runner":
        return <NmapRunnerPage />
      case "ids-builder":
        return <IdsBuilderPage />
      case "smart-parser":
        return <SmartParserPage />
      case "phishing-triage":
        return <PhishingTriagePage />
      case "safe-url-analyzer":
        return <SafeUrlAnalyzerPage />
      case "recon-exposure":
        return <ReconExposurePage />
      case "logs-alerts":
        return <LogsAlertsPage />
      case "siem":
        return <SiemWorkspacePage />
      case "attachment-triage":
        return <AttachmentTriagePage />
      case "detection-mitre":
        return <DetectionMitrePage />
      case "soc-guide":
        return <SocGuidePage />
      case "case-timeline":
        return <InvestigationTimelinePage />
      case "settings":
        return <SettingsPage />
      default:
        return <NotFoundPage />
    }
  }

  const pageClass = `ba-app-page-${String(page).replace(/[^a-z0-9-]/gi, "-").toLowerCase()}`

  return (
    <div className={`ba-app dark ${isHomePage ? "ba-app-home" : ""} ${pageClass}`} data-theme={theme}>
      <BootScreen visible={bootVisible} />
      <BaBackendBanner />
      <Topbar page={page} groups={WORKSPACES} options={ALL_WORKSPACES} />
      <main className="ba-main-shell">
        <div key={page} className={isHomePage ? "ba-home-shell" : "ba-page-shell"}>
          <PageErrorBoundary page={page} navigate={navigate}>
            <Suspense fallback={<LoadingWorkbench />}>
              {renderPage()}
            </Suspense>
          </PageErrorBoundary>
        </div>
      </main>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <InvestigationProvider>
        <Routes>
          <Route path="/*" element={<AppRoutes />} />
        </Routes>
      </InvestigationProvider>
    </BrowserRouter>
  )
}

export default App
