/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useEffect, useMemo, useState } from "react"
import {
  INVESTIGATION_EVENT,
  addAnalystNote,
  addArtifact,
  addFinding,
  addHypothesis,
  addTimelineEvent,
  clearInvestigationData,
  getStorageMode,
  investigationMarkdown,
  loadInvestigationState,
  setStorageMode,
} from "../lib/investigationStore"

const InvestigationContext = createContext(null)

export function InvestigationProvider({ children }) {
  const [state, setState] = useState(() => loadInvestigationState())
  const [storageMode, setModeState] = useState(() => getStorageMode())

  useEffect(() => {
    function handleUpdate(event) {
      setState(event.detail?.state || loadInvestigationState())
      setModeState(getStorageMode())
    }
    window.addEventListener(INVESTIGATION_EVENT, handleUpdate)
    window.addEventListener("storage", handleUpdate)
    return () => {
      window.removeEventListener(INVESTIGATION_EVENT, handleUpdate)
      window.removeEventListener("storage", handleUpdate)
    }
  }, [])

  const value = useMemo(() => ({
    state,
    storageMode,
    addArtifact,
    addTimelineEvent,
    addAnalystNote,
    addHypothesis,
    addFinding,
    setStorageMode: (mode) => {
      const next = setStorageMode(mode)
      setModeState(next)
      setState(loadInvestigationState())
      return next
    },
    clearInvestigationData: () => {
      clearInvestigationData()
      setState(loadInvestigationState())
    },
    markdown: () => investigationMarkdown(loadInvestigationState()),
  }), [state, storageMode])

  return <InvestigationContext.Provider value={value}>{children}</InvestigationContext.Provider>
}

export function useInvestigation() {
  const context = useContext(InvestigationContext)
  if (!context) throw new Error("useInvestigation must be used inside InvestigationProvider")
  return context
}
