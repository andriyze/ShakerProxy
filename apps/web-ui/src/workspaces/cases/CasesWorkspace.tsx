import React from "react"
import { FeatureViews } from "../../shell/common"
import { CaseWorkspace } from "./CaseWorkspace"

export function CasesWorkspace() {
  return (
    <>
      <CaseWorkspace />
      <FeatureViews workspace="cases" />
    </>
  )
}
