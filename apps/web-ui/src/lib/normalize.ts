// Defensive normalizers for API responses whose arrays may be null or missing.
import type {
  AnalyzerStatusReport,
  CapabilityBundle,
  DiagnosticReport,
  Preflight,
  RecoveryObjectiveRegistry,
} from "../types"

export function list<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : []
}

export function normalizePreflight(value: Preflight): Preflight {
  return {
    ...value,
    interfaces: list(value.interfaces).map((item) => ({
      ...item,
      flags: list(item.flags),
      addresses: list(item.addresses),
      wireless_bands: list(item.wireless_bands),
    })),
  }
}

export function normalizeCapabilities(value: CapabilityBundle): CapabilityBundle {
  return {
    ...value,
    features: list(value.features),
    glossary: list(value.glossary),
    support_matrix: {
      ...value.support_matrix,
      certification_levels: list(value.support_matrix?.certification_levels),
      environments: list(value.support_matrix?.environments),
    },
  }
}

export function normalizeRecoveryObjectives(value: RecoveryObjectiveRegistry): RecoveryObjectiveRegistry {
  return {
    ...value,
    statuses: list(value.statuses),
    objectives: list(value.objectives).map((objective) => ({
      ...objective,
      evidence: list(objective.evidence),
      limitations: list(objective.limitations),
    })),
  }
}

export function normalizeDiagnostics(value: DiagnosticReport): DiagnosticReport {
  return {
    ...value,
    checks: list(value.checks).map((check) => ({ ...check, observations: list(check.observations) })),
    resource_pressure: {
      ...value.resource_pressure,
      causes: list(value.resource_pressure?.causes),
      actions: list(value.resource_pressure?.actions),
    },
  }
}

export function normalizeAnalyzers(value: AnalyzerStatusReport): AnalyzerStatusReport {
  return { ...value, analyzers: list(value.analyzers) }
}
