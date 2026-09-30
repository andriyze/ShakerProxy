export function coordinatedRetentionRunRequest(preview: unknown, password: string, policyRevision: number) {
  return {password, policy_revision: policyRevision, preview};
}
