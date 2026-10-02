export const mainWorkerRows = Object.freeze([
  "native-kernel-lease-helper-exit-contention-release-and-sigkill",
  "native-kernel-lease-lock-root-replacement-and-unsafe-mode-refused",
  ...["success", "reload_unknown", "probe_failure"].flatMap((mode) => [
    `native-real-ha-${mode}`,
    `native-retention-${mode}-archive-and-fresh-epoch`,
  ]),
  "native-real-ha-invalid-component-before-effect",
  "native-real-ha-sigkill-after-rename-and-fresh-process-recovery",
  "actual-wrapper-init-public-data-root-private-state",
  "actual-wrapper-non-tty-and-yes-refused",
  "actual-wrapper-pty-confirmed-producer-apply-real-ha-proof",
  "actual-wrapper-blocks-epoch-reuse-rotates-and-applies-next-proposal",
  "actual-wrapper-pty-confirmed-recovery-and-audit",
  "actual-wrapper-existing-epoch-missing-key-refuses-without-replacement",
]);
export const readonlyWorkerRows = Object.freeze([
  "actual-wrapper-readonly-mount-refuses-apply-and-recovery-before-grant-or-audit",
]);
export const boundaryRows = Object.freeze([
  "owned-ha-2026.9.4-startup",
  "candidate-and-checkpoint-components-valid",
  "invalid-ha-trigger-rejected-before-effect",
  "reload-and-exact-loaded-config-verified",
  "installed-but-not-reloaded-config-rejected",
  "restored-checkpoint-reloaded-and-verified",
  "owned-container-and-volume-removed",
]);
export function assertExactRows(actual, expected) {
  if (
    actual.length !== expected.length ||
    new Set(actual).size !== actual.length ||
    actual.some((entry) => !expected.includes(entry))
  )
    throw new Error("worker_evidence_incomplete");
}
export function parseWorkerRows(output, expected) {
  const rows = output
    .trim()
    .split("\n")
    .map((line) => {
      if (!/^PASSED [a-z0-9_-]+$/u.test(line))
        throw new Error("worker_output_invalid");
      return line.slice("PASSED ".length);
    });
  assertExactRows(rows, expected);
  return rows;
}
