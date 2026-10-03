export function parseHaFixtureArguments(args) {
  const ack = "--ack-disposable-ha-boundary-smoke";
  if (args.length === 1 && args[0] === ack)
    return { fullWorkflow: false, architecture: "amd64" };
  if (args.length === 2 && args[0] === ack && args[1] === "--full-workflow")
    return { fullWorkflow: true, architecture: "amd64" };
  if (
    args.length === 4 &&
    args[0] === ack &&
    args[1] === "--full-workflow" &&
    args[2] === "--native-arm64-builder" &&
    /^sha256:[a-f0-9]{64}$/u.test(args[3])
  )
    return { fullWorkflow: true, architecture: "arm64", builder: args[3] };
  throw new Error("fixture_arguments_invalid");
}

export function assertFixtureArchitecture(images, daemon, expected) {
  const normalized =
    daemon === "aarch64" ? "arm64" : daemon === "x86_64" ? "amd64" : daemon;
  if (
    normalized !== expected ||
    images.some(
      (image) => image?.Os !== "linux" || image?.Architecture !== expected,
    )
  )
    throw new Error("fixture_architecture_mismatch");
}

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
  "native-mcp-fixture-decline-and-cancellation-before-effect",
  "native-mcp-fixture-approved-real-producer-apply-and-loaded-ha-proof",
  "native-mcp-fixture-rotation-preserves-live-config-and-reload-count",
  "native-dashboard-api-read-proposal-approval-save-and-readback",
  "native-dashboard-source-drift-and-uncertain-send-no-replay",
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
