import { spawn } from "node:child_process";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Phase3OperatorError } from "./operatorApproval.js";

/** Linux BusyBox flock holds the inherited open-file description after it exits. */
export async function acquirePhase3OperatorLease(parent: string) {
  if (
    process.platform !== "linux" ||
    !isAbsolute(parent) ||
    resolve(parent) !== parent
  )
    throw new Phase3OperatorError("operator_lease_unavailable");
  const uid = BigInt(process.getuid!());
  const root = await lstat(parent, { bigint: true });
  if (!root.isDirectory() || root.uid !== uid || (root.mode & 0o077n) !== 0n)
    throw new Phase3OperatorError("operator_root_unsafe");
  const executable = "/bin/busybox";
  const binary = await lstat(executable, { bigint: true });
  if (
    (await realpath(executable)) !== executable ||
    !binary.isFile() ||
    binary.uid !== 0n ||
    (binary.mode & 0o022n) !== 0n
  )
    throw new Phase3OperatorError("operator_lease_unavailable");
  const path = join(parent, "operator.lock");
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );
  let released = false;
  const assertHeld = async () => {
    if (released) throw new Phase3OperatorError("operator_lease_released");
    const [opened, current, currentRoot] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(path, { bigint: true }),
      lstat(parent, { bigint: true }),
    ]);
    if (
      !same(opened, current) ||
      !current.isFile() ||
      current.nlink !== 1n ||
      current.uid !== uid ||
      current.size !== 0n ||
      (current.mode & 0o077n) !== 0n ||
      !same(root, currentRoot) ||
      !currentRoot.isDirectory() ||
      current.dev !== root.dev ||
      currentRoot.uid !== uid ||
      (currentRoot.mode & 0o077n) !== 0n
    )
      throw new Phase3OperatorError("operator_lease_unsafe");
  };
  try {
    await assertHeld();
    await new Promise<void>((resolveLock, reject) => {
      const child = spawn(executable, ["flock", "-n", "3"], {
        stdio: ["ignore", "ignore", "ignore", handle.fd],
        env: {},
        cwd: "/",
        shell: false,
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
      }, 5000);
      child.once("error", () => {
        clearTimeout(timer);
        reject(new Phase3OperatorError("operator_lease_unavailable"));
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        if (code === 0) resolveLock();
        else reject(new Phase3OperatorError("operator_busy"));
      });
    });
    await assertHeld();
    return {
      assertHeld,
      release: async () => {
        if (!released) {
          released = true;
          await handle.close();
        }
      },
    };
  } catch (error) {
    released = true;
    await handle.close();
    throw error;
  }
}

function same(left: BigIntStats, right: BigIntStats) {
  return left.dev === right.dev && left.ino === right.ino;
}
