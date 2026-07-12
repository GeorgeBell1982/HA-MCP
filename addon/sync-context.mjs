import { cp, mkdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
const files = [
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "tsconfig.json",
  "tsconfig.build.json",
];
const check = process.argv.includes("--check");
if (!check) {
  await mkdir("addon/app", { recursive: true });
  for (const file of files)
    await cp(file, join("addon/app", file), { force: true });
  await cp("src", "addon/app/src", { recursive: true, force: true });
}
const source = [...files, ...(await walk("src"))];
for (const file of source) {
  const expected = await digest(file);
  const actual = await digest(join("addon/app", file));
  if (expected !== actual)
    throw new Error(
      `Add-on build context drift: ${file}. Run node addon/sync-context.mjs`,
    );
}
async function walk(dir) {
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(path)));
    else out.push(path);
  }
  return out;
}
async function digest(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}
