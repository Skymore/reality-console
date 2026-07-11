import { execFileSync } from "node:child_process"
import { chmodSync, copyFileSync, mkdirSync, readFileSync } from "node:fs"
import { delimiter, dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

function findExecutable(name) {
  const extension = process.platform === "win32" ? ".exe" : ""
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    const candidate = join(directory, `${name}${extension}`)
    try {
      execFileSync(candidate, ["version"], { stdio: "ignore" })
      return candidate
    } catch {
      // Continue through PATH.
    }
  }
  throw new Error("xray was not found in PATH")
}

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const manifest = JSON.parse(readFileSync(join(root, "xray-sidecar.json"), "utf8"))
const target = execFileSync("rustc", ["--print", "host-tuple"], { encoding: "utf8" }).trim()
const extension = process.platform === "win32" ? ".exe" : ""
const outputDirectory = join(root, "src-tauri", "binaries")
const output = join(outputDirectory, `xray-${target}${extension}`)
const source = findExecutable("xray")
const versionOutput = execFileSync(source, ["version"], { encoding: "utf8" })
const detectedVersion = versionOutput.match(/^Xray\s+(\S+)/)?.[1]

if (!manifest.assets[target]) {
  throw new Error(`Unsupported Xray sidecar target: ${target}`)
}
if (detectedVersion !== manifest.version) {
  throw new Error(`Expected Xray ${manifest.version}, found ${detectedVersion ?? "unknown"}`)
}

mkdirSync(outputDirectory, { recursive: true })
copyFileSync(source, output)
if (process.platform !== "win32") chmodSync(output, 0o755)

console.log(`Prepared ${output}`)
