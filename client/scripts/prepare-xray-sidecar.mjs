import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { basename, dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { unzipSync } from "fflate"

const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
const DOWNLOAD_TIMEOUT_MS = 60_000
const SUPPORTED_TARGETS = new Set([
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
])

export function parseTarget(argv, environment = process.env) {
  const targetArgument = argv.find((argument) => argument.startsWith("--target="))
  if (targetArgument) return targetArgument.slice("--target=".length)
  if (environment.TAURI_ENV_TARGET_TRIPLE) return environment.TAURI_ENV_TARGET_TRIPLE
  return execFileSync("rustc", ["--print", "host-tuple"], {
    encoding: "utf8",
    timeout: 10_000,
  }).trim()
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex")
}

export function officialAssetUrl(version, name) {
  return `https://github.com/XTLS/Xray-core/releases/download/v${version}/${name}`
}

export function extractPinnedExecutable(archiveBytes, target) {
  const expected = target.endsWith("windows-msvc") ? "xray.exe" : "xray"
  const entries = unzipSync(archiveBytes)
  const matching = Object.entries(entries).filter(
    ([name]) => basename(name).toLowerCase() === expected,
  )
  if (matching.length !== 1) {
    throw new Error(`Expected exactly one ${expected} in the pinned Xray archive`)
  }
  return matching[0][1]
}

async function download(url) {
  const response = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
  })
  if (!response.ok) throw new Error(`Xray download failed with HTTP ${response.status}`)
  const declaredSize = Number(response.headers.get("content-length") ?? 0)
  if (declaredSize > MAX_ARCHIVE_BYTES) throw new Error("Xray archive exceeds the size limit")
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) throw new Error("Xray archive exceeds the size limit")
  return bytes
}

async function obtainArchive({ asset, cachePath, environment, version }) {
  const suppliedArchive = environment.XRAY_SIDECAR_ARCHIVE
  if (suppliedArchive) return readFileSync(resolve(suppliedArchive))

  if (existsSync(cachePath)) {
    const cached = readFileSync(cachePath)
    if (sha256(cached) === asset.sha256) return cached
    rmSync(cachePath, { force: true })
  }
  if (environment.XRAY_SIDECAR_OFFLINE === "1") {
    throw new Error("The verified Xray archive is not cached and offline mode is enabled")
  }
  const bytes = await download(officialAssetUrl(version, asset.name))
  mkdirSync(dirname(cachePath), { recursive: true })
  const temporary = `${cachePath}.tmp-${process.pid}`
  writeFileSync(temporary, bytes, { mode: 0o600 })
  renameSync(temporary, cachePath)
  return bytes
}

export async function prepareSidecar({
  root,
  target,
  environment = process.env,
  verifyExecutable = true,
}) {
  if (!SUPPORTED_TARGETS.has(target)) {
    throw new Error(`Unsupported Xray sidecar target: ${target}`)
  }
  const manifest = JSON.parse(readFileSync(join(root, "xray-sidecar.json"), "utf8"))
  const asset = manifest.assets[target]
  if (!asset?.name || !/^[a-f0-9]{64}$/.test(asset.sha256)) {
    throw new Error(`The Xray sidecar manifest is invalid for ${target}`)
  }
  const cachePath = join(root, ".cache", "xray", manifest.version, asset.name)
  const archive = await obtainArchive({ asset, cachePath, environment, version: manifest.version })
  const actualChecksum = sha256(archive)
  if (actualChecksum !== asset.sha256) {
    throw new Error(`Xray archive checksum mismatch for ${asset.name}`)
  }

  const executable = extractPinnedExecutable(archive, target)
  const extension = target.endsWith("windows-msvc") ? ".exe" : ""
  const outputDirectory = join(root, "src-tauri", "binaries")
  const output = join(outputDirectory, `xray-${target}${extension}`)
  const temporary = `${output}.tmp-${process.pid}`
  mkdirSync(outputDirectory, { recursive: true })
  writeFileSync(temporary, executable, { mode: 0o700 })
  if (!target.endsWith("windows-msvc")) chmodSync(temporary, 0o755)

  const hostTarget = execFileSync("rustc", ["--print", "host-tuple"], {
    encoding: "utf8",
    timeout: 10_000,
  }).trim()
  if (verifyExecutable && target === hostTarget) {
    const versionOutput = execFileSync(temporary, ["version"], {
      encoding: "utf8",
      timeout: 10_000,
    })
    const detectedVersion = versionOutput.match(/^Xray\s+(\S+)/)?.[1]
    if (detectedVersion !== manifest.version) {
      rmSync(temporary, { force: true })
      throw new Error(`Expected Xray ${manifest.version}, found ${detectedVersion ?? "unknown"}`)
    }
  }
  rmSync(output, { force: true })
  renameSync(temporary, output)
  return { output, target, version: manifest.version, archiveSha256: actualChecksum }
}

async function main() {
  const root = dirname(dirname(fileURLToPath(import.meta.url)))
  const target = parseTarget(process.argv.slice(2))
  const result = await prepareSidecar({ root, target })
  process.stdout.write(
    `Prepared Xray ${result.version} for ${result.target} (${result.archiveSha256})\n`,
  )
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ""
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}
