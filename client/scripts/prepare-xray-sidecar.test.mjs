import assert from "node:assert/strict"
import { mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { mkdtemp } from "node:fs/promises"
import { zipSync } from "fflate"
import {
  extractPinnedExecutable,
  officialAssetUrl,
  parseTarget,
  prepareSidecar,
  sha256,
} from "./prepare-xray-sidecar.mjs"

test("target selection prefers an explicit target over Tauri environment", () => {
  assert.equal(
    parseTarget(["--target=x86_64-pc-windows-msvc"], {
      TAURI_ENV_TARGET_TRIPLE: "aarch64-apple-darwin",
    }),
    "x86_64-pc-windows-msvc",
  )
})

test("official release URL is derived only from pinned manifest fields", () => {
  assert.equal(
    officialAssetUrl("26.3.27", "Xray-windows-64.zip"),
    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip",
  )
})

test("extractor requires exactly one target-named executable", () => {
  const archive = zipSync({ "nested/xray": new Uint8Array([1, 2, 3]) })
  assert.deepEqual(Array.from(extractPinnedExecutable(archive, "aarch64-apple-darwin")), [1, 2, 3])
  assert.throws(
    () => extractPinnedExecutable(zipSync({ README: new Uint8Array([1]) }), "aarch64-apple-darwin"),
    /exactly one xray/,
  )
})

test("prepare verifies a supplied archive and writes only the target sidecar", async () => {
  const root = await mkdtemp(join(tmpdir(), "connect-sidecar-"))
  mkdirSync(join(root, "src-tauri", "binaries"), { recursive: true })
  const archive = zipSync({
    xray: new TextEncoder().encode("pinned executable"),
    "geoip.dat": new TextEncoder().encode("not extracted"),
  })
  const archivePath = join(root, "fixture.zip")
  writeFileSync(archivePath, archive)
  writeFileSync(
    join(root, "xray-sidecar.json"),
    JSON.stringify({
      version: "26.3.27",
      assets: {
        "aarch64-apple-darwin": {
          name: "fixture.zip",
          sha256: sha256(archive),
        },
      },
    }),
  )

  const result = await prepareSidecar({
    root,
    target: "aarch64-apple-darwin",
    environment: { XRAY_SIDECAR_ARCHIVE: archivePath },
    verifyExecutable: false,
  })
  assert.equal(readFileSync(result.output, "utf8"), "pinned executable")
  assert.equal(result.archiveSha256, sha256(archive))
})

test("prepare rejects an archive whose checksum differs from the pin", async () => {
  const root = await mkdtemp(join(tmpdir(), "connect-sidecar-"))
  const archivePath = join(root, "fixture.zip")
  writeFileSync(archivePath, zipSync({ xray: new Uint8Array([7]) }))
  writeFileSync(
    join(root, "xray-sidecar.json"),
    JSON.stringify({
      version: "26.3.27",
      assets: {
        "aarch64-apple-darwin": {
          name: "fixture.zip",
          sha256: "0".repeat(64),
        },
      },
    }),
  )
  await assert.rejects(
    prepareSidecar({
      root,
      target: "aarch64-apple-darwin",
      environment: { XRAY_SIDECAR_ARCHIVE: archivePath },
      verifyExecutable: false,
    }),
    /checksum mismatch/,
  )
})

test("Tauri platform bundles require the matching external sidecar", () => {
  const root = join(import.meta.dirname, "..")
  const base = JSON.parse(readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8"))
  const macos = JSON.parse(
    readFileSync(join(root, "src-tauri", "tauri.macos.conf.json"), "utf8"),
  )
  const windows = JSON.parse(
    readFileSync(join(root, "src-tauri", "tauri.windows.conf.json"), "utf8"),
  )
  const manifest = JSON.parse(readFileSync(join(root, "xray-sidecar.json"), "utf8"))

  assert.deepEqual(base.bundle.externalBin, ["binaries/xray"])
  assert.deepEqual(Object.keys(manifest.assets).sort(), [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
  ])
  assert.deepEqual(macos.bundle.targets, ["app", "dmg"])
  assert.equal(macos.bundle.macOS.hardenedRuntime, true)
  assert.deepEqual(windows.bundle.targets, ["nsis"])
  assert.equal(windows.bundle.windows.digestAlgorithm, "sha256")
  assert.equal(windows.bundle.windows.nsis.installMode, "currentUser")
})
