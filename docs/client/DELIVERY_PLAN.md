# Reality Client Delivery Plan

Each phase ends in a focused commit and leaves the existing server console buildable.

## Phase 1: Architecture

- requirements, security model, runtime architecture, and packaging contract
- commit: `docs(client): define companion app architecture`

## Phase 2: Backend Scaffold

- independent Tauri app under `client/`
- command DTOs, error model, and minimal frontend placeholder
- commit: `chore(client): scaffold companion app`

## Phase 3: Connection Core

- VLESS + REALITY parser and strict validator
- redacted debug representation
- deterministic Xray config generator
- unit tests using non-production fixtures
- commit: `feat(client): add reality connection core`

## Phase 4: Profile Storage

- app-data profile index
- macOS Keychain and Windows Credential Manager integration
- import, list, rename, and delete commands
- commit: `feat(client): add secure profile storage`

## Phase 5: Xray Supervisor

- pinned sidecar manifest and packaging script
- serialized start/stop lifecycle
- local port readiness and bounded diagnostics
- commit: `feat(client): manage bundled xray core`

## Phase 6: System Proxy

- macOS and Windows adapters
- prior-state snapshot and crash recovery
- manual proxy remains available when system mutation fails
- commit: `feat(client): add recoverable system proxy mode`

## Phase 7: Release Validation

- macOS Apple Silicon smoke test
- macOS Intel and Windows x64 CI builds
- install, import, connect, disconnect, and recovery checklist
- commit: `chore(client): add cross-platform release checks`
