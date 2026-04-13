# Reality Console Requirements

## 1. Product Goal

Reality Console is a local-first management app for running and maintaining an `Xray + REALITY` server on a personal machine.

The app should reduce the need to manually edit JSON, copy links by hand, inspect terminal output, or remember network prerequisites like public IP, port forwarding, and service status.

## 2. Target User

- Individual self-hosters running `Xray` locally on macOS first
- Small-scale sharing scenarios: self + a few friends
- Users comfortable with technical terms, but not interested in editing raw config files every time

## 3. Problems To Solve

- It is easy to break `config.json` by hand.
- User management is primitive when all friends share one UUID.
- Connection links, QR codes, and parameter changes are tedious to maintain manually.
- It is hard to tell whether failure is caused by app config, service state, firewall, public IP, or router setup.
- Existing panels are usually Linux/VPS-oriented, while this setup is local-first on macOS.

## 4. Product Principles

- Local-first: no required cloud backend
- Safe by default: validate before writing config changes
- Observable: always show current service state and last validation result
- Reversible: every config write creates a backup
- Focused: optimize for single-node local management, not multi-tenant hosting

## 5. Recommended MVP

### 5.1 Service Overview

- Detect whether `xray` is installed
- Show running state, version, PID, listen port, public IPv4, LAN IP
- Show current active config path
- Provide `start`, `stop`, `restart`, and `test config` actions

### 5.2 User Management

- Read current VLESS users from config
- Add user with generated UUID
- Delete or disable a user
- Edit user label and note
- Generate share link for each user
- Generate QR code for each user

### 5.3 REALITY Settings

- Show and edit:
  - listen port
  - target
  - serverNames
  - public key
  - shortIds
- Validate key fields before save
- Warn when settings are inconsistent with client parameters

### 5.4 Diagnostics

- Show public IP and whether it matches router WAN IP when available
- Check whether Xray is listening on the configured port
- Check whether local config passes `xray ... -test`
- Show recent service logs
- Provide guided hints for common failures:
  - wrong import type
  - port not forwarded
  - SNI mismatch
  - outdated client
  - service not listening

### 5.5 Backups

- Create timestamped backups before config writes
- Allow restore from recent backup

## 6. Post-MVP Candidates

- Traffic counters per user
- Temporary user expiration
- User pause/resume without deletion
- Multiple inbound templates
- Subscription export
- Multi-node support
- Remote access from another device on the LAN

## 7. Explicit Non-Goals For V0

- Billing
- Team collaboration
- Cloud sync
- Multi-server orchestration
- Full replacement for VPS-oriented Linux panels like `3x-ui`

## 8. Platform Recommendation

Recommended default stack:

- `Tauri 2`
- `React + TypeScript + Vite`
- `Tailwind CSS`
- `shadcn/ui`
- `Radix UI`

Reasoning:

- Better fit than a pure web app for local filesystem and process control
- Lighter than Electron for a utility app
- Easier to package as a native macOS desktop tool
- `shadcn/ui + Radix` gives strong accessibility primitives without locking the app into a generic admin look

## 8.1 UI System Intent

- Use `DESIGN.md` as the visual source of truth
- Implement project tokens as CSS variables first, then map them into Tailwind utilities
- Prefer composing `Radix` primitives and `shadcn/ui` building blocks instead of heavy all-in-one admin kits
- Keep the interface warm and editorial rather than default enterprise gray

Alternative if we want fastest prototype:

- Local web dashboard with `Next.js` or `Vite + React`

This is faster to build, but weaker for native local integration and packaging.

## 9. Initial Information Architecture

- Dashboard
- Users
- Config
- Diagnostics
- Logs
- Backups
- Settings

## 10. Open Questions

- macOS-only first, or Windows support from day one?
- Do we want the app to manage only one local Xray instance, or also import multiple configs?
- Should the app store friend notes and labels outside `config.json`?
- Should QR code sharing be a first-class flow in the first build?
- Do we want guided router help inside the app, or just status checks?

## 11. Proposed First Build Scope

If we want to start coding immediately, the first implementation should include only:

- Read current local config
- Show service status
- Show users list
- Add/delete user
- Generate link + QR code
- Restart service
- Validate config before save

This is the smallest useful version.
