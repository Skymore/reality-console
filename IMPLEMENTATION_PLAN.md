# Reality Console Implementation Plan

## Step 1. Lock Product And Stack

Output:

- project docs aligned around `Tauri + React + TypeScript + Tailwind + shadcn/ui + Radix`
- implementation phases defined

Commit goal:

- `docs: define implementation plan and stack`

## Step 2. Scaffold App Shell

Output:

- Tauri 2 project created
- React + TypeScript + Vite frontend running
- base Rust backend present

Commit goal:

- `chore: scaffold tauri react app`

## Step 3. Install UI Foundation

Output:

- Tailwind configured
- shadcn/ui initialized
- base tokens and theme CSS created from `DESIGN.md`
- core layout primitives ready

Commit goal:

- `feat: add design tokens and ui foundation`

## Step 4. Build Navigation Shell

Output:

- application frame with sidebar and top bar
- placeholder pages for Dashboard, Users, Config, Diagnostics, Logs, Backups, Settings
- visual system applied consistently

Commit goal:

- `feat: build application shell`

## Step 5. Add Local Xray Inspection

Output:

- commands to inspect xray installation, service state, config path, and network basics
- frontend status cards wired to backend commands

Commit goal:

- `feat: add local xray inspection`

## Step 6. Add User Management MVP

Output:

- read VLESS users from config
- add user, delete user, regenerate link
- validate config before save

Commit goal:

- `feat: add vless user management`

## Step 7. Add Diagnostics MVP

Output:

- config test results
- listening port checks
- recent logs and failure hints

Commit goal:

- `feat: add diagnostics workflow`

## Working Rules

- Each step should leave the app in a runnable state
- No direct config writes without backup creation
- No hidden state outside documented files unless intentionally designed
- Prefer explicit local commands over magical background behavior
