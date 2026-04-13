import { useMemo, useState } from "react"
import { CalendarDays, Copy, KeyRound, QrCode, RefreshCcw, Trash2, UserPlus } from "lucide-react"
import QRCode from "react-qr-code"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import type { CreateUserInput, ManagedUser } from "@/lib/users"

type UsersPageProps = {
  users: ManagedUser[]
  configPath?: string | null
  metadataPath?: string | null
  isLoading: boolean
  error?: string | null
  mutationNotice?: string | null
  onRefresh: () => Promise<void>
  onCreateUser: (input: CreateUserInput) => Promise<void>
  onDeleteUser: (userId: string) => Promise<void>
}

export function UsersPage({
  users,
  configPath,
  metadataPath,
  isLoading,
  error,
  mutationNotice,
  onRefresh,
  onCreateUser,
  onDeleteUser,
}: UsersPageProps) {
  const [createOpen, setCreateOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<ManagedUser | null>(null)
  const [label, setLabel] = useState("")
  const [note, setNote] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [submitBusy, setSubmitBusy] = useState(false)
  const [actionBusyId, setActionBusyId] = useState<string | null>(null)
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null)

  const availableLinks = useMemo(
    () => users.filter((user) => Boolean(user.shareLink)).length,
    [users],
  )

  async function handleCreateUser() {
    try {
      setSubmitBusy(true)
      setFormError(null)
      await onCreateUser({
        label,
        note,
      })
      setLabel("")
      setNote("")
      setCreateOpen(false)
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : "Failed to create user.")
    } finally {
      setSubmitBusy(false)
    }
  }

  async function handleCopyLink(user: ManagedUser) {
    if (!user.shareLink) {
      setCopyFeedback(`Share link is unavailable for ${user.label}.`)
      return
    }

    try {
      await navigator.clipboard.writeText(user.shareLink)
      setCopyFeedback(`Copied link for ${user.label}.`)
    } catch (nextError) {
      setCopyFeedback(
        nextError instanceof Error ? nextError.message : `Could not copy link for ${user.label}.`,
      )
    }
  }

  async function handleDeleteUser(user: ManagedUser) {
    if (!window.confirm(`Delete ${user.label}? This removes the UUID from the live config.`)) {
      return
    }

    try {
      setActionBusyId(user.id)
      await onDeleteUser(user.id)
    } finally {
      setActionBusyId(null)
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <Card className="border-border/60 bg-panel/80 shadow-panel">
        <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <CardTitle className="font-heading text-3xl">User roster</CardTitle>
            <CardDescription>
              Real users are now read from the active Xray config, not hard-coded preview data.
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              className="rounded-full px-4"
              onClick={() => void onRefresh()}
              disabled={isLoading}
            >
              <RefreshCcw className={isLoading ? "size-4 animate-spin" : "size-4"} />
              Refresh
            </Button>
            <Button className="rounded-full px-4" onClick={() => setCreateOpen(true)}>
              <UserPlus className="size-4" />
              Add user
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {error ? (
            <Banner tone="danger" text={error} />
          ) : null}
          {mutationNotice ? <Banner tone="neutral" text={mutationNotice} /> : null}
          {copyFeedback ? <Banner tone="neutral" text={copyFeedback} /> : null}

          {users.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-border/70 bg-background/75 px-5 py-8 text-sm text-muted-foreground">
              No VLESS users were found in the current config.
            </div>
          ) : (
            users.map((user) => (
              <div
                key={user.id}
                className="flex flex-col gap-4 rounded-3xl border border-border/60 bg-background/80 p-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-base font-medium">{user.label}</span>
                      <Badge variant="secondary" className="rounded-full">
                        {user.flow ?? "xtls-rprx-vision"}
                      </Badge>
                      {user.shareLink ? (
                        <Badge className="rounded-full bg-primary/12 text-primary hover:bg-primary/12">
                          Ready to share
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="rounded-full">
                          Link unavailable
                        </Badge>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <KeyRound className="size-3.5" />
                      <span className="font-mono">{user.id}</span>
                    </div>

                    {user.createdAt ? (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <CalendarDays className="size-3.5" />
                        <span>{new Date(user.createdAt * 1000).toLocaleString()}</span>
                      </div>
                    ) : null}

                    <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
                      {user.note ?? "No note yet. This user is still managed, but has no local metadata note."}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="rounded-full px-3"
                      onClick={() => void handleCopyLink(user)}
                      disabled={!user.shareLink}
                    >
                      <Copy className="size-4" />
                      Copy link
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="rounded-full px-3"
                      onClick={() => setSelectedUser(user)}
                      disabled={!user.shareLink}
                    >
                      <QrCode className="size-4" />
                      Show QR
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="rounded-full px-3 text-destructive hover:text-destructive"
                      onClick={() => void handleDeleteUser(user)}
                      disabled={actionBusyId === user.id}
                    >
                      <Trash2 className="size-4" />
                      {actionBusyId === user.id ? "Deleting..." : "Delete"}
                    </Button>
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Card className="border-border/60 bg-secondary/75 shadow-none">
        <CardHeader>
          <CardTitle className="font-heading text-2xl">User management state</CardTitle>
          <CardDescription>Links are built from the live config plus local network discovery.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <FactRow label="Configured users" value={String(users.length)} />
          <FactRow label="Shareable links" value={String(availableLinks)} />
          <FactRow label="Config path" value={configPath ?? "Unknown"} mono />
          <FactRow label="Metadata path" value={metadataPath ?? "Unknown"} mono />
          <div className="rounded-3xl border border-border/60 bg-background/75 p-4 leading-6 text-muted-foreground">
            Notes live outside the raw Xray config so the UI can keep operator-only context without
            polluting transport settings.
          </div>
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="border-border/70 bg-background sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-heading text-3xl">Create VLESS user</DialogTitle>
            <DialogDescription>
              Leave the label empty to auto-generate the next `friend-N` slot.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="user-label">Label</Label>
              <Input
                id="user-label"
                value={label}
                onChange={(event) => setLabel(event.currentTarget.value)}
                placeholder="friend-6"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-note">Note</Label>
              <Textarea
                id="user-note"
                value={note}
                onChange={(event) => setNote(event.currentTarget.value)}
                placeholder="Temporary test account for iPhone"
                rows={4}
              />
            </div>
            {formError ? <Banner tone="danger" text={formError} /> : null}
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={submitBusy}>
                Cancel
              </Button>
              <Button onClick={() => void handleCreateUser()} disabled={submitBusy}>
                {submitBusy ? "Creating..." : "Create user"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(selectedUser)} onOpenChange={(open) => !open && setSelectedUser(null)}>
        <DialogContent className="border-border/70 bg-background sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-heading text-3xl">
              {selectedUser?.label ?? "Share user"}
            </DialogTitle>
            <DialogDescription>
              Scan this on a supported mobile client, or copy the raw link directly.
            </DialogDescription>
          </DialogHeader>

          {selectedUser?.shareLink ? (
            <div className="space-y-4">
              <div className="flex justify-center rounded-3xl border border-border/60 bg-white p-4">
                <QRCode value={selectedUser.shareLink} size={220} />
              </div>
              <div className="rounded-3xl border border-border/60 bg-background/80 p-4 font-mono text-xs leading-6 text-muted-foreground">
                {selectedUser.shareLink}
              </div>
              <div className="flex justify-end">
                <Button onClick={() => void handleCopyLink(selectedUser)}>
                  <Copy className="size-4" />
                  Copy link
                </Button>
              </div>
            </div>
          ) : (
            <Banner tone="danger" text="A share link could not be generated for this user." />
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}

function FactRow({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="rounded-3xl border border-border/60 bg-background/75 p-4">
      <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">{label}</div>
      <div className={mono ? "mt-2 break-all font-mono text-sm" : "mt-2 text-sm font-medium"}>{value}</div>
    </div>
  )
}

function Banner({
  text,
  tone,
}: {
  text: string
  tone: "neutral" | "danger"
}) {
  return (
    <div
      className={
        tone === "danger"
          ? "rounded-3xl border border-destructive/25 bg-destructive/10 px-4 py-3 text-sm text-destructive"
          : "rounded-3xl border border-border/70 bg-background/75 px-4 py-3 text-sm text-muted-foreground"
      }
    >
      {text}
    </div>
  )
}
