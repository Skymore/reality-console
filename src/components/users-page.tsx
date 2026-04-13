import { useCallback, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { ClipboardCopy, Copy, Pencil, QrCode, RefreshCcw, Trash2, UserPlus } from "lucide-react"
import QRCode from "react-qr-code"

import { Banner } from "@/components/banner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { CreateUserInput, ManagedUser, TrafficResponse } from "@/lib/users"

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const value = bytes / Math.pow(1024, i)
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

type UsersPageProps = {
  users: ManagedUser[]
  configPath?: string | null
  trafficResponse?: TrafficResponse | null
  isLoading: boolean
  error?: string | null
  mutationNotice?: string | null
  showToast: (msg: string) => void
  onRefresh: () => Promise<void>
  onCreateUser: (input: CreateUserInput) => Promise<void>
  onUpdateLabel: (userId: string, newLabel: string) => Promise<void>
  onUpdateNote: (userId: string, newNote: string) => Promise<void>
  onDeleteUser: (userId: string) => Promise<void>
}

export function UsersPage({
  users,
  configPath,
  trafficResponse,
  isLoading,
  error,
  mutationNotice,
  showToast,
  onRefresh,
  onCreateUser,
  onUpdateLabel,
  onUpdateNote,
  onDeleteUser,
}: UsersPageProps) {
  const { t } = useTranslation()
  const [createOpen, setCreateOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<ManagedUser | null>(null)
  const [label, setLabel] = useState("")
  const [note, setNote] = useState("")
  const [formError, setFormError] = useState<string | null>(null)
  const [submitBusy, setSubmitBusy] = useState(false)
  const [actionBusyId, setActionBusyId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ManagedUser | null>(null)
  const [editingUser, setEditingUser] = useState<{ id: string; label: string; note: string } | null>(null)
  const qrRef = useRef<HTMLDivElement>(null)

  const handleCopyQr = useCallback(async () => {
    const svg = qrRef.current?.querySelector("svg")
    if (!svg) return
    try {
      const canvas = document.createElement("canvas")
      const padding = 32
      canvas.width = 200 + padding * 2
      canvas.height = 200 + padding * 2
      const ctx = canvas.getContext("2d")!
      ctx.fillStyle = "#ffffff"
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      const svgData = new XMLSerializer().serializeToString(svg)
      const img = new Image()
      img.src = "data:image/svg+xml;base64," + btoa(svgData)
      await new Promise<void>((resolve) => { img.onload = () => resolve() })
      ctx.drawImage(img, padding, padding, 200, 200)
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"))
      if (blob) {
        await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })])
        showToast(t("users.qrCopied"))
      }
    } catch {
      showToast(t("users.qrCopyFailed"))
    }
  }, [selectedUser, t])

  async function handleCreateUser() {
    try {
      setSubmitBusy(true)
      setFormError(null)
      await onCreateUser({ label, note })
      setLabel("")
      setNote("")
      setCreateOpen(false)
    } catch (nextError) {
      setFormError(nextError instanceof Error ? nextError.message : t("users.createFailed"))
    } finally {
      setSubmitBusy(false)
    }
  }

  async function handleCopyLink(user: ManagedUser) {
    if (!user.shareLink) {
      showToast(t("users.linkNA", { label: user.label }))
      return
    }
    try {
      await navigator.clipboard.writeText(user.shareLink)
      showToast(t("users.copied", { label: user.label }))
    } catch (nextError) {
      showToast(
        nextError instanceof Error ? nextError.message : t("users.copyFailed", { label: user.label }),
      )
    }
  }

  async function saveEdit() {
    if (!editingUser || !editingUser.label.trim()) return
    try {
      await onUpdateLabel(editingUser.id, editingUser.label.trim())
      await onUpdateNote(editingUser.id, editingUser.note)
      setEditingUser(null)
    } catch { /* error shown by parent */ }
  }

  async function confirmDelete() {
    if (!deleteTarget) return
    try {
      setActionBusyId(deleteTarget.id)
      await onDeleteUser(deleteTarget.id)
    } finally {
      setActionBusyId(null)
      setDeleteTarget(null)
    }
  }

  return (
    <div className="space-y-4">
      {/* Action bar */}
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {t("users.count", { count: users.length })}
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="rounded-full"
            onClick={() => void onRefresh()}
            disabled={isLoading}
          >
            <RefreshCcw className={isLoading ? "size-3.5 animate-spin" : "size-3.5"} />
            {t("action.refresh")}
          </Button>
          <Button size="sm" className="rounded-full" onClick={() => setCreateOpen(true)}>
            <UserPlus className="size-3.5" />
            {t("users.addUser")}
          </Button>
        </div>
      </div>

      {/* Banners */}
      {error ? <Banner tone="danger" text={error} /> : null}
      {mutationNotice ? <Banner tone="neutral" text={mutationNotice} /> : null}

      {/* User list */}
      {users.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border/70 bg-background/75 px-5 py-8 text-center text-sm text-muted-foreground">
          {t("users.noUsers")}
        </div>
      ) : (
        <div className="space-y-2">
          {users.map((user) => (
            <div
              key={user.id}
              className="flex items-center gap-3 rounded-xl border border-border/60 bg-background/80 px-3 py-2.5"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">{user.label}</span>
                  <Badge variant="secondary" className="shrink-0 rounded-full text-[10px]">
                    {user.flow ?? "xtls-rprx-vision"}
                  </Badge>
                  {user.shareLink ? (
                    <span className="size-1.5 shrink-0 rounded-full bg-green-500" title="Ready" />
                  ) : (
                    <span className="size-1.5 shrink-0 rounded-full bg-muted-foreground/40" title="N/A" />
                  )}
                </div>
                <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="truncate font-mono">{user.id}</span>
                  {(() => {
                    const tr = trafficResponse?.users.find((u) => u.email === user.label)
                    if (!tr) return null
                    return (
                      <span className="shrink-0">
                        ↑{formatBytes(tr.uplink)} ↓{formatBytes(tr.downlink)}
                      </span>
                    )
                  })()}
                </div>
                <p className="mt-0.5 truncate text-xs text-muted-foreground/60">
                  {user.note || t("users.noNote")}
                </p>
              </div>

              <div className="flex shrink-0 gap-1">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      onClick={() => setEditingUser({ id: user.id, label: user.label, note: user.note ?? "" })}
                    >
                      <Pencil className="size-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("users.editLabel")}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon-xs" onClick={() => void handleCopyLink(user)} disabled={!user.shareLink}>
                      <Copy className="size-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("users.copyLink")}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon-xs" onClick={() => setSelectedUser(user)} disabled={!user.shareLink}>
                      <QrCode className="size-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("users.showQr")}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      className="text-destructive hover:text-destructive"
                      onClick={() => setDeleteTarget(user)}
                      disabled={actionBusyId === user.id}
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t("users.deleteUser")}</TooltipContent>
                </Tooltip>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Config path footer */}
      {configPath ? (
        <p className="text-xs text-muted-foreground">
          Config: <span className="font-mono">{configPath}</span>
        </p>
      ) : null}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="border-border/70 bg-background sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-heading text-xl">{t("users.createTitle")}</DialogTitle>
            <DialogDescription>{t("users.createDesc")}</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="user-label">{t("users.label")}</Label>
              <Input
                id="user-label"
                value={label}
                onChange={(event) => setLabel(event.currentTarget.value)}
                placeholder="friend-6"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-note">{t("users.note")}</Label>
              <Textarea
                id="user-note"
                value={note}
                onChange={(event) => setNote(event.currentTarget.value)}
                placeholder={t("users.notePlaceholder")}
                rows={3}
              />
            </div>
            {formError ? <Banner tone="danger" text={formError} /> : null}
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={submitBusy}>
                {t("users.cancel")}
              </Button>
              <Button onClick={() => void handleCreateUser()} disabled={submitBusy}>
                {submitBusy ? t("users.creating") : t("users.create")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* QR dialog */}
      <Dialog open={Boolean(selectedUser)} onOpenChange={(open) => !open && setSelectedUser(null)}>
        <DialogContent className="border-border/70 bg-background sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-heading text-xl">
              {selectedUser?.label ?? t("users.shareDesc")}
            </DialogTitle>
            <DialogDescription>{t("users.shareDesc")}</DialogDescription>
          </DialogHeader>

          {selectedUser?.shareLink ? (
            <div className="space-y-4">
              <div ref={qrRef} className="flex justify-center rounded-xl border border-border/60 bg-white p-4">
                <QRCode value={selectedUser.shareLink} size={200} />
              </div>
              <div className="break-all rounded-xl border border-border/60 bg-background/80 p-3 font-mono text-xs leading-5 text-muted-foreground">
                {selectedUser.shareLink}
              </div>
              <div className="flex justify-end gap-2">
                <Button size="sm" variant="outline" onClick={() => void handleCopyQr()}>
                  <ClipboardCopy className="size-3.5" />
                  {t("users.copyQr")}
                </Button>
                <Button size="sm" onClick={() => void handleCopyLink(selectedUser)}>
                  <Copy className="size-3.5" />
                  {t("users.copyLinkBtn")}
                </Button>
              </div>
            </div>
          ) : (
            <Banner tone="danger" text={t("users.linkUnavailable")} />
          )}
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={Boolean(editingUser)} onOpenChange={(open) => !open && setEditingUser(null)}>
        <DialogContent className="border-border/70 bg-background sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-heading text-xl">{t("users.editLabel")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-label">{t("users.label")}</Label>
              <Input
                id="edit-label"
                value={editingUser?.label ?? ""}
                onChange={(e) => setEditingUser((prev) => prev ? { ...prev, label: e.currentTarget.value } : null)}
                onKeyDown={(e) => { if (e.key === "Enter") void saveEdit() }}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-note">{t("users.note")}</Label>
              <Textarea
                id="edit-note"
                value={editingUser?.note ?? ""}
                onChange={(e) => setEditingUser((prev) => prev ? { ...prev, note: e.currentTarget.value } : null)}
                placeholder={t("users.notePlaceholder")}
                rows={2}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setEditingUser(null)}>
                {t("users.cancel")}
              </Button>
              <Button onClick={() => void saveEdit()}>
                {t("users.save")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="border-border/70 bg-background sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-heading text-xl">{t("users.deleteUser")}</DialogTitle>
            <DialogDescription>
              {t("users.confirmDelete", { label: deleteTarget?.label ?? "" })}
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={actionBusyId === deleteTarget?.id}>
              {t("users.cancel")}
            </Button>
            <Button variant="destructive" onClick={() => void confirmDelete()} disabled={actionBusyId === deleteTarget?.id}>
              {actionBusyId === deleteTarget?.id ? t("users.deleting") : t("users.deleteUser")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
