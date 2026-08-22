"use client";

import * as React from "react";
import {
  Fingerprint,
  FolderGit2,
  Loader2,
  Mail,
  MoreHorizontal,
  Plus,
  Power,
  Send,
} from "lucide-react";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { ApiError } from "@/lib/auth-api";
import { useAuth } from "@/components/auth-provider";
import {
  adminApi,
  GLOBAL_ACCESS_ROLES,
  ROLES,
  ROLE_LABELS,
  STATUS_LABELS,
  type AdminUser,
} from "@/lib/admin-api";
import { platformApi, type ProjectOut } from "@/lib/platform-api";

const LAST_ADMIN_HINT =
  "Dernier administrateur actif : le rétrograder ou le désactiver fermerait l'accès à l'administration.";

function statusBadgeClass(status: string): string {
  if (status === "active") {
    return "border-emerald-600/30 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300";
  }
  if (status === "pending_invitation") {
    return "border-amber-600/30 bg-amber-500/12 text-amber-700 dark:text-amber-300";
  }
  return "border-muted-foreground/30 bg-muted text-muted-foreground";
}

function formatDate(iso: string | null): string {
  if (!iso) return "Jamais";
  return new Date(iso).toLocaleDateString("fr-FR", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

// --------------------------------------------------------------------------- #
// Modale d'invitation
// --------------------------------------------------------------------------- #

/** Monté uniquement à l'ouverture : l'état repart neuf à chaque invitation,
    sans effet de remise à zéro. */
function InviteUserDialog({
  onOpenChange,
  onInvited,
}: {
  onOpenChange: (open: boolean) => void;
  onInvited: () => void;
}) {
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<string>("viewer");
  const [submitting, setSubmitting] = React.useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await adminApi.invite(email.trim(), role);
      toast.success(`Invitation envoyée à ${email.trim()}.`);
      onOpenChange(false);
      onInvited();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible d'envoyer l'invitation."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>Inviter un utilisateur</DialogTitle>
            <DialogDescription>
              Un lien d&apos;activation lui sera envoyé par e-mail. Il choisira
              son mot de passe lui-même — vous n&apos;en définissez aucun.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="invite-email">Adresse e-mail</Label>
              <Input
                id="invite-email"
                type="email"
                required
                autoComplete="off"
                placeholder="collegue@entreprise.ma"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="invite-role">Rôle</Label>
              <Select value={role} onValueChange={(v) => setRole(v ?? "viewer")}>
                <SelectTrigger id="invite-role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {ROLE_LABELS[r]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {GLOBAL_ACCESS_ROLES.includes(role)
                  ? "Ce rôle donne accès à tous les projets de l'organisation."
                  : "Ce rôle ne voit aucun projet tant que vous ne lui en attribuez pas."}
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Annuler
            </Button>
            <Button type="submit" disabled={submitting || !email.trim()}>
              {submitting ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Send className="size-4" />
              )}
              Envoyer l&apos;invitation
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// --------------------------------------------------------------------------- #
// Modale d'accès aux projets
// --------------------------------------------------------------------------- #

/** Monté uniquement quand un utilisateur est sélectionné : ses accès sont
    chargés au montage, sans effet de synchronisation sur un prop nullable. */
function ProjectAccessDialog({
  user,
  projects,
  onOpenChange,
  onSaved,
}: {
  user: AdminUser;
  projects: ProjectOut[];
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const userId = user.id;
  React.useEffect(() => {
    adminApi
      .getProjectAccess(userId)
      .then((items) => setSelected(new Set(items.map((p) => p.id))))
      .catch((err) =>
        toast.error(errorMessage(err, "Impossible de charger les accès."))
      )
      .finally(() => setLoading(false));
  }, [userId]);

  async function save() {
    setSaving(true);
    try {
      await adminApi.setProjectAccess(user.id, [...selected]);
      toast.success("Accès aux projets mis à jour.");
      onOpenChange(false);
      onSaved();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible d'enregistrer les accès."));
    } finally {
      setSaving(false);
    }
  }

  const hasGlobalAccess = GLOBAL_ACCESS_ROLES.includes(user.role);

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Accès aux projets</DialogTitle>
          <DialogDescription>{user.email}</DialogDescription>
        </DialogHeader>

        {hasGlobalAccess ? (
          <p className="py-4 text-sm text-muted-foreground">
            Le rôle « {ROLE_LABELS[user.role]} » donne déjà accès à tous les
            projets de l&apos;organisation. Pour restreindre son périmètre,
            changez d&apos;abord son rôle.
          </p>
        ) : loading ? (
          <div className="space-y-2 py-4">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : projects.length === 0 ? (
          <p className="py-4 text-sm text-muted-foreground">
            Aucun projet n&apos;existe encore dans cette organisation.
          </p>
        ) : (
          <div className="max-h-72 space-y-1 overflow-y-auto py-2">
            {projects.map((project) => {
              const checked = selected.has(project.id);
              return (
                <label
                  key={project.id}
                  className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-2 hover:bg-muted/60"
                >
                  <input
                    type="checkbox"
                    className="size-4 accent-primary"
                    checked={checked}
                    onChange={(e) => {
                      const next = new Set(selected);
                      if (e.target.checked) next.add(project.id);
                      else next.delete(project.id);
                      setSelected(next);
                    }}
                  />
                  <FolderGit2 className="size-4 shrink-0 text-muted-foreground" />
                  <span className="truncate text-sm">{project.name}</span>
                </label>
              );
            })}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {hasGlobalAccess ? "Fermer" : "Annuler"}
          </Button>
          {!hasGlobalAccess && (
            <Button onClick={save} disabled={saving || loading}>
              {saving && <Loader2 className="size-4 animate-spin" />}
              Enregistrer
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// --------------------------------------------------------------------------- #
// Tableau des comptes
// --------------------------------------------------------------------------- #

export function UsersManager() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = React.useState<AdminUser[] | null>(null);
  const [projects, setProjects] = React.useState<ProjectOut[]>([]);
  const [inviteOpen, setInviteOpen] = React.useState(false);
  const [accessUser, setAccessUser] = React.useState<AdminUser | null>(null);
  const [busyId, setBusyId] = React.useState<number | null>(null);

  const load = React.useCallback(
    () =>
      adminApi
        .listUsers()
        .then((page) => setUsers(page.items))
        .catch((err) => {
          toast.error(errorMessage(err, "Impossible de charger les comptes."));
          setUsers([]);
        }),
    []
  );

  React.useEffect(() => {
    void load();
    void platformApi
      .listProjects()
      .then(setProjects)
      .catch(() => setProjects([]));
  }, [load]);

  async function changeRole(user: AdminUser, role: string) {
    if (role === user.role) return;
    setBusyId(user.id);
    try {
      await adminApi.changeRole(user.id, role);
      toast.success(`${user.email} est désormais ${ROLE_LABELS[role]}.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de changer le rôle."));
    } finally {
      setBusyId(null);
    }
  }

  async function toggleStatus(user: AdminUser) {
    const disabling = user.status === "active";
    setBusyId(user.id);
    try {
      await adminApi.changeStatus(user.id, !disabling);
      toast.success(disabling ? "Compte désactivé." : "Compte réactivé.");
      await load();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de changer le statut."));
    } finally {
      setBusyId(null);
    }
  }

  async function resetWebauthn(user: AdminUser) {
    setBusyId(user.id);
    try {
      await adminApi.resetWebauthn(user.id);
      toast.success(
        `Biométrie réinitialisée : ${user.email} devra ré-enrôler un appareil.`
      );
      await load();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de réinitialiser la biométrie."));
    } finally {
      setBusyId(null);
    }
  }

  async function resendInvitation(user: AdminUser) {
    setBusyId(user.id);
    try {
      await adminApi.invite(user.email, user.role);
      toast.success(`Invitation renvoyée à ${user.email}.`);
      await load();
    } catch (err) {
      toast.error(errorMessage(err, "Impossible de renvoyer l'invitation."));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="grid gap-1">
            <CardTitle>Comptes</CardTitle>
            <CardDescription>
              Invitez des collègues, définissez leur rôle et leur périmètre.
            </CardDescription>
          </div>
          <Button onClick={() => setInviteOpen(true)}>
            <Plus className="size-4" />
            Inviter
          </Button>
        </div>
      </CardHeader>

      <CardContent>
        {users === null ? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Utilisateur</TableHead>
                  <TableHead>Rôle</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead>Dernière connexion</TableHead>
                  <TableHead>Projets</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => {
                  const isSelf = user.id === currentUser?.id;
                  const locked = user.is_last_active_admin;
                  const disabled = user.status === "disabled";
                  const pending = user.status === "pending_invitation";
                  const busy = busyId === user.id;

                  return (
                    <TableRow
                      key={user.id}
                      className={cn(disabled && "opacity-55")}
                    >
                      <TableCell>
                        <div className="flex min-w-0 flex-col">
                          <span className="truncate font-medium">
                            {user.name ?? user.email}
                            {isSelf && (
                              <span className="ml-1.5 text-xs font-normal text-muted-foreground">
                                (vous)
                              </span>
                            )}
                          </span>
                          {user.name && (
                            <span className="truncate text-xs text-muted-foreground">
                              {user.email}
                            </span>
                          )}
                        </div>
                      </TableCell>

                      <TableCell>
                        {locked ? (
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <span className="inline-block cursor-not-allowed">
                                  <Badge variant="outline">
                                    {ROLE_LABELS[user.role] ?? user.role}
                                  </Badge>
                                </span>
                              }
                            />
                            <TooltipContent>{LAST_ADMIN_HINT}</TooltipContent>
                          </Tooltip>
                        ) : (
                          <Select
                            value={user.role}
                            onValueChange={(role) =>
                              role && void changeRole(user, role)
                            }
                            disabled={busy}
                          >
                            <SelectTrigger size="sm" className="w-44">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ROLES.map((r) => (
                                <SelectItem key={r} value={r}>
                                  {ROLE_LABELS[r]}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      </TableCell>

                      <TableCell>
                        <Badge
                          variant="outline"
                          className={statusBadgeClass(user.status)}
                        >
                          {STATUS_LABELS[user.status] ?? user.status}
                        </Badge>
                      </TableCell>

                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(user.last_login_at)}
                      </TableCell>

                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs"
                          onClick={() => setAccessUser(user)}
                        >
                          {GLOBAL_ACCESS_ROLES.includes(user.role)
                            ? "Tous"
                            : "Gérer"}
                        </Button>
                      </TableCell>

                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger
                            render={
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-8"
                                disabled={busy}
                              >
                                {busy ? (
                                  <Loader2 className="size-4 animate-spin" />
                                ) : (
                                  <MoreHorizontal className="size-4" />
                                )}
                              </Button>
                            }
                          />
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuSeparator />

                            {pending && (
                              <DropdownMenuItem
                                onClick={() => void resendInvitation(user)}
                              >
                                <Mail className="size-4" />
                                Renvoyer l&apos;invitation
                              </DropdownMenuItem>
                            )}

                            <DropdownMenuItem
                              onClick={() => setAccessUser(user)}
                            >
                              <FolderGit2 className="size-4" />
                              Accès aux projets
                            </DropdownMenuItem>

                            <DropdownMenuItem
                              onClick={() => void resetWebauthn(user)}
                            >
                              <Fingerprint className="size-4" />
                              Réinitialiser la biométrie
                            </DropdownMenuItem>

                            <DropdownMenuSeparator />

                            <DropdownMenuItem
                              disabled={locked || (isSelf && !disabled)}
                              onClick={() => void toggleStatus(user)}
                              className={cn(
                                !disabled && "text-destructive focus:text-destructive"
                              )}
                            >
                              <Power className="size-4" />
                              {disabled ? "Réactiver le compte" : "Désactiver le compte"}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      {inviteOpen && (
        <InviteUserDialog onOpenChange={setInviteOpen} onInvited={load} />
      )}
      {accessUser !== null && (
        <ProjectAccessDialog
          user={accessUser}
          projects={projects}
          onOpenChange={(open) => !open && setAccessUser(null)}
          onSaved={load}
        />
      )}
    </Card>
  );
}
