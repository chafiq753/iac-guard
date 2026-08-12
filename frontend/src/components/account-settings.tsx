"use client";

import * as React from "react";
import { KeyRound, Loader2, User as UserIcon } from "lucide-react";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, authApi, type UserOut } from "@/lib/auth-api";

/** Onglet « Compte » des Settings : nom, e-mail, mot de passe. */
export function AccountSettings() {
  const [user, setUser] = React.useState<UserOut | null>(null);
  const [name, setName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [savingProfile, setSavingProfile] = React.useState(false);

  const [currentPassword, setCurrentPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [changingPassword, setChangingPassword] = React.useState(false);

  React.useEffect(() => {
    void authApi.me().then((u) => {
      setUser(u);
      setName(u.name ?? "");
      setEmail(u.email);
    });
  }, []);

  async function onSaveProfile(e: React.FormEvent) {
    e.preventDefault();
    setSavingProfile(true);
    try {
      const updated = await authApi.updateProfile({
        name: name.trim(),
        email: email.trim(),
      });
      setUser(updated);
      toast.success("Profil mis à jour.");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Échec de la mise à jour.");
    } finally {
      setSavingProfile(false);
    }
  }

  async function onChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setChangingPassword(true);
    try {
      await authApi.changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      toast.success("Mot de passe changé.");
    } catch (err) {
      toast.error(
        err instanceof ApiError ? err.message : "Échec du changement de mot de passe."
      );
    } finally {
      setChangingPassword(false);
    }
  }

  if (user === null) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="[--card-spacing:--spacing(6)]">
        <form onSubmit={onSaveProfile}>
          <CardHeader className="gap-1.5">
            <CardTitle className="flex items-center gap-2">
              <UserIcon className="size-4" />
              Profil
            </CardTitle>
            <CardDescription>Votre nom et votre e-mail de connexion.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5 pt-2">
            <div className="grid gap-2">
              <Label htmlFor="name">Nom</Label>
              <Input
                id="name"
                placeholder="ex. Chafiq Boulghallat"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="max-w-md"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="email">E-mail</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="max-w-md"
              />
            </div>
          </CardContent>
          <CardFooter className="mt-6">
            <Button type="submit" disabled={savingProfile}>
              {savingProfile ? <Loader2 className="size-4 animate-spin" /> : null}
              Enregistrer
            </Button>
          </CardFooter>
        </form>
      </Card>

      <Card className="[--card-spacing:--spacing(6)]">
        <form onSubmit={onChangePassword}>
          <CardHeader className="gap-1.5">
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="size-4" />
              Mot de passe
            </CardTitle>
            <CardDescription>
              Changer votre mot de passe déconnecte tous vos autres appareils connectés.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5 pt-2">
            <div className="grid gap-2">
              <Label htmlFor="current-password">Mot de passe actuel</Label>
              <Input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="max-w-md"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="new-password">Nouveau mot de passe</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="max-w-md"
              />
              <p className="text-xs text-muted-foreground">
                12 caractères minimum, avec majuscule, minuscule, chiffre et
                caractère spécial.
              </p>
            </div>
          </CardContent>
          <CardFooter className="mt-6">
            <Button
              type="submit"
              disabled={changingPassword || !currentPassword || !newPassword}
            >
              {changingPassword ? <Loader2 className="size-4 animate-spin" /> : null}
              Changer le mot de passe
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
