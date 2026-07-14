"use client";

/**
 * i18n minimal FR / AR pour les pages d'authentification.
 *
 * Positionnement produit (marché marocain) : le choix de langue est offert dès
 * le login. Le reste de l'app reste en français pour l'instant ; ce module est
 * conçu pour s'étendre écran par écran (il suffit d'ajouter des clés).
 * L'arabe s'affiche en RTL (dir="rtl" posé par AuthShell).
 */

import * as React from "react";

export type Lang = "fr" | "ar";

const translations = {
  fr: {
    tagline: "Protégé par chiffrement Argon2id et double authentification.",

    // Login
    "login.title": "Se connecter",
    "login.desc": "Accédez à votre tableau de bord de sécurité.",
    "login.email": "E-mail",
    "login.continue": "Continuer",
    "login.password": "Mot de passe",
    "login.submit": "Se connecter",
    "login.forgot": "Mot de passe oublié ?",
    "login.biometric": "Utiliser Face ID / empreinte / clé de sécurité",
    "login.github": "Se connecter avec GitHub",
    "login.or": "ou",
    "login.changeEmail": "Changer d'e-mail",
    "login.noAccount": "Pas encore de compte ?",
    "login.create": "Créer un compte",
    "login.mfaTitle": "Vérification en deux étapes",
    "login.mfaDesc": "Confirmez votre identité pour terminer la connexion.",
    "login.restart": "← Recommencer",
    "login.badCredentials": "E-mail ou mot de passe incorrect.",
    "login.locked":
      "Trop de tentatives. Compte temporairement verrouillé, réessayez plus tard.",
    "login.genericError": "Une erreur est survenue.",
    "login.biometricCancelled": "Vérification biométrique annulée.",
    "login.biometricFailed": "La vérification biométrique a échoué.",

    // Signup
    "signup.title": "Créer un compte",
    "signup.desc": "Commencez à surveiller la sécurité de votre infrastructure.",
    "signup.confirm": "Confirmer le mot de passe",
    "signup.submit": "Créer mon compte",
    "signup.haveAccount": "Déjà un compte ?",
    "signup.signIn": "Se connecter",
    "signup.mismatch": "Les mots de passe ne correspondent pas.",
    "signup.rulesIncomplete":
      "Le mot de passe ne respecte pas encore toutes les règles.",
    "signup.emailTaken": "Un compte existe déjà avec cet e-mail.",
    "signup.created": "Compte créé. Connectez-vous pour accéder à la plateforme.",
    "rule.length": "Au moins 12 caractères",
    "rule.lower": "Une minuscule (a-z)",
    "rule.upper": "Une majuscule (A-Z)",
    "rule.digit": "Un chiffre (0-9)",
    "rule.special": "Un caractère spécial (!@#$%…)",

    // Mot de passe oublié
    "forgot.title": "Réinitialiser le mot de passe",
    "forgot.desc":
      "Entrez votre e-mail : si un compte existe, vous recevrez un lien de réinitialisation.",
    "forgot.submit": "Envoyer le lien",
    "forgot.sent":
      "Si un compte existe pour cet e-mail, un lien de réinitialisation sera envoyé.",
    "forgot.back": "Retour à la connexion",
  },
  ar: {
    tagline: "محميّ بتشفير Argon2id والمصادقة الثنائية.",

    // Login
    "login.title": "تسجيل الدخول",
    "login.desc": "ادخل إلى لوحة مراقبة الأمان الخاصة بك.",
    "login.email": "البريد الإلكتروني",
    "login.continue": "متابعة",
    "login.password": "كلمة المرور",
    "login.submit": "تسجيل الدخول",
    "login.forgot": "نسيت كلمة المرور؟",
    "login.biometric": "استخدام Face ID / البصمة / مفتاح الأمان",
    "login.github": "تسجيل الدخول عبر GitHub",
    "login.or": "أو",
    "login.changeEmail": "تغيير البريد الإلكتروني",
    "login.noAccount": "ليس لديك حساب؟",
    "login.create": "إنشاء حساب",
    "login.mfaTitle": "التحقق بخطوتين",
    "login.mfaDesc": "أكّد هويتك لإتمام تسجيل الدخول.",
    "login.restart": "→ البدء من جديد",
    "login.badCredentials": "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
    "login.locked": "محاولات كثيرة جداً. الحساب مقفل مؤقتاً، حاول لاحقاً.",
    "login.genericError": "حدث خطأ ما.",
    "login.biometricCancelled": "تم إلغاء التحقق البيومتري.",
    "login.biometricFailed": "فشل التحقق البيومتري.",

    // Signup
    "signup.title": "إنشاء حساب",
    "signup.desc": "ابدأ في مراقبة أمان بنيتك التحتية.",
    "signup.confirm": "تأكيد كلمة المرور",
    "signup.submit": "إنشاء حسابي",
    "signup.haveAccount": "لديك حساب بالفعل؟",
    "signup.signIn": "تسجيل الدخول",
    "signup.mismatch": "كلمتا المرور غير متطابقتين.",
    "signup.rulesIncomplete": "كلمة المرور لا تستوفي كل الشروط بعد.",
    "signup.emailTaken": "يوجد حساب بهذا البريد الإلكتروني بالفعل.",
    "signup.created": "تم إنشاء الحساب. سجّل الدخول للوصول إلى المنصة.",
    "rule.length": "12 حرفاً على الأقل",
    "rule.lower": "حرف صغير (a-z)",
    "rule.upper": "حرف كبير (A-Z)",
    "rule.digit": "رقم (0-9)",
    "rule.special": "رمز خاص (!@#$%…)",

    // Mot de passe oublié
    "forgot.title": "إعادة تعيين كلمة المرور",
    "forgot.desc":
      "أدخل بريدك الإلكتروني: إذا كان هناك حساب، فستتلقى رابط إعادة التعيين.",
    "forgot.submit": "إرسال الرابط",
    "forgot.sent": "إذا كان هناك حساب بهذا البريد، فسيتم إرسال رابط إعادة التعيين.",
    "forgot.back": "العودة إلى تسجيل الدخول",
  },
} as const;

export type TranslationKey = keyof (typeof translations)["fr"];

const STORAGE_KEY = "iacg-lang";

interface LangContextValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: TranslationKey) => string;
  dir: "ltr" | "rtl";
}

const LangContext = React.createContext<LangContextValue | null>(null);

export function LangProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = React.useState<Lang>("fr");

  // La préférence survit au rechargement (lue après l'hydratation pour ne pas
  // créer d'écart serveur/client).
  React.useEffect(() => {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "fr" || saved === "ar") setLangState(saved);
  }, []);

  const setLang = React.useCallback((next: Lang) => {
    setLangState(next);
    window.localStorage.setItem(STORAGE_KEY, next);
  }, []);

  const t = React.useCallback(
    (key: TranslationKey) => translations[lang][key] ?? translations.fr[key],
    [lang]
  );

  const value = React.useMemo<LangContextValue>(
    () => ({ lang, setLang, t, dir: lang === "ar" ? "rtl" : "ltr" }),
    [lang, setLang, t]
  );

  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}

export function useLang(): LangContextValue {
  const ctx = React.useContext(LangContext);
  if (ctx === null) throw new Error("useLang doit être utilisé dans <LangProvider>.");
  return ctx;
}
