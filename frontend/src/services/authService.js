/**
 * Authentication Service (Supabase Auth)
 * Keeps the existing modal UI but replaces demo/mock auth with real Supabase Auth.
 */

import { supabase } from "./supabaseClient";
import { validateReturnTo } from "../utils/authUtils";

const checkSupabaseConfig = () => {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || "";
  const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || "";
  
  if (!supabaseUrl || !supabaseAnonKey || supabaseUrl.includes("placeholder")) {
    throw new Error(
      "Supabase is not configured. Please set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env file.\n\n" +
      "To find these values:\n" +
      "1. Go to https://app.supabase.com\n" +
      "2. Select your project\n" +
      "3. Click 'Settings' (gear icon) in the left sidebar\n" +
      "4. Click 'API' under Project Settings\n" +
      "5. Copy the 'Project URL' → this is your VITE_SUPABASE_URL\n" +
      "6. Copy the 'anon' or 'public' key → this is your VITE_SUPABASE_ANON_KEY\n\n" +
      "Create a .env file in the frontend/ directory with:\n" +
      "VITE_SUPABASE_URL=https://your-project-id.supabase.co\n" +
      "VITE_SUPABASE_ANON_KEY=your-anon-key-here"
    );
  }
};

const signInWithGoogle = async () => {
  checkSupabaseConfig();
  
  // Store the return URL: use existing (e.g. set by View report button) or current page
  // Use sessionStorage for tab-isolation (prevents cross-tab interference)
  // Validate to prevent open redirects and loops
  const existingReturnTo = sessionStorage.getItem("auth:returnTo");
  const returnTo = validateReturnTo(
    existingReturnTo || window.location.pathname + window.location.search
  );
  sessionStorage.setItem("auth:returnTo", returnTo);

  // Redirect to dedicated callback route (PKCE flow)
  const callbackUrl = `${window.location.origin}/auth/callback`;

  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: callbackUrl,
      queryParams: {
        access_type: 'offline',
        prompt: 'consent',
      },
    },
  });
  
  if (error) {
    // console.error("Google OAuth error:", error); // prod: no console
    sessionStorage.removeItem("auth:returnTo");
    throw new Error(error.message || "Google sign-in failed");
  }
  
  // OAuth will redirect, so we don't need to return anything
  // The redirect will happen automatically
};

const signInWithGitHub = async () => {
  checkSupabaseConfig();
  
  // Store the return URL: use existing (e.g. set by View report button) or current page
  const existingReturnTo = sessionStorage.getItem("auth:returnTo");
  const returnTo = validateReturnTo(
    existingReturnTo || window.location.pathname + window.location.search
  );
  sessionStorage.setItem("auth:returnTo", returnTo);

  // Redirect to dedicated callback route (PKCE flow)
  const callbackUrl = `${window.location.origin}/auth/callback`;

  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: callbackUrl,
    },
  });
  
  if (error) {
    // console.error("GitHub OAuth error:", error); // prod: no console
    sessionStorage.removeItem("auth:returnTo");
    throw new Error(error.message || "GitHub sign-in failed");
  }
  
  // OAuth will redirect, so we don't need to return anything
  // The redirect will happen automatically
};

const signInWithEmail = async (email, password) => {
  checkSupabaseConfig();
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    if (error.message.includes("Email not confirmed")) {
      throw new Error("Please check your email and click the confirmation link before signing in.");
    }
    throw new Error(error.message || "Invalid credentials");
  }
  return data.user;
};

/** Message shown when sign-up succeeds but email confirmation is required */
export const EMAIL_CONFIRM_REQUIRED_MESSAGE =
  "Please check your email to confirm your account before signing in.";

const signUpWithEmail = async (email, password, name) => {
  checkSupabaseConfig();
  const redirectTo =
    typeof window !== "undefined" ? `${window.location.origin}${window.location.pathname || ""}` : undefined;
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      ...(name ? { data: { full_name: name } } : {}),
      ...(redirectTo ? { emailRedirectTo: redirectTo } : {}),
    },
  });
  if (error) throw new Error(error.message || "Sign up failed");

  if (data.user && !data.session) {
    return { user: data.user, needsEmailConfirmation: true };
  }
  return { user: data.user, needsEmailConfirmation: false };
};

const signOut = async () => {
  const { error } = await supabase.auth.signOut();
  if (error) throw new Error(error.message || "Sign out failed");
};

const authService = {
  signInWithGoogle,
  signInWithGitHub,
  signInWithEmail,
  signUpWithEmail,
  signOut,
};

export default authService;





