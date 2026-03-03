/**
 * Feature flags derived from VITE_ environment variables.
 *
 * In OSS mode (default), auth and cloud features are disabled.
 * Set VITE_AUTH_ENABLED=true and provide Supabase credentials to enable.
 */

const _bool = (key, fallback = false) => {
  const v = import.meta.env[key];
  if (v === undefined || v === "") return fallback;
  return v === "true" || v === "1";
};

export const AUTH_ENABLED =
  _bool("VITE_AUTH_ENABLED") &&
  !!import.meta.env.VITE_SUPABASE_URL &&
  !!import.meta.env.VITE_SUPABASE_ANON_KEY;

export const HISTORY_ENABLED = AUTH_ENABLED;
export const CLOUD_MODE = AUTH_ENABLED;
