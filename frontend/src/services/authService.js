/**
 * Authentication Service
 * Handles OAuth (Google, GitHub) and email/password authentication
 * 
 * NOTE: This is a frontend-only implementation for demo purposes.
 * In production, replace with actual backend API calls.
 */

const AUTH_STORAGE_KEY = "atlas_auth_user";
const AUTH_TOKEN_KEY = "atlas_auth_token";

// Google OAuth Configuration
// To use Google Sign-In, set up credentials at: https://console.cloud.google.com/apis/credentials
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || "";
const GITHUB_CLIENT_ID = import.meta.env.VITE_GITHUB_CLIENT_ID || "";

// Simulated delay to mimic API calls
const simulateDelay = (ms = 800) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Initialize Google Sign-In SDK
 */
const initGoogleAuth = () => {
  return new Promise((resolve, reject) => {
    // Check if already loaded
    if (window.google?.accounts?.id) {
      resolve(window.google.accounts.id);
      return;
    }

    // Load the Google Identity Services library
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.google?.accounts?.id) {
        resolve(window.google.accounts.id);
      } else {
        reject(new Error("Google Sign-In failed to load"));
      }
    };
    script.onerror = () => reject(new Error("Failed to load Google Sign-In SDK"));
    document.head.appendChild(script);
  });
};

/**
 * Parse JWT token to get user info
 */
const parseJwt = (token) => {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
};

/**
 * Store user data in localStorage
 */
const storeUser = (user, token = null) => {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user));
  if (token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
  }
};

/**
 * Clear stored auth data
 */
const clearStoredAuth = () => {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  localStorage.removeItem(AUTH_TOKEN_KEY);
};

/**
 * Get current authenticated user from storage
 */
const getCurrentUser = () => {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
};

/**
 * Get stored auth token
 */
const getAuthToken = () => {
  return localStorage.getItem(AUTH_TOKEN_KEY);
};

/**
 * Sign in with Google OAuth
 */
const signInWithGoogle = () => {
  return new Promise(async (resolve, reject) => {
    try {
      // If no client ID configured, use demo mode
      if (!GOOGLE_CLIENT_ID) {
        console.log("Google Client ID not configured. Using demo mode.");
        await simulateDelay(1200);
        
        const demoUser = {
          id: "google_demo_" + Date.now(),
          email: "demo.user@gmail.com",
          name: "Demo User",
          avatar: "https://lh3.googleusercontent.com/a/default-user=s96-c",
          provider: "google",
          createdAt: new Date().toISOString(),
        };
        
        storeUser(demoUser, "demo_google_token_" + Date.now());
        resolve(demoUser);
        return;
      }

      const googleAuth = await initGoogleAuth();
      
      googleAuth.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: (response) => {
          if (response.credential) {
            const payload = parseJwt(response.credential);
            if (payload) {
              const user = {
                id: payload.sub,
                email: payload.email,
                name: payload.name,
                avatar: payload.picture,
                provider: "google",
                createdAt: new Date().toISOString(),
              };
              storeUser(user, response.credential);
              resolve(user);
            } else {
              reject(new Error("Failed to parse Google credentials"));
            }
          } else {
            reject(new Error("Google sign-in was cancelled"));
          }
        },
        auto_select: false,
        cancel_on_tap_outside: true,
      });

      // Prompt for account selection
      googleAuth.prompt((notification) => {
        if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
          // Fall back to One Tap alternative or show error
          const reasonMap = {
            browser_not_supported: "Browser not supported",
            invalid_client: "Invalid Google Client ID",
            missing_client_id: "Google Client ID not configured",
            opt_out_or_no_session: "Please enable cookies for Google Sign-In",
            secure_http_required: "HTTPS required for Google Sign-In",
            suppressed_by_user: "Sign-in was cancelled",
            unregistered_origin: "This domain is not registered with Google",
          };
          const reason = notification.getNotDisplayedReason() || notification.getSkippedReason();
          reject(new Error(reasonMap[reason] || "Google Sign-In unavailable"));
        }
      });
    } catch (error) {
      reject(error);
    }
  });
};

/**
 * Sign in with GitHub OAuth
 */
const signInWithGitHub = async () => {
  // If no client ID configured, use demo mode
  if (!GITHUB_CLIENT_ID) {
    console.log("GitHub Client ID not configured. Using demo mode.");
    await simulateDelay(1200);
    
    const demoUser = {
      id: "github_demo_" + Date.now(),
      email: "demo.user@github.com",
      name: "Demo Developer",
      avatar: "https://avatars.githubusercontent.com/u/0?v=4",
      provider: "github",
      createdAt: new Date().toISOString(),
    };
    
    storeUser(demoUser, "demo_github_token_" + Date.now());
    return demoUser;
  }

  // In production, this would redirect to GitHub OAuth
  // and handle the callback with the authorization code
  const redirectUri = `${window.location.origin}/auth/github/callback`;
  const scope = "user:email read:user";
  
  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.set("client_id", GITHUB_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", scope);
  authUrl.searchParams.set("state", crypto.randomUUID());
  
  // For demo, we'll simulate the OAuth flow
  // In production, redirect to: window.location.href = authUrl.toString();
  await simulateDelay(1200);
  
  const demoUser = {
    id: "github_" + Date.now(),
    email: "user@github.com",
    name: "GitHub User",
    avatar: "https://avatars.githubusercontent.com/u/0?v=4",
    provider: "github",
    createdAt: new Date().toISOString(),
  };
  
  storeUser(demoUser, "github_demo_token_" + Date.now());
  return demoUser;
};

/**
 * Sign in with email and password
 */
const signInWithEmail = async (email, password) => {
  if (!email || !password) {
    throw new Error("Email and password are required");
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new Error("Invalid email format");
  }

  // In production, this would make an API call to your backend
  // For demo, we'll simulate authentication
  await simulateDelay(1000);

  // Demo: Accept any valid-looking credentials
  const user = {
    id: "email_" + Date.now(),
    email: email,
    name: email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, l => l.toUpperCase()),
    avatar: null,
    provider: "email",
    createdAt: new Date().toISOString(),
  };

  storeUser(user, "email_token_" + Date.now());
  return user;
};

/**
 * Sign up with email and password
 */
const signUpWithEmail = async (email, password, name) => {
  if (!email || !password) {
    throw new Error("Email and password are required");
  }

  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters");
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new Error("Invalid email format");
  }

  // In production, this would make an API call to your backend
  await simulateDelay(1200);

  const user = {
    id: "email_" + Date.now(),
    email: email,
    name: name || email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, l => l.toUpperCase()),
    avatar: null,
    provider: "email",
    createdAt: new Date().toISOString(),
  };

  storeUser(user, "email_token_" + Date.now());
  return user;
};

/**
 * Sign out the current user
 */
const signOut = async () => {
  // Clear any Google session
  if (window.google?.accounts?.id) {
    window.google.accounts.id.disableAutoSelect();
  }
  
  clearStoredAuth();
  await simulateDelay(300);
};

const authService = {
  getCurrentUser,
  getAuthToken,
  signInWithGoogle,
  signInWithGitHub,
  signInWithEmail,
  signUpWithEmail,
  signOut,
  initGoogleAuth,
};

export default authService;





