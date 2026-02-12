import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import ShieldLogo from "./ShieldLogo";
import "./SignInModal.scss";

const SignInModal = () => {
  const {
    isSignInModalOpen,
    closeSignInModal,
    signInWithGoogle,
    signInWithEmail,
    signUpWithEmail,
    isLoading,
    authError,
    authSuccessMessage,
    clearError,
  } = useAuth();

  const [mode, setMode] = useState("signin"); // 'signin' or 'signup'
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [localError, setLocalError] = useState("");

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isSignInModalOpen) {
      setEmail("");
      setPassword("");
      setName("");
      setLocalError("");
      setMode("signin");
    }
  }, [isSignInModalOpen]);

  // Clear errors when switching modes
  useEffect(() => {
    setLocalError("");
    clearError();
  }, [mode, clearError]);

  const handleGoogleSignIn = async () => {
    try {
      await signInWithGoogle();
    } catch (error) {
      // console.error("Google sign-in failed:", error); // prod: no console
    }
  };

  const handleEmailSubmit = async (e) => {
    e.preventDefault();
    setLocalError("");

    if (!email.trim()) {
      setLocalError("Please enter your email");
      return;
    }

    if (!password) {
      setLocalError("Please enter your password");
      return;
    }

    try {
      if (mode === "signup") {
        await signUpWithEmail(email, password, name);
      } else {
        await signInWithEmail(email, password);
      }
    } catch (error) {
      setLocalError(error.message);
    }
  };

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      closeSignInModal();
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Escape") {
      closeSignInModal();
    }
  };

  useEffect(() => {
    if (isSignInModalOpen) {
      document.addEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = "";
    };
  }, [isSignInModalOpen]);

  if (!isSignInModalOpen) return null;

  const displayError = localError || authError;

  return (
    <div className="signin-modal-overlay" onClick={handleBackdropClick}>
      <div className="signin-modal">
        {/* Close button */}
        <button className="modal-close" onClick={closeSignInModal} aria-label="Close">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6L6 18M6 6l12 12" />
          </svg>
        </button>

        {/* Header */}
        <div className="modal-header">
          <div className="modal-logo">
            <ShieldLogo size={40} />
            <span className="logo-text">ExtensionShield</span>
          </div>
          <h2 className="modal-title">
            {mode === "signin" ? "Welcome back" : "Create your account"}
          </h2>
          <p className="modal-subtitle">
            {mode === "signin"
              ? "Sign in to access your scan history and saved reports"
              : "Start securing your browser extensions today"}
          </p>
        </div>

        {/* OAuth */}
        <div className="oauth-buttons">
          <button
            className="oauth-btn google"
            onClick={handleGoogleSignIn}
            disabled={isLoading}
          >
            <svg className="oauth-icon" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            <span>Continue with Google</span>
          </button>
        </div>

        {/* Divider */}
        <div className="divider">
          <span>Or sign in with email</span>
        </div>

        {/* Email Form */}
        <form className="email-form" onSubmit={handleEmailSubmit}>
          {mode === "signup" && (
            <div className="form-field">
              <label htmlFor="name">Full Name</label>
              <input
                type="text"
                id="name"
                placeholder="John Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={isLoading}
                autoComplete="name"
              />
            </div>
          )}

          <div className="form-field">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isLoading}
              autoComplete="email"
              required
            />
          </div>

          <div className="form-field">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              placeholder={mode === "signup" ? "Min. 8 characters" : "••••••••"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
              autoComplete={mode === "signup" ? "new-password" : "current-password"}
              required
            />
          </div>

          {authSuccessMessage && (
            <div className="success-message" role="status">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
              <span>{authSuccessMessage}</span>
            </div>
          )}
          {displayError && (
            <div className="error-message">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
              <span>{displayError}</span>
            </div>
          )}

          <button type="submit" className="submit-btn" disabled={isLoading}>
            {isLoading ? (
              <span className="loading-spinner" />
            ) : mode === "signin" ? (
              "Sign In"
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        {/* Mode Toggle */}
        <div className="mode-toggle">
          {mode === "signin" ? (
            <p>
              Don't have an account?{" "}
              <button onClick={() => setMode("signup")} disabled={isLoading}>
                Sign up
              </button>
            </p>
          ) : (
            <p>
              Already have an account?{" "}
              <button onClick={() => setMode("signin")} disabled={isLoading}>
                Sign in
              </button>
            </p>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <p>
            By signing in, you agree to our{" "}
            <a href="#terms">Terms of Service</a> and{" "}
            <a href="#privacy">Privacy Policy</a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default SignInModal;

