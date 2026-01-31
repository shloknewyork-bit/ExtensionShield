import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import authService from "../services/authService";

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSignInModalOpen, setIsSignInModalOpen] = useState(false);
  const [authError, setAuthError] = useState(null);

  // Check for existing session on mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const storedUser = authService.getCurrentUser();
        if (storedUser) {
          setUser(storedUser);
        }
      } catch (error) {
        console.error("Auth check failed:", error);
      } finally {
        setIsLoading(false);
      }
    };
    checkAuth();
  }, []);

  const signInWithGoogle = useCallback(async () => {
    setAuthError(null);
    setIsLoading(true);
    try {
      const user = await authService.signInWithGoogle();
      setUser(user);
      setIsSignInModalOpen(false);
      return user;
    } catch (error) {
      setAuthError(error.message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signInWithGitHub = useCallback(async () => {
    setAuthError(null);
    setIsLoading(true);
    try {
      const user = await authService.signInWithGitHub();
      setUser(user);
      setIsSignInModalOpen(false);
      return user;
    } catch (error) {
      setAuthError(error.message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signInWithEmail = useCallback(async (email, password) => {
    setAuthError(null);
    setIsLoading(true);
    try {
      const user = await authService.signInWithEmail(email, password);
      setUser(user);
      setIsSignInModalOpen(false);
      return user;
    } catch (error) {
      setAuthError(error.message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signUpWithEmail = useCallback(async (email, password, name) => {
    setAuthError(null);
    setIsLoading(true);
    try {
      const user = await authService.signUpWithEmail(email, password, name);
      setUser(user);
      setIsSignInModalOpen(false);
      return user;
    } catch (error) {
      setAuthError(error.message);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    setIsLoading(true);
    try {
      await authService.signOut();
      setUser(null);
    } catch (error) {
      console.error("Sign out failed:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const openSignInModal = useCallback(() => {
    setAuthError(null);
    setIsSignInModalOpen(true);
  }, []);

  const closeSignInModal = useCallback(() => {
    setAuthError(null);
    setIsSignInModalOpen(false);
  }, []);

  const clearError = useCallback(() => {
    setAuthError(null);
  }, []);

  const value = {
    user,
    isLoading,
    isAuthenticated: !!user,
    authError,
    isSignInModalOpen,
    signInWithGoogle,
    signInWithGitHub,
    signInWithEmail,
    signUpWithEmail,
    signOut,
    openSignInModal,
    closeSignInModal,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;





