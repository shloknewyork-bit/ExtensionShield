/**
 * DevHintRow – Centered hint below hero, above stats: "</> Building an extension? [Upload CRX/ZIP] for a private build scan."
 * Same pill click logic as UploadCtaPill (sign-in / upgrade / navigate to /scan/upload).
 */
import React, { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useUpgradeModal } from "../context/UpgradeModalContext";
import "./DevHintRow.scss";

const SCAN_UPLOAD_PATH = "/scan/upload";

function useIsPro() {
  return { isPro: false };
}

export default function DevHintRow() {
  const navigate = useNavigate();
  const { isAuthenticated, openSignInModal } = useAuth();
  const { openUpgradeModal } = useUpgradeModal();
  const { isPro } = useIsPro();

  const handlePillClick = useCallback(() => {
    if (!isAuthenticated) {
      try {
        sessionStorage.setItem("auth:returnTo", SCAN_UPLOAD_PATH);
      } catch (_) {}
      openSignInModal();
      return;
    }
    if (!isPro) {
      openUpgradeModal({ redirectOnClose: SCAN_UPLOAD_PATH });
      return;
    }
    navigate(SCAN_UPLOAD_PATH);
  }, [isAuthenticated, openSignInModal, isPro, navigate, openUpgradeModal]);

  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handlePillClick();
      }
    },
    [handlePillClick]
  );

  return (
    <p className="dev-hint-row" aria-label="Developer upload hint">
      <span className="dev-hint-row__code-chip" aria-hidden="true">
        {"</>"}
      </span>{" "}
      Building an extension?{" "}
      <button
        type="button"
        className="dev-hint-row__pill"
        onClick={handlePillClick}
        onKeyDown={handleKeyDown}
        aria-label="Upload CRX/ZIP for a private build scan"
        title="Upload CRX or ZIP for a private build scan (Pro)"
      >
        Upload CRX/ZIP
      </button>{" "}
      for a private build scan.
    </p>
  );
}
