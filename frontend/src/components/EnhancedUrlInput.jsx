import React, { useRef } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Search, Upload } from "lucide-react";
import "./EnhancedUrlInput.scss";

/**
 * Enhanced URL Input Component with File Upload Support
 */
const EnhancedUrlInput = ({
  value,
  onChange,
  onScan,
  onFileUpload,
  isScanning = false,
  scanDisabled = false,
  scanDisabledTooltip = "",
  scanButtonLabel = "Scan Extension",
  className = "",
  ...props
}) => {
  const fileInputRef = useRef(null);

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && value.trim() && !isScanning) {
      onScan();
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file && onFileUpload) {
      onFileUpload(file);
    }
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className={`enhanced-url-input ${className}`}>
      <div className="input-container">
        {/* URL Input Section */}
        <div className="url-field-container">
          <label htmlFor="extension-url" className="input-label">
            Chrome Web Store URL
          </label>
          <Input
            id="extension-url"
            placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyPress={handleKeyPress}
            className="url-input-field"
          />
        </div>

        {/* Scan Button */}
        <div
          className={`scan-button-wrapper ${scanDisabled ? "is-disabled" : ""}`}
          title={scanDisabled ? scanDisabledTooltip : ""}
        >
          <Button
            onClick={onScan}
            disabled={isScanning || !value.trim() || scanDisabled}
            className="scan-button"
            size="lg"
            aria-disabled={isScanning || !value.trim() || scanDisabled}
          >
            {isScanning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                {scanButtonLabel}
              </>
            )}
          </Button>
        </div>

        {/* File Upload Section */}
        {onFileUpload && (
          <div className="file-upload-section">
            <div className="divider-with-text">
              <div className="divider-line"></div>
              <span className="divider-text">OR</span>
              <div className="divider-line"></div>
            </div>
            
            <input
              ref={fileInputRef}
              type="file"
              accept=".crx,.zip"
              onChange={handleFileChange}
              className="hidden"
              disabled={isScanning}
            />
            
            <Button
              onClick={handleUploadClick}
              disabled={isScanning}
              variant="outline"
              className="upload-button"
              size="lg"
            >
              <Upload className="mr-2 h-4 w-4" />
              Upload CRX/ZIP File
            </Button>
          </div>
        )}
      </div>

      <p className="input-help-text">
        {onFileUpload
          ? "Paste a Chrome Web Store URL or upload a local extension file"
          : "Paste a Chrome Web Store URL to analyze the extension"
        }
      </p>
    </div>
  );
};

export default EnhancedUrlInput;