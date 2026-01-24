import React from "react";
import "./ScanProgress.scss";

const ScanProgress = ({ currentStage, stages }) => {
  const defaultStages = [
    { id: "extracting", label: "Extracting", icon: "📦" },
    { id: "security_scan", label: "Security Scan", icon: "🔍" },
    { id: "building_evidence", label: "Building Evidence Index", icon: "📚" },
    { id: "applying_rules", label: "Applying Rulepacks", icon: "⚖️" },
    { id: "generating_report", label: "Generating Report", icon: "📄" },
  ];

  const stagesToShow = stages || defaultStages;
  const currentIndex = stagesToShow.findIndex((s) => s.id === currentStage);

  return (
    <div className="scan-progress">
      <div className="scan-progress-stages">
        {stagesToShow.map((stage, index) => {
          const isActive = index === currentIndex;
          const isCompleted = index < currentIndex;
          const isPending = index > currentIndex;

          return (
            <div
              key={stage.id}
              className={`scan-progress-stage ${
                isActive
                  ? "active"
                  : isCompleted
                  ? "completed"
                  : "pending"
              }`}
            >
              <div className="stage-icon">
                {isCompleted ? "✅" : isActive ? stage.icon : "⏳"}
              </div>
              <div className="stage-label">{stage.label}</div>
              {isActive && <div className="stage-pulse"></div>}
            </div>
          );
        })}
      </div>
      {currentIndex >= 0 && currentIndex < stagesToShow.length && (
        <div className="scan-progress-bar">
          <div
            className="scan-progress-fill"
            style={{
              width: `${((currentIndex + 1) / stagesToShow.length) * 100}%`,
            }}
          ></div>
        </div>
      )}
    </div>
  );
};

export default ScanProgress;

