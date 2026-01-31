import React, { useState } from "react";
import { Badge } from "../ui/badge";
import { ExternalLink } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "../ui/tooltip";
import "./CitationBadge.scss";

const CitationBadge = ({ citationId, citation, onCitationClick }) => {
  const [isHovered, setIsHovered] = useState(false);

  const handleClick = () => {
    if (citation?.source_url) {
      window.open(citation.source_url, "_blank", "noopener,noreferrer");
    }
    if (onCitationClick) {
      onCitationClick(citationId, citation);
    }
  };

  const tooltipContent = citation?.short_snippet || citation?.title || citationId;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="outline"
            className="citation-badge-component"
            onClick={handleClick}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
          >
            <span className="citation-id">{citationId}</span>
            <ExternalLink className={`citation-icon ${isHovered ? "hovered" : ""}`} />
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="citation-tooltip">
          <div className="tooltip-content">
            {citation?.title && (
              <div className="tooltip-title">{citation.title}</div>
            )}
            {tooltipContent && (
              <div className="tooltip-snippet">{tooltipContent}</div>
            )}
            {citation?.source_url && (
              <div className="tooltip-url">
                <ExternalLink className="h-3 w-3" />
                {citation.source_url}
              </div>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
};

export default CitationBadge;









