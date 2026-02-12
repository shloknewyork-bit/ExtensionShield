import React, { useMemo } from "react";
import "./RainfallDroplets.scss";

const DEFAULT_COUNT = 18;
const DEFAULT_DURATION_MIN = 3.5;
const DEFAULT_DURATION_MAX = 5.9;
const DEFAULT_OPACITY_MIN = 0.4;
const DEFAULT_OPACITY_MAX = 0.85;

/**
 * Builds a stable droplet config so positions/delays don't change between renders.
 */
function buildDropletConfig(count, durationMin, durationMax, opacityMin, opacityMax) {
  return Array.from({ length: count }, (_, i) => ({
    id: i,
    left: 5 + (i * 5.5) % 90,
    delay: (i * 0.4) % 5,
    duration: durationMin + (i % 3) * ((durationMax - durationMin) / 3),
    size: 4 + (i % 3) * 2,
    opacity: opacityMin + (i % 4) * ((opacityMax - opacityMin) / 4),
  }));
}

/**
 * RainfallDroplets – reusable falling-droplets background animation.
 * Renders a layer of animated droplets falling from top to bottom.
 *
 * @param {Object} props
 * @param {number} [props.count=18] - Number of droplets
 * @param {string} [props.color] - CSS color for droplets (default: accent green)
 * @param {string} [props.className] - Extra class for the wrapper
 * @param {number} [props.zIndex=0] - z-index of the layer
 * @param {number} [props.durationMin=3.5] - Min animation duration (s)
 * @param {number} [props.durationMax=5.9] - Max animation duration (s)
 * @param {number} [props.opacityMin=0.4] - Min droplet opacity
 * @param {number} [props.opacityMax=0.85] - Max droplet opacity
 */
const RainfallDroplets = ({
  count = DEFAULT_COUNT,
  color,
  className = "",
  zIndex = 0,
  durationMin = DEFAULT_DURATION_MIN,
  durationMax = DEFAULT_DURATION_MAX,
  opacityMin = DEFAULT_OPACITY_MIN,
  opacityMax = DEFAULT_OPACITY_MAX,
}) => {
  const config = useMemo(
    () => buildDropletConfig(count, durationMin, durationMax, opacityMin, opacityMax),
    [count, durationMin, durationMax, opacityMin, opacityMax]
  );

  const wrapperStyle = {
    zIndex: Number(zIndex),
    ...(color ? { "--rainfall-droplet-color": color } : {}),
  };

  return (
    <div
      className={`rainfall-droplets ${className}`.trim()}
      style={wrapperStyle}
      aria-hidden
    >
      {config.map(({ id, left, delay, duration, size, opacity }) => (
        <span
          key={id}
          className="rainfall-droplets__droplet"
          style={{
            left: `${left}%`,
            animationDelay: `${delay}s`,
            animationDuration: `${duration}s`,
            width: size,
            height: size,
            opacity,
          }}
        />
      ))}
    </div>
  );
};

export default RainfallDroplets;
