import React, { useState, useEffect, useRef } from "react";

/**
 * Displays a number with a typewriter animation (character-by-character).
 * @param {number} value - The number to display
 * @param {string} [suffix=""] - Optional suffix (e.g. "+") appended after the number
 * @param {number} [charDelayMs=80] - Delay between each character in ms
 * @param {string} [className] - Optional class for the wrapper span
 */
const TypewriterNumber = ({ value, suffix = "", charDelayMs = 80, className = "" }) => {
  const [displayed, setDisplayed] = useState("");
  const [isComplete, setIsComplete] = useState(false);
  const timeoutRef = useRef(null);
  const fullText = `${Number(value).toLocaleString()}${suffix}`;

  useEffect(() => {
    setDisplayed("");
    setIsComplete(false);

    if (fullText.length === 0) {
      setIsComplete(true);
      return () => {};
    }

    let index = 0;
    const tick = () => {
      if (index <= fullText.length) {
        setDisplayed(fullText.slice(0, index));
        if (index === fullText.length) {
          setIsComplete(true);
          return;
        }
        index += 1;
        timeoutRef.current = setTimeout(tick, charDelayMs);
      }
    };
    timeoutRef.current = setTimeout(tick, charDelayMs);

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [value, suffix, charDelayMs]); // fullText as dependency would change every render; we depend on value + suffix

  return (
    <span className={className}>
      {displayed}
      {!isComplete && <span className="typewriter-cursor" aria-hidden="true" />}
    </span>
  );
};

export default TypewriterNumber;
