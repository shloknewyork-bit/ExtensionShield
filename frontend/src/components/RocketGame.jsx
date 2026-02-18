import React, { useEffect, useRef } from "react";
import { getRiskHex, getInfoHex } from "../utils/riskColorUtils";
import "./RocketGame.scss";

// Hoisted constants to avoid per-frame allocation
const TARGET_COLORS = ["#ff6b35", "#ffa500", "#ffd700", "#ff4444", "#ff8c00"];

/**
 * Rocket Game - Minimal Working Version
 */
const RocketGame = ({ 
  isActive = true, 
  onStatsUpdate,
}) => {
  const canvasRef = useRef(null);
  const rafRef = useRef(null);
  const keysRef = useRef(new Set());
  // Cache gradient so we don't re-create it every frame (include theme for light/dark)
  const bgCacheRef = useRef({ gradient: null, height: 0, isLight: null });
  const infoHexRef = useRef(null);

  const gameRef = useRef({
    startedAt: 0,
    lastTs: 0,
    lastUiUpdate: 0,
    lastShot: 0,
    gameOver: false,
    score: 0,
    rocket: { x: 100, y: 300, w: 30, h: 50, speed: 200 },
    bullets: [],
    targets: [],
    coins: [], // Coin particles for visual feedback
    nextTargetSpawn: 1,
  });

  // Setup canvas size - DO NOT TOUCH ROCKET POSITION AFTER INITIAL SETUP
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let isInitialized = false;

    const resize = () => {
      const parent = canvas.parentElement;
      if (!parent) return;
      
      const isFullscreen = parent.classList.contains('game-container-fullscreen') || 
                          parent.closest('.game-container-fullscreen');
      
      let w, h;
      if (isFullscreen) {
        w = window.innerWidth;
        h = window.innerHeight;
      } else {
        const rect = parent.getBoundingClientRect();
        w = Math.max(800, rect.width || 800);
        h = Math.max(600, rect.height || 600);
      }

      // Only update canvas dimensions - NEVER touch rocket position
      canvas.width = w;
      canvas.height = h;
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';

      // ONLY on first resize: set initial rocket position
      if (!isInitialized) {
        const rocket = gameRef.current.rocket;
        rocket.x = 100;
        rocket.y = h / 2;
        isInitialized = true;
      }
      // After initialization, NEVER modify rocket position here
      // The game loop will handle bounds checking
    };

    resize();
    
    if (isActive) {
      canvas.setAttribute('tabindex', '0');
      canvas.style.outline = 'none';
      canvas.style.cursor = 'crosshair';
      setTimeout(() => canvas.focus(), 100);
    }
    
    const handleClick = () => canvas.focus();
    canvas.addEventListener('click', handleClick);
    
    const ro = new ResizeObserver(resize);
    ro.observe(canvas.parentElement);
    window.addEventListener('resize', resize);
    
    return () => {
      canvas.removeEventListener('click', handleClick);
      ro.disconnect();
      window.removeEventListener('resize', resize);
    };
  }, [isActive]);

  // Keyboard input - robust key detection
  useEffect(() => {
    if (!isActive) return;

    const normalizeKey = (key, code) => {
      // Normalize key string
      const keyLower = key ? key.toLowerCase() : '';
      
      // Handle arrow keys - check both key and code
      if (keyLower === "arrowup" || code === "ArrowUp") return "arrowup";
      if (keyLower === "arrowdown" || code === "ArrowDown") return "arrowdown";
      if (keyLower === "arrowleft" || code === "ArrowLeft") return "arrowleft";
      if (keyLower === "arrowright" || code === "ArrowRight") return "arrowright";
      
      // Handle space
      if (keyLower === " " || keyLower === "space" || code === "Space") return " ";
      
      // Handle WASD
      if (keyLower === "w" || code === "KeyW") return "w";
      if (keyLower === "a" || code === "KeyA") return "a";
      if (keyLower === "s" || code === "KeyS") return "s";
      if (keyLower === "d" || code === "KeyD") return "d";
      
      return keyLower;
    };

    const gameKeys = new Set([" ", "arrowup", "arrowdown", "arrowleft", "arrowright", "w", "a", "s", "d", "enter"]);

    const onDown = (e) => {
      const key = normalizeKey(e.key, e.code);
      if (gameKeys.has(key)) {
        e.preventDefault();
        e.stopPropagation();
        keysRef.current.add(key);
      }
    };
    
    const onUp = (e) => {
      const key = normalizeKey(e.key, e.code);
      if (gameKeys.has(key)) {
        e.preventDefault();
        e.stopPropagation();
        keysRef.current.delete(key);
      }
    };

    // Add listeners with capture to catch events early
    window.addEventListener("keydown", onDown, { passive: false, capture: true });
    window.addEventListener("keyup", onUp, { passive: false, capture: true });
    
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.addEventListener("keydown", onDown, { passive: false });
      canvas.addEventListener("keyup", onUp, { passive: false });
    }
    
    return () => {
      window.removeEventListener("keydown", onDown, { capture: true });
      window.removeEventListener("keyup", onUp, { capture: true });
      if (canvas) {
        canvas.removeEventListener("keydown", onDown);
        canvas.removeEventListener("keyup", onUp);
      }
    };
  }, [isActive]);

  // Main game loop
  useEffect(() => {
    if (!isActive) return;

    const step = (ts) => {
      const canvas = canvasRef.current;
      const ctx = canvas?.getContext("2d");
      if (!canvas || !ctx) return;

      const g = gameRef.current;
      
      // Get ACTUAL canvas dimensions from the canvas element itself
      const w = canvas.width || canvas.clientWidth || 800;
      const h = canvas.height || canvas.clientHeight || 600;

      // Calculate deltaTime properly
      const dt = g.lastTs ? Math.min(0.033, (ts - g.lastTs) / 1000) : 0.016;
      g.lastTs = ts;

      const keys = keysRef.current;
      const rocket = g.rocket;
      
      if (!g.gameOver) {
        // Movement - direct and simple
        const moveAmount = rocket.speed * dt;
        
        // Y-axis movement (UP/DOWN)
        if (keys.has("arrowup") || keys.has("w")) {
          rocket.y = rocket.y - moveAmount;
        }
        if (keys.has("arrowdown") || keys.has("s")) {
          rocket.y = rocket.y + moveAmount;
        }
        
        // X-axis movement (LEFT/RIGHT)
        if (keys.has("arrowleft") || keys.has("a")) {
          rocket.x = rocket.x - moveAmount;
        }
        if (keys.has("arrowright") || keys.has("d")) {
          rocket.x = rocket.x + moveAmount;
        }
        
        // Bounds checking - clamp to canvas boundaries
        const minX = 0;
        const maxX = w - rocket.w;
        const minY = 0;
        const maxY = h - rocket.h;
        
        rocket.x = Math.max(minX, Math.min(maxX, rocket.x));
        rocket.y = Math.max(minY, Math.min(maxY, rocket.y));

        // Shooting - Press SPACEBAR to shoot
        if (keys.has(" ") && (ts - g.lastShot) > 150) {
          g.lastShot = ts;
          // Create bullet from rocket's tip (right side, at the tip Y position)
          g.bullets.push({
            x: rocket.x + rocket.w,
            y: rocket.y - 3, // Shoot from the tip of the ship (rocket.y is the tip)
            w: 10,
            h: 6,
            speed: 500,
          });
        }

        // Spawn targets - circular obstacles with different sizes
        g.nextTargetSpawn -= dt;
        if (g.nextTargetSpawn <= 0) {
          const colors = TARGET_COLORS;
          
          // Create different obstacle sizes: small (30%), medium (50%), large (20%)
          const rand = Math.random();
          let radius, points;
          if (rand < 0.3) {
            // Small obstacles
            radius = 12 + Math.random() * 5; // 12-17px
            points = 10;
          } else if (rand < 0.8) {
            // Medium obstacles
            radius = 18 + Math.random() * 7; // 18-25px
            points = 25;
          } else {
            // Large obstacles (bigger, more points)
            radius = 28 + Math.random() * 12; // 28-40px
            points = 50;
          }
          
          g.targets.push({
            x: w,
            y: Math.random() * (h - radius * 2),
            radius: radius,
            speed: 100,
            color: colors[Math.floor(Math.random() * colors.length)],
            points: points, // Points value for this obstacle
          });
          g.nextTargetSpawn = 1.5;
        }

        // Update bullets
        g.bullets.forEach(b => b.x += b.speed * dt);
        g.bullets = g.bullets.filter(b => b.x < w + 50);

        // Update targets
        g.targets.forEach(t => t.x -= t.speed * dt);
        g.targets = g.targets.filter(t => t.x > -50);

        // Update coin particles
        g.coins.forEach(coin => {
          coin.x += coin.vx * dt;
          coin.y += coin.vy * dt;
          coin.vy += 50 * dt; // Gravity effect
          coin.life -= dt * 2; // Fade out over 0.5 seconds
        });
        g.coins = g.coins.filter(coin => coin.life > 0 && coin.y > -50);

        // Collision: bullets vs targets (circular targets)
        for (let i = g.bullets.length - 1; i >= 0; i--) {
          const bullet = g.bullets[i];
          const bulletCenterX = bullet.x + bullet.w / 2;
          const bulletCenterY = bullet.y + bullet.h / 2;
          
          for (let j = g.targets.length - 1; j >= 0; j--) {
            const target = g.targets[j];
            const targetCenterX = target.x + target.radius;
            const targetCenterY = target.y + target.radius;
            
            // Calculate distance between bullet center and target center
            const dx = bulletCenterX - targetCenterX;
            const dy = bulletCenterY - targetCenterY;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            // Check if bullet overlaps with circular target
            if (distance < target.radius + Math.max(bullet.w, bullet.h) / 2) {
              // Hit! Award points based on obstacle size
              const points = target.points || 10;
              g.score += points;
              
              // Create coin particles for visual feedback
              // Show one main coin with total points, plus smaller coins for bigger obstacles
              const numCoins = points >= 50 ? 3 : points >= 25 ? 2 : 1;
              for (let k = 0; k < numCoins; k++) {
                g.coins.push({
                  x: targetCenterX + (k - (numCoins - 1) / 2) * 20, // Spread horizontally
                  y: targetCenterY,
                  vx: (Math.random() - 0.5) * 80, // Random horizontal velocity
                  vy: -60 - Math.random() * 40, // Upward velocity
                  life: 1.2, // Fade out over time
                  points: k === 0 ? points : 0, // Main coin shows points, others are decorative
                  isMain: k === 0, // Mark main coin
                });
              }
              
              // Remove bullet and target
              g.bullets.splice(i, 1);
              g.targets.splice(j, 1);
              break; // Bullet can only hit one target
            }
          }
        }

        // Collision: rocket vs targets (circular targets)
        const rocketCenterX = rocket.x + rocket.w / 2;
        const rocketCenterY = rocket.y;
        const rocketRadius = Math.max(rocket.w, rocket.h) / 2;
        
        for (const target of g.targets) {
          const targetCenterX = target.x + target.radius;
          const targetCenterY = target.y + target.radius;
          
          // Calculate distance between rocket center and target center
          const dx = rocketCenterX - targetCenterX;
          const dy = rocketCenterY - targetCenterY;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          // Check if rocket overlaps with circular target
          if (distance < target.radius + rocketRadius) {
            g.gameOver = true;
            break;
          }
        }
      }

      // Drawing — read theme and risk hex once per frame (avoids 4+ getRiskHex calls)
      const isLight = document.documentElement.classList.contains("light");
      const riskGood = getRiskHex("GOOD");
      const riskBad = getRiskHex("BAD");

      ctx.clearRect(0, 0, w, h);

      // Background — light: transparent so frame CSS (gradient + dots) shows; dark: draw gradient
      if (!isLight) {
        const bgCache = bgCacheRef.current;
        const themeChanged = bgCache.isLight === true;
        if (!bgCache.gradient || bgCache.height !== h || themeChanged) {
          const root = document.documentElement;
          const getVar = (name) => getComputedStyle(root).getPropertyValue(name).trim() || "#1c1a17";
          const primary = getVar("--theme-bg-primary");
          const tertiary = getVar("--theme-bg-tertiary");
          const grad = ctx.createLinearGradient(0, 0, 0, h);
          grad.addColorStop(0, primary);
          grad.addColorStop(0.5, tertiary);
          grad.addColorStop(1, primary);
          bgCache.gradient = grad;
          bgCache.height = h;
          bgCache.isLight = false;
        }
        ctx.fillStyle = bgCache.gradient;
        ctx.fillRect(0, 0, w, h);
      }
      bgCacheRef.current.isLight = isLight;

      // Stars — light: subtle dots (match homepage); dark: bright white
      ctx.fillStyle = isLight ? "rgba(73, 70, 63, 0.12)" : "rgba(255, 255, 255, 0.8)";
      for (let i = 0; i < 100; i++) {
        const x = (i * 37) % w;
        const y = (i * 73) % h;
        ctx.beginPath();
        ctx.arc(x, y, 1, 0, Math.PI * 2);
        ctx.fill();
      }

      // Targets - circular obstacles with glow
      g.targets.forEach(target => {
        ctx.shadowBlur = 10;
        ctx.shadowColor = target.color;
        ctx.fillStyle = target.color;
        ctx.beginPath();
        ctx.arc(target.x + target.radius, target.y + target.radius, target.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Bullets - make them more visible (use theme info color)
      if (!infoHexRef.current) infoHexRef.current = getInfoHex();
      const infoHex = infoHexRef.current;
      g.bullets.forEach(bullet => {
        ctx.shadowBlur = 8;
        ctx.shadowColor = infoHex;
        ctx.fillStyle = infoHex;
        ctx.fillRect(bullet.x, bullet.y, bullet.w, bullet.h);
        ctx.shadowBlur = 0;
        ctx.fillStyle = infoHex;
        ctx.fillRect(bullet.x + 2, bullet.y + 1, bullet.w - 4, bullet.h - 2);
      });

      // Coin particles - points boost animation
      g.coins.forEach(coin => {
        const alpha = Math.max(0, coin.life);
        const scale = 1 + (1 - coin.life) * 0.3; // Slight grow as they fade
        const size = coin.isMain ? 10 : 6; // Main coin is bigger
        
        // Draw coin/star effect
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.translate(coin.x, coin.y);
        ctx.scale(scale, scale);
        
        // Gold coin circle with glow
        ctx.fillStyle = coin.isMain ? "#ffd700" : "#ffed4e";
        ctx.shadowBlur = 12;
        ctx.shadowColor = "#ffd700";
        ctx.beginPath();
        ctx.arc(0, 0, size, 0, Math.PI * 2);
        ctx.fill();
        
        // Points text (only on main coin)
        if (coin.isMain && coin.points > 0) {
          ctx.shadowBlur = 8;
          ctx.shadowColor = "#22c55e";
          ctx.fillStyle = "#22c55e";
          ctx.font = "bold 14px monospace";
          ctx.textAlign = "center";
          ctx.fillText(`+${Math.round(coin.points)}`, 0, -18);
          ctx.textAlign = "left";
        }
        
        ctx.restore();
      });

      // Rocket - Blue triangular body with orange fin (matching screenshot)
      const rx = rocket.x;
      const ry = rocket.y; // This is the tip of the rocket
      const rw = rocket.w;
      const rh = rocket.h;

      // Orange fin on the left side
      ctx.fillStyle = "#ff6b35";
      ctx.beginPath();
      ctx.moveTo(rx, ry - rh / 2);
      ctx.lineTo(rx - 8, ry - rh / 3);
      ctx.lineTo(rx - 8, ry + rh / 3);
      ctx.lineTo(rx, ry + rh / 2);
      ctx.closePath();
      ctx.fill();

      // Blue triangular body pointing right (theme info color)
      ctx.fillStyle = infoHex;
      ctx.beginPath();
      ctx.moveTo(rx + rw, ry); // Tip pointing right
      ctx.lineTo(rx, ry - rh / 2); // Top left
      ctx.lineTo(rx, ry + rh / 2); // Bottom left
      ctx.closePath();
      ctx.fill();

      // Blue accent/cockpit window
      ctx.fillStyle = infoHex;
      ctx.beginPath();
      ctx.arc(rx + rw * 0.3, ry, 5, 0, Math.PI * 2);
      ctx.fill();

      // Score display (top left)
      ctx.fillStyle = "#22c55e";
      ctx.font = "bold 24px monospace";
      ctx.fillText(`Score: ${Math.floor(g.score)}`, 20, 40);
      
      // Instructions (top right) — theme-aware
      ctx.fillStyle = isLight ? "rgba(0, 0, 0, 0.65)" : "rgba(255, 255, 255, 0.7)";
      ctx.font = "14px monospace";
      ctx.textAlign = "right";
      ctx.fillText("SPACE to shoot", w - 20, 30);
      ctx.fillText("Arrow keys or WASD to move", w - 20, 50);
      ctx.textAlign = "left";
      
      // Debug info (bottom) — theme-aware
      const isFocused = document.activeElement === canvas;
      ctx.fillStyle = isFocused ? riskGood : riskBad;
      ctx.font = "14px monospace";
      ctx.fillText(`Focus: ${isFocused ? 'YES' : 'CLICK!'}`, 20, h - 60);
      
      if (keys.size > 0) {
        ctx.fillStyle = riskGood;
        ctx.fillText(`Keys: ${Array.from(keys).join(', ')}`, 20, h - 40);
      }
      
      ctx.fillStyle = isLight ? "rgba(0, 0, 0, 0.5)" : "rgba(255, 255, 255, 0.6)";
      ctx.fillText(`Canvas: ${w}x${h}`, 20, h - 20);
      ctx.fillText(`Rocket: (${Math.round(rocket.x)}, ${Math.round(rocket.y)})`, 200, h - 20);

      // Game over
      if (g.gameOver) {
        ctx.fillStyle = isLight ? "rgba(255, 255, 255, 0.88)" : "rgba(0, 0, 0, 0.75)";
        ctx.fillRect(0, 0, w, h);

        ctx.textAlign = "center";

        // "GAME OVER" title
        ctx.fillStyle = riskBad;
        ctx.font = "bold 48px monospace";
        ctx.fillText("GAME OVER", w / 2, h / 2 - 30);

        // Score
        ctx.fillStyle = isLight ? "rgba(0, 0, 0, 0.8)" : "rgba(255,255,255,0.7)";
        ctx.font = "20px monospace";
        ctx.fillText(`Score: ${Math.floor(g.score)}`, w / 2, h / 2 + 10);

        // Restart prompt - pulsing opacity
        const pulse = 0.5 + 0.5 * Math.sin(ts / 400);
        ctx.fillStyle = isLight
          ? `rgba(21, 128, 61, ${0.6 + pulse * 0.4})`
          : `rgba(59, 130, 246, ${0.5 + pulse * 0.5})`;
        ctx.font = "18px monospace";
        ctx.fillText("Press ENTER to play again", w / 2, h / 2 + 55);

        ctx.textAlign = "left";

        // Restart on Enter
        if (keys.has("enter")) {
          g.gameOver = false;
          g.score = 0;
          g.bullets = [];
          g.targets = [];
          g.coins = [];
          g.nextTargetSpawn = 1;
          g.rocket.x = 100;
          g.rocket.y = h / 2;
          keys.delete("enter");
        }
      }

      // Throttled stats callback (no React state — score is canvas-only; avoids re-renders)
      if (ts - g.lastUiUpdate > 100 && onStatsUpdate) {
        g.lastUiUpdate = ts;
        onStatsUpdate({
          score: Math.floor(g.score),
          best: Math.floor(g.score),
          time: (ts - g.startedAt) / 1000,
          gameOver: g.gameOver,
        });
      }

      rafRef.current = requestAnimationFrame(step);
    };

    // Initialize game - only set initial values if not already set
    if (gameRef.current.startedAt === 0) {
      const g = gameRef.current;
      g.startedAt = performance.now();
      g.lastTs = 0;
      g.lastUiUpdate = 0;
      g.lastShot = 0;
      g.gameOver = false;
      g.score = 0;
      g.bullets = [];
      g.targets = [];
      g.coins = [];
      g.nextTargetSpawn = 1;
      
      // Only set initial position if rocket hasn't been positioned yet
      const canvas = canvasRef.current;
      if (canvas && g.rocket.y === 300) {
        const h = canvas.height || canvas.clientHeight || 600;
        g.rocket.y = h / 2;
      }
    }

    rafRef.current = requestAnimationFrame(step);
    
    return () => {
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
      }
    };
  }, [isActive, onStatsUpdate]);

  return (
    <div className="rocket-game">
      <div className="rocket-game-frame">
        <canvas ref={canvasRef} className="rocket-game-canvas" />
      </div>
    </div>
  );
};

export default RocketGame;