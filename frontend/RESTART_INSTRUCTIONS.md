# How to See Theme Changes

## Important: You MUST access the correct port!

- **Frontend (React/Vite)**: `http://localhost:5173` ✅ CORRECT
- **API (FastAPI)**: `http://localhost:8007` ❌ WRONG (this is the backend API)

## Steps to See Changes:

1. **Stop the current dev server** (if running):
   ```bash
   # Press Ctrl+C in the terminal where npm run dev is running
   # OR kill the process:
   pkill -f vite
   ```

2. **Clear Vite cache**:
   ```bash
   cd frontend
   rm -rf node_modules/.vite .vite dist
   ```

3. **Restart the dev server**:
   ```bash
   npm run dev
   ```

4. **Open the CORRECT URL in your browser**:
   ```
   http://localhost:5173
   ```
   NOT http://localhost:8007 or http://0.0.0.0:8007

5. **Hard refresh your browser**:
   - Mac: `Cmd + Shift + R`
   - Windows: `Ctrl + Shift + F5`
   - Or: Open DevTools (F12) → Network tab → Check "Disable cache" → Refresh

## Why Changes Might Not Show:

- ❌ Accessing port 8007 (that's the API, not the frontend)
- ❌ Browser cache (need hard refresh)
- ❌ Vite cache (need to clear and restart)
- ❌ Dev server not running

## Verify Dev Server is Running:

```bash
lsof -ti:5173
# Should return a process ID if running
```

## SCSS Compilation:

✅ **Vite automatically compiles SCSS** - no manual compilation needed!
- Vite uses the `sass` package (already installed)
- SCSS files are compiled on-the-fly during development
- Changes should hot-reload automatically

If you see the old theme, you're likely:
1. Looking at the wrong port (8007 instead of 5173)
2. Need to hard refresh the browser
3. Need to restart the dev server after clearing cache

