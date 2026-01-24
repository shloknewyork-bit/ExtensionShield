#!/bin/bash
cd /Users/stanzin/Desktop/Project-Atlas/frontend
echo "Clearing Vite cache..."
rm -rf node_modules/.vite .vite dist 2>/dev/null
echo "Starting dev server..."
npm run dev

