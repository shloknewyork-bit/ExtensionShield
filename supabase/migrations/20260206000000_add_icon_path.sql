-- Add icon_path column to scan_results table
-- This stores the relative path to the extension icon (e.g., "icons/128.png")
-- extracted from manifest.json during scan

alter table public.scan_results 
add column if not exists icon_path text;

-- Add comment for documentation
comment on column public.scan_results.icon_path is 
'Relative path to extension icon file (e.g., "icons/128.png") extracted from manifest.json. Used to render extension icons via /api/scan/icon/{extension_id} endpoint.';

