-- 002_user_scan_history.sql
-- User-scoped scan history that references global scan_results by extension_id.

create table if not exists public.user_scan_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  extension_id text not null,
  created_at timestamptz not null default now()
);

create index if not exists user_scan_history_user_created_at_idx
  on public.user_scan_history (user_id, created_at desc);

alter table public.user_scan_history enable row level security;

-- Users can only see their own history
create policy "user_scan_history_select_own"
  on public.user_scan_history
  for select
  using (auth.uid() = user_id);

-- Users can only insert rows for themselves
create policy "user_scan_history_insert_own"
  on public.user_scan_history
  for insert
  with check (auth.uid() = user_id);

-- Users can delete their own history rows
create policy "user_scan_history_delete_own"
  on public.user_scan_history
  for delete
  using (auth.uid() = user_id);


