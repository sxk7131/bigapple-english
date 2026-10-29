-- ============================================================
-- Reading Roots — 책장 (한 번만 실행, 묶음 피드백 SQL 다음에)
-- 아이마다 책장 하나를 배정하고, 책장은 시리즈·레벨별로 늘려갈 수 있음
-- ============================================================

create table if not exists public.rr_shelves (
  id text primary key,                 -- 예: 'ort-2', 'reading-roots-1'
  title text not null,                 -- 예: 'ORT Level 2'
  series text not null,                -- 예: 'ORT'
  level int not null default 0,
  batch_size int not null default 10,  -- 녹음 몇 권마다 피드백 1개
  sort int not null default 0,
  created_at timestamptz not null default now(),
  unique (series, level)
);

insert into public.rr_shelves (id, title, series, level, batch_size, sort) values
  ('ort-1', 'ORT Level 1', 'ORT', 1, 10, 10),
  ('ort-2', 'ORT Level 2', 'ORT', 2, 10, 20),
  ('ort-3', 'ORT Level 3', 'ORT', 3, 10, 30)
on conflict (id) do nothing;

-- 책 → 책장
alter table public.rr_books add column if not exists shelf_id text references public.rr_shelves(id) on delete cascade;
alter table public.rr_books add column if not exists label text;          -- 책등에 보일 번호 (없으면 책 id)
alter table public.rr_books alter column level set default 0;
update public.rr_books set shelf_id = 'ort-' || level where series = 'ORT' and shelf_id is null and level between 1 and 3;
create index if not exists rr_books_shelf_idx on public.rr_books(shelf_id, num);

-- 학생 → 책장 (지금 레벨 그대로 옮김)
alter table public.rr_students add column if not exists shelf_id text references public.rr_shelves(id) on delete set null;
update public.rr_students set shelf_id = 'ort-' || level where shelf_id is null and level between 1 and 3;

alter table public.rr_shelves enable row level security;

drop policy if exists "signed in reads shelves" on public.rr_shelves;
create policy "signed in reads shelves" on public.rr_shelves
  for select to authenticated using (true);

drop policy if exists "teacher manages shelves" on public.rr_shelves;
create policy "teacher manages shelves" on public.rr_shelves
  for all to authenticated using (public.rr_is_teacher()) with check (public.rr_is_teacher());

select (select count(*) from public.rr_shelves) as shelves,
       (select count(*) from public.rr_books where shelf_id is not null) as books_on_shelves,
       (select count(*) from public.rr_students where shelf_id is not null) as students_with_shelf;
