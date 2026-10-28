-- ============================================================
-- Big Apple Reading Roots — Supabase 설정 (한 번만 실행)
-- Supabase 대시보드 → SQL Editor → 이 파일 전체 붙여넣기 → Run
-- 기존 앱 테이블(students, homeworks, submissions, notices)은 건드리지 않아요.
-- ============================================================

-- 1) 선생님 계정 목록 ------------------------------------------------
create table if not exists public.rr_teachers (
  user_id uuid primary key references auth.users(id) on delete cascade,
  name text not null default '선생님',
  created_at timestamptz not null default now()
);

-- 선생님인지 확인하는 함수 (보안 규칙에서 사용)
create or replace function public.rr_is_teacher()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.rr_teachers where user_id = auth.uid());
$$;

-- 2) 학생 ----------------------------------------------------------
-- (rr_is_student 함수는 아래 학생 테이블을 만든 뒤에 정의)
create table if not exists public.rr_students (
  user_id uuid primary key references auth.users(id) on delete cascade,
  login_id text not null unique,
  name text not null,
  class_name text not null default '',
  level int not null default 1,
  pin text not null,
  active boolean not null default true,
  last_login_at timestamptz,
  created_at timestamptz not null default now()
);

-- 등록된(사용 중인) 학생인지 확인하는 함수
create or replace function public.rr_is_student()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.rr_students where user_id = auth.uid() and active);
$$;

-- 3) 책 ------------------------------------------------------------
create table if not exists public.rr_books (
  id text primary key,            -- 예: '2-7' (레벨-번호, 빅애플 ORT 리스트 순서)
  series text not null default 'ORT',
  level int not null,
  num int not null,
  title text not null,
  video_drive_id text,            -- 구글 드라이브 영상 파일 ID (있으면 앱에서 재생)
  quiz jsonb,                     -- 2단계에서 사용
  unique (series, level, num)
);

-- 4) 녹음 제출 -----------------------------------------------------
create table if not exists public.rr_submissions (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.rr_students(user_id) on delete cascade,
  book_id text not null references public.rr_books(id),
  audio_path text,                -- 저장소(recordings) 안의 파일 경로
  duration_sec int,
  created_at timestamptz not null default now(),
  feedback text,
  feedback_at timestamptz,
  score int                       -- 2단계(자동 채점)에서 사용
);
create index if not exists rr_submissions_student_idx on public.rr_submissions(student_id, created_at desc);
create index if not exists rr_submissions_pending_idx on public.rr_submissions(created_at desc) where feedback is null;

-- 5) 보안 규칙 (Row Level Security) --------------------------------
alter table public.rr_teachers   enable row level security;
alter table public.rr_students   enable row level security;
alter table public.rr_books      enable row level security;
alter table public.rr_submissions enable row level security;

drop policy if exists "teacher reads self" on public.rr_teachers;
create policy "teacher reads self" on public.rr_teachers
  for select to authenticated using (user_id = auth.uid());

drop policy if exists "teacher manages students" on public.rr_students;
create policy "teacher manages students" on public.rr_students
  for all to authenticated using (public.rr_is_teacher()) with check (public.rr_is_teacher());

drop policy if exists "student reads self" on public.rr_students;
create policy "student reads self" on public.rr_students
  for select to authenticated using (user_id = auth.uid());

drop policy if exists "everyone signed in reads books" on public.rr_books;
create policy "everyone signed in reads books" on public.rr_books
  for select to authenticated using (true);

drop policy if exists "teacher manages books" on public.rr_books;
create policy "teacher manages books" on public.rr_books
  for all to authenticated using (public.rr_is_teacher()) with check (public.rr_is_teacher());

drop policy if exists "student inserts own submission" on public.rr_submissions;
create policy "student inserts own submission" on public.rr_submissions
  for insert to authenticated with check (student_id = auth.uid() and public.rr_is_student());

drop policy if exists "student reads own submissions" on public.rr_submissions;
create policy "student reads own submissions" on public.rr_submissions
  for select to authenticated using (student_id = auth.uid());

drop policy if exists "teacher manages submissions" on public.rr_submissions;
create policy "teacher manages submissions" on public.rr_submissions
  for all to authenticated using (public.rr_is_teacher()) with check (public.rr_is_teacher());

-- 6) 학생이 로그인한 시간 기록 -------------------------------------
create or replace function public.rr_touch_login()
returns void
language sql
security definer
set search_path = public
as $$
  update public.rr_students set last_login_at = now() where user_id = auth.uid();
$$;

-- 7) 선생님이 학생 비밀번호(4자리)를 바꾸는 함수 --------------------
create or replace function public.rr_reset_pin(p_student uuid, p_pin text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.rr_is_teacher() then
    raise exception 'not a teacher';
  end if;
  if p_pin !~ '^[0-9]{4}$' then
    raise exception 'pin must be 4 digits';
  end if;
  update auth.users
     set encrypted_password = extensions.crypt('rr-' || p_pin || '-bigapple', extensions.gen_salt('bf'))
   where id = p_student;
  update public.rr_students set pin = p_pin where user_id = p_student;
end;
$$;

revoke all on function public.rr_reset_pin(uuid, text) from public, anon;
grant execute on function public.rr_reset_pin(uuid, text) to authenticated;
grant execute on function public.rr_touch_login() to authenticated;
grant execute on function public.rr_is_teacher() to authenticated;
grant execute on function public.rr_is_student() to authenticated;

-- 8) 녹음 파일 저장소 (비공개) -------------------------------------
insert into storage.buckets (id, name, public, file_size_limit)
values ('recordings', 'recordings', false, 20971520)
on conflict (id) do nothing;

drop policy if exists "rr student uploads own recordings" on storage.objects;
create policy "rr student uploads own recordings" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'recordings' and (storage.foldername(name))[1] = auth.uid()::text and public.rr_is_student());

drop policy if exists "rr read own or teacher" on storage.objects;
create policy "rr read own or teacher" on storage.objects
  for select to authenticated
  using (bucket_id = 'recordings' and ((storage.foldername(name))[1] = auth.uid()::text or public.rr_is_teacher()));

drop policy if exists "rr teacher deletes recordings" on storage.objects;
create policy "rr teacher deletes recordings" on storage.objects
  for delete to authenticated
  using (bucket_id = 'recordings' and public.rr_is_teacher());

-- 9) ORT Level 1~3 책 목록 (빅애플 ORT 리스트 순서) -----------------
insert into public.rr_books (id, series, level, num, title, video_drive_id) values
  ('1-1', 'ORT', 1, 1, 'The Headache', null),
  ('1-2', 'ORT', 1, 2, 'At the Park', null),
  ('1-3', 'ORT', 1, 3, 'Fancy Dress', null),
  ('1-4', 'ORT', 1, 4, 'Push!', null),
  ('1-5', 'ORT', 1, 5, 'Good Old Mum', null),
  ('1-6', 'ORT', 1, 6, 'The Pet Shop', null),
  ('1-7', 'ORT', 1, 7, 'What a Mess!', null),
  ('1-8', 'ORT', 1, 8, 'Making Faces', null),
  ('1-9', 'ORT', 1, 9, 'The Journey', null),
  ('1-10', 'ORT', 1, 10, 'Goal!', null),
  ('1-11', 'ORT', 1, 11, 'Who Did That?', null),
  ('1-12', 'ORT', 1, 12, 'Shopping', null),
  ('1-13', 'ORT', 1, 13, 'Hop! Hop! Hop!', null),
  ('1-14', 'ORT', 1, 14, 'Catkin the Kitten', null),
  ('1-15', 'ORT', 1, 15, 'In the Trolley', null),
  ('1-16', 'ORT', 1, 16, 'The Trampoline', null),
  ('1-17', 'ORT', 1, 17, 'The Enormous Crab', null),
  ('1-18', 'ORT', 1, 18, 'The Caterpillar', null),
  ('1-19', 'ORT', 1, 19, 'Hide and Seek', null),
  ('1-20', 'ORT', 1, 20, 'Look at Me', null),
  ('1-21', 'ORT', 1, 21, 'Go Away, Floppy', null),
  ('1-22', 'ORT', 1, 22, 'Reds and Blues', null),
  ('1-23', 'ORT', 1, 23, 'Big Feet', null),
  ('1-24', 'ORT', 1, 24, 'Kipper''s Diary', null),
  ('1-25', 'ORT', 1, 25, 'What Dogs Like', null),
  ('1-26', 'ORT', 1, 26, 'Presents for Dad', null),
  ('1-27', 'ORT', 1, 27, 'Top Dog', null),
  ('1-28', 'ORT', 1, 28, 'Go Away, Cat', null),
  ('1-29', 'ORT', 1, 29, 'Go On, Mum!', null),
  ('1-30', 'ORT', 1, 30, 'Look After Me', null),
  ('1-31', 'ORT', 1, 31, 'The Sandcastle', null),
  ('1-32', 'ORT', 1, 32, 'Floppy''s Bone', null),
  ('1-33', 'ORT', 1, 33, 'The Box of Treasure', null),
  ('1-34', 'ORT', 1, 34, 'One Wheel', null),
  ('1-35', 'ORT', 1, 35, 'Chip''s Robot', null),
  ('1-36', 'ORT', 1, 36, 'Hook a Duck', null),
  ('1-37', 'ORT', 1, 37, 'The Ice Cream', null),
  ('1-38', 'ORT', 1, 38, 'Can You See Me?', null),
  ('1-39', 'ORT', 1, 39, 'Good Dog', null),
  ('1-40', 'ORT', 1, 40, 'What a Din!', null),
  ('1-41', 'ORT', 1, 41, 'See Me Skip', null),
  ('1-42', 'ORT', 1, 42, 'The Mud Pie', null),
  ('2-1', 'ORT', 2, 1, 'A Sinking Feeling', null),
  ('2-2', 'ORT', 2, 2, 'Naughty Children', null),
  ('2-3', 'ORT', 2, 3, 'Monkey Tricks', null),
  ('2-4', 'ORT', 2, 4, 'Hey Presto!', null),
  ('2-5', 'ORT', 2, 5, 'It''s the Weather', null),
  ('2-6', 'ORT', 2, 6, 'Creepy-crawly!', null),
  ('2-7', 'ORT', 2, 7, 'What Is It?', null),
  ('2-8', 'ORT', 2, 8, 'The Lost Puppy', null),
  ('2-9', 'ORT', 2, 9, 'New Trees', null),
  ('2-10', 'ORT', 2, 10, 'The Band', null),
  ('2-11', 'ORT', 2, 11, 'The Little Dragon', null),
  ('2-12', 'ORT', 2, 12, 'Up and Down', null),
  ('2-13', 'ORT', 2, 13, 'The Odd Egg', null),
  ('2-14', 'ORT', 2, 14, 'Out!', null),
  ('2-15', 'ORT', 2, 15, 'Fire!', null),
  ('2-16', 'ORT', 2, 16, 'The Ball Pit', null),
  ('2-17', 'ORT', 2, 17, 'Red Noses', null),
  ('2-18', 'ORT', 2, 18, 'The Gulls'' Picnic', null),
  ('2-19', 'ORT', 2, 19, 'The Big Egg', null),
  ('2-20', 'ORT', 2, 20, 'Poor Floppy', null),
  ('2-21', 'ORT', 2, 21, 'Put It Back', null),
  ('2-22', 'ORT', 2, 22, 'The Hole in the Sand', null),
  ('2-23', 'ORT', 2, 23, 'A Present for Mum', null),
  ('2-24', 'ORT', 2, 24, 'In a Bit', null),
  ('2-25', 'ORT', 2, 25, 'The Toys'' Party', null),
  ('2-26', 'ORT', 2, 26, 'New Trainers', null),
  ('2-27', 'ORT', 2, 27, 'A New Dog', null),
  ('2-28', 'ORT', 2, 28, 'The Dream', null),
  ('2-29', 'ORT', 2, 29, 'The Go-kart', null),
  ('2-30', 'ORT', 2, 30, 'What a Bad Dog!', null),
  ('2-31', 'ORT', 2, 31, 'Floppy''s Bath', null),
  ('2-32', 'ORT', 2, 32, 'The Baby-sitter', null),
  ('2-33', 'ORT', 2, 33, 'The Water Fight', null),
  ('2-34', 'ORT', 2, 34, 'Kipper''s Birthday', null),
  ('2-35', 'ORT', 2, 35, 'Spots!', null),
  ('2-36', 'ORT', 2, 36, 'Kipper''s Balloon', null),
  ('2-37', 'ORT', 2, 37, 'Kipper''s Laces', null),
  ('2-38', 'ORT', 2, 38, 'The Wobbly Tooth', null),
  ('2-39', 'ORT', 2, 39, 'The Foggy Day', null),
  ('2-40', 'ORT', 2, 40, 'The Chase', null),
  ('2-41', 'ORT', 2, 41, 'Biff''s Aeroplane', null),
  ('2-42', 'ORT', 2, 42, 'Floppy the Hero', null),
  ('3-1', 'ORT', 3, 1, 'On the Sand', null),
  ('3-2', 'ORT', 3, 2, 'The Egg Hunt', null),
  ('3-3', 'ORT', 3, 3, 'Nobody Wanted to Play', null),
  ('3-4', 'ORT', 3, 4, 'By the Stream', null),
  ('3-5', 'ORT', 3, 5, 'The Rope Swing', null),
  ('3-6', 'ORT', 3, 6, 'A Cat in the Tree', null),
  ('3-7', 'ORT', 3, 7, 'Kipper the Clown', null),
  ('3-8', 'ORT', 3, 8, 'Strawberry Jam', null),
  ('3-9', 'ORT', 3, 9, 'The Jumble Sale', null),
  ('3-10', 'ORT', 3, 10, 'The Snowman', null),
  ('3-11', 'ORT', 3, 11, 'Kipper''s Idea', null),
  ('3-12', 'ORT', 3, 12, 'At the Seaside', null),
  ('3-13', 'ORT', 3, 13, 'The Barbecue', null),
  ('3-14', 'ORT', 3, 14, 'The Carnival', null),
  ('3-15', 'ORT', 3, 15, 'At the Pool', null),
  ('3-16', 'ORT', 3, 16, 'The Cold Day', null),
  ('3-17', 'ORT', 3, 17, 'Book Week', null),
  ('3-18', 'ORT', 3, 18, 'Bull''s-eye!', null),
  ('3-19', 'ORT', 3, 19, 'The Duck Race', null),
  ('3-20', 'ORT', 3, 20, 'Sniff', null),
  ('3-21', 'ORT', 3, 21, 'Pond Dipping', null),
  ('3-22', 'ORT', 3, 22, 'The Steel Band', null),
  ('3-23', 'ORT', 3, 23, 'The Mud Bath', null),
  ('3-24', 'ORT', 3, 24, 'The Ice Rink', null),
  ('3-25', 'ORT', 3, 25, 'Floppy and the Puppets', null),
  ('3-26', 'ORT', 3, 26, 'Monkeys on the Car', null),
  ('3-27', 'ORT', 3, 27, 'Dragons!', null),
  ('3-28', 'ORT', 3, 28, 'Helicopter Rescue', null),
  ('3-29', 'ORT', 3, 29, 'Gran and the Go-karts', null),
  ('3-30', 'ORT', 3, 30, 'The Enormous Picture', null),
  ('3-31', 'ORT', 3, 31, 'King of the Castle', null),
  ('3-32', 'ORT', 3, 32, 'Bug Hunt', null),
  ('3-33', 'ORT', 3, 33, 'Mister Haggis', null),
  ('3-34', 'ORT', 3, 34, 'A Walk in the Sun', null),
  ('3-35', 'ORT', 3, 35, 'Green Sheets', null),
  ('3-36', 'ORT', 3, 36, 'Road Burner', null)
on conflict (id) do update set title = excluded.title;

