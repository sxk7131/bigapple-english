-- ============================================================
-- Reading Roots — 묶음 피드백 (한 번만 실행)
-- Level 1~3: 녹음 10권마다, Level 4 이상: 5권마다 피드백 1개
-- ============================================================

create table if not exists public.rr_feedbacks (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.rr_students(user_id) on delete cascade,
  text text not null,
  book_count int not null default 0,
  avg_score int,                 -- 자동 채점이 붙으면 채워짐
  top_words jsonb,               -- 자주 틀린 단어 (자동 채점이 붙으면 채워짐)
  created_at timestamptz not null default now()
);
create index if not exists rr_feedbacks_student_idx on public.rr_feedbacks(student_id, created_at desc);

alter table public.rr_submissions add column if not exists batch_id uuid references public.rr_feedbacks(id) on delete set null;
create index if not exists rr_submissions_unbatched_idx on public.rr_submissions(student_id) where batch_id is null;

alter table public.rr_feedbacks enable row level security;

drop policy if exists "teacher manages feedbacks" on public.rr_feedbacks;
create policy "teacher manages feedbacks" on public.rr_feedbacks
  for all to authenticated using (public.rr_is_teacher()) with check (public.rr_is_teacher());

drop policy if exists "student reads own feedbacks" on public.rr_feedbacks;
create policy "student reads own feedbacks" on public.rr_feedbacks
  for select to authenticated using (student_id = auth.uid());

-- 학생은 아직 피드백 묶음에 들어가지 않은 자기 녹음만 지울 수 있음
drop policy if exists "student deletes own unreviewed submission" on public.rr_submissions;
create policy "student deletes own unreviewed submission" on public.rr_submissions
  for delete to authenticated using (student_id = auth.uid() and feedback is null and batch_id is null);

-- 선생님이 녹음 묶음에 피드백 하나를 남기는 함수 (한 번에 저장)
create or replace function public.rr_give_feedback(p_student uuid, p_text text, p_submissions uuid[])
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  if not public.rr_is_teacher() then
    raise exception 'not a teacher';
  end if;
  if coalesce(trim(p_text), '') = '' then
    raise exception 'feedback text is empty';
  end if;
  insert into public.rr_feedbacks (student_id, text, book_count, avg_score)
  values (p_student, trim(p_text), coalesce(array_length(p_submissions, 1), 0),
          (select round(avg(score))::int from public.rr_submissions where id = any(p_submissions) and score is not null))
  returning id into v_id;
  update public.rr_submissions
     set batch_id = v_id
   where id = any(p_submissions) and student_id = p_student and batch_id is null;
  return v_id;
end;
$$;

revoke all on function public.rr_give_feedback(uuid, text, uuid[]) from public, anon;
grant execute on function public.rr_give_feedback(uuid, text, uuid[]) to authenticated;

select 'ok' as feedback_batches_ready;
