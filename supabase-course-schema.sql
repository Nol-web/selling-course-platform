-- Global Seller Hub course platform schema
-- Run this in Supabase SQL Editor inside the existing workflow-app project.

create extension if not exists "pgcrypto";

create table if not exists public.course_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text not null default '',
  terms_accepted_at timestamptz,
  privacy_accepted_at timestamptz,
  marketing_accepted_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.course_invite_codes (
  code text primary key,
  label text not null,
  course_ids text[] not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.course_enrollments (
  user_id uuid not null references auth.users(id) on delete cascade,
  course_id text not null,
  source_code text references public.course_invite_codes(code),
  created_at timestamptz not null default now(),
  primary key (user_id, course_id)
);

create table if not exists public.course_admins (
  email text primary key,
  created_at timestamptz not null default now()
);

create table if not exists public.site_sections (
  key text primary key,
  content jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.course_profiles enable row level security;
alter table public.course_invite_codes enable row level security;
alter table public.course_enrollments enable row level security;
alter table public.course_admins enable row level security;
alter table public.site_sections enable row level security;

drop policy if exists "course_profiles_select_own" on public.course_profiles;
create policy "course_profiles_select_own"
on public.course_profiles for select
to authenticated
using (auth.uid() = id);

drop policy if exists "course_profiles_update_own" on public.course_profiles;
create policy "course_profiles_update_own"
on public.course_profiles for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "course_enrollments_select_own" on public.course_enrollments;
create policy "course_enrollments_select_own"
on public.course_enrollments for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "course_invite_codes_no_public_read" on public.course_invite_codes;
create policy "course_invite_codes_no_public_read"
on public.course_invite_codes for select
to authenticated
using (false);

drop policy if exists "course_admins_select_self" on public.course_admins;
create policy "course_admins_select_self"
on public.course_admins for select
to authenticated
using (email = auth.jwt()->>'email');

drop policy if exists "site_sections_public_read" on public.site_sections;
create policy "site_sections_public_read"
on public.site_sections for select
to anon, authenticated
using (true);

create or replace function public.is_course_admin()
returns boolean
as $$
begin
  if auth.uid() is null then
    return false;
  end if;

  return exists (
    select 1
    from public.course_admins a
    where lower(a.email) = lower(auth.jwt()->>'email')
  );
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.is_course_admin() to authenticated;

create or replace function public.get_site_section(section_key text)
returns jsonb
as $$
begin
  return coalesce(
    (
      select s.content
      from public.site_sections s
      where s.key = section_key
    ),
    '{}'::jsonb
  );
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.get_site_section(text) to anon, authenticated;

create or replace function public.save_site_section(
  section_key text,
  section_content jsonb
)
returns jsonb
as $$
begin
  if not public.is_course_admin() then
    raise exception 'Admin access required';
  end if;

  if coalesce(trim(section_key), '') = '' then
    raise exception 'Section key is required';
  end if;

  insert into public.site_sections (key, content, updated_at)
  values (section_key, coalesce(section_content, '{}'::jsonb), now())
  on conflict (key) do update
  set
    content = excluded.content,
    updated_at = now();

  return public.get_site_section(section_key);
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.save_site_section(text, jsonb) to authenticated;

create or replace function public.course_admin_overview()
returns jsonb
as $$
begin
  if not public.is_course_admin() then
    raise exception 'Admin access required';
  end if;

  return jsonb_build_object(
    'members', (select count(*) from public.course_profiles),
    'inviteCodes', (select count(*) from public.course_invite_codes where active = true),
    'enrollments', (select count(*) from public.course_enrollments),
    'recentMembers', coalesce((
      select jsonb_agg(row_to_json(p))
      from (
        select email, full_name, created_at
        from public.course_profiles
        order by created_at desc
        limit 8
      ) p
    ), '[]'::jsonb),
    'inviteLinks', coalesce((
      select jsonb_agg(row_to_json(i))
      from (
        select code, label, course_ids, active, created_at
        from public.course_invite_codes
        order by created_at desc
        limit 20
      ) i
    ), '[]'::jsonb)
  );
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.course_admin_overview() to authenticated;

create or replace function public.handle_course_profile_signup()
returns trigger
as $$
begin
  insert into public.course_profiles (
    id,
    email,
    full_name,
    terms_accepted_at,
    privacy_accepted_at,
    marketing_accepted_at
  )
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    case when coalesce((new.raw_user_meta_data->>'terms_accepted')::boolean, false) then now() else null end,
    case when coalesce((new.raw_user_meta_data->>'privacy_accepted')::boolean, false) then now() else null end,
    case when coalesce((new.raw_user_meta_data->>'marketing_accepted')::boolean, false) then now() else null end
  )
  on conflict (id) do update
  set
    email = excluded.email,
    full_name = excluded.full_name,
    updated_at = now();

  return new;
end;
$$
language plpgsql
security definer
set search_path = public;

drop trigger if exists on_course_auth_user_created on auth.users;
create trigger on_course_auth_user_created
after insert on auth.users
for each row execute function public.handle_course_profile_signup();

create or replace function public.enroll_from_course_invite(invite_code text)
returns table(course_id text)
as $$
declare
  target_invite public.course_invite_codes%rowtype;
  target_course text;
begin
  if auth.uid() is null then
    raise exception 'Login is required';
  end if;

  select *
  into target_invite
  from public.course_invite_codes
  where code = invite_code
    and active = true;

  if not found then
    raise exception 'Invalid invite code';
  end if;

  foreach target_course in array target_invite.course_ids loop
    insert into public.course_enrollments (user_id, course_id, source_code)
    values (auth.uid(), target_course, target_invite.code)
    on conflict (user_id, course_id) do nothing;
  end loop;

  return query
  select e.course_id
  from public.course_enrollments e
  where e.user_id = auth.uid()
  order by e.created_at;
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.enroll_from_course_invite(text) to authenticated;

create or replace function public.save_course_invite(
  invite_code text,
  invite_label text,
  invite_course_ids text[]
)
returns table(code text, label text, course_ids text[])
as $$
declare
  clean_code text;
begin
  if not public.is_course_admin() then
    raise exception 'Admin access required';
  end if;

  clean_code := lower(regexp_replace(coalesce(invite_code, ''), '[^a-z0-9-]', '-', 'g'));
  clean_code := trim(both '-' from clean_code);

  if length(clean_code) < 3 or length(clean_code) > 48 then
    raise exception 'Invite code must be 3-48 characters';
  end if;

  if array_length(invite_course_ids, 1) is null then
    raise exception 'Select at least one course';
  end if;

  insert into public.course_invite_codes (code, label, course_ids, active)
  values (
    clean_code,
    coalesce(nullif(trim(coalesce(invite_label, '')), ''), clean_code),
    invite_course_ids,
    true
  )
  on conflict (code) do update
  set
    label = excluded.label,
    course_ids = excluded.course_ids,
    active = true;

  return query
  select i.code, i.label, i.course_ids
  from public.course_invite_codes i
  where i.code = clean_code;
end;
$$
language plpgsql
security definer
set search_path = public;

grant execute on function public.save_course_invite(text, text, text[]) to authenticated;

insert into public.course_invite_codes (code, label, course_ids)
values
  ('starter', '입문 스타터팩', array['global-selling-start', 'marketplace-entry']),
  ('lazada', '라자다 시작 패키지', array['global-selling-start', 'marketplace-entry', 'product-listing']),
  ('ops', '운영 실무 패키지', array['seller-operations', 'seller-automation']),
  ('all', '전체 무료 강의 패키지', array['global-selling-start', 'marketplace-entry', 'product-listing', 'seller-operations', 'ads-growth', 'seller-automation'])
on conflict (code) do update
set
  label = excluded.label,
  course_ids = excluded.course_ids,
  active = true;

insert into public.site_sections (key, content)
values (
  'roadmap',
  '{
    "title": "처음 시작하는 순서",
    "description": "막연한 해외 판매를 단계별 학습 흐름으로 바꿉니다.",
    "steps": [
      {
        "title": "시장과 채널 선택",
        "body": "내 상품과 자본에 맞는 국가, 플랫폼, 판매 방식을 고릅니다."
      },
      {
        "title": "상품과 리스팅",
        "body": "팔릴 만한 상품을 찾고 구매자가 이해하는 페이지로 구성합니다."
      },
      {
        "title": "주문과 운영",
        "body": "배송, CS, 반품, 정산을 반복 가능한 업무 흐름으로 만듭니다."
      },
      {
        "title": "광고와 확장",
        "body": "지표를 보고 광고, 상품군, 자동화를 붙여 매출을 키웁니다."
      }
    ]
  }'::jsonb
)
on conflict (key) do nothing;
