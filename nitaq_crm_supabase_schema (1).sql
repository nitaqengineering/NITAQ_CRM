-- ============================================================
-- نطاق (NITAQ CRM) — سكيما الربط السحابي (Supabase)
-- شغّل الملف ده مرة واحدة بس، من: Supabase Dashboard → SQL Editor → New query
-- ============================================================

-- 1) جدول الملفات الشخصية (المستخدمون + الأدوار + الصلاحيات)
create table if not exists nitaq_crm_profiles (
  id            text primary key,                 -- نفس الـid المستخدم داخل التطبيق (ownerId/engineerId/byId)
  auth_user_id  uuid unique references auth.users(id) on delete set null,
  name          text not null,
  email         text,
  role          text not null default 'engineer' check (role in ('owner','engineer')),
  perms         jsonb not null default '{"seeAll":false,"editAll":false,"assign":false,"del":false,"dash":false,"reports":false,"groups":true,"lookups":false,"data":false}'::jsonb,
  active        boolean not null default true,
  created_at    timestamptz not null default now()
);

-- 2) جدول السجلات العام (عملاء / اسكتشات ومشاريع / سجل تواصل / سجل تعديلات)
create table if not exists nitaq_crm_records (
  id          text primary key,
  entity      text not null check (entity in ('client','lead','inter','audit','settings')),
  data        jsonb not null,
  updated_at  timestamptz not null default now()
);
create index if not exists idx_nitaq_crm_records_entity on nitaq_crm_records(entity);
create index if not exists idx_nitaq_crm_records_lead_owner on nitaq_crm_records((data->>'ownerId')) where entity='lead';
create index if not exists idx_nitaq_crm_records_lead_engineer on nitaq_crm_records((data->>'engineerId')) where entity='lead';
create index if not exists idx_nitaq_crm_records_inter_lead on nitaq_crm_records((data->>'leadId')) where entity='inter';

alter table nitaq_crm_profiles enable row level security;
alter table nitaq_crm_records  enable row level security;

-- 3) دوال مساعدة — بتقرا بروفايل المستخدم الحالي مرة واحدة لكل استعلام
create or replace function nitaq_my_profile_id() returns text
language sql stable security definer set search_path = public as $$
  select id from nitaq_crm_profiles where auth_user_id = auth.uid() and active = true limit 1
$$;

create or replace function nitaq_my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from nitaq_crm_profiles where auth_user_id = auth.uid() and active = true limit 1
$$;

create or replace function nitaq_see_all() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(role = 'owner' or (perms->>'seeAll')::boolean, false)
  from nitaq_crm_profiles where auth_user_id = auth.uid() and active = true limit 1
$$;

create or replace function nitaq_is_active_user() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from nitaq_crm_profiles where auth_user_id = auth.uid() and active = true)
$$;

-- بيفحص هل الاسكتش/المشروع صاحب leadId ده منسوب لي (كمسؤول أو مهندس).
-- لازم يبقى SECURITY DEFINER عشان يتخطى RLS جوه نفسه — الاستعلام ده بيقرا من
-- نفس جدول nitaq_crm_records اللي بيحمي نفسه، فلو سيبناه عادي هيسبب
-- "infinite recursion detected in policy" لأن قراءته هتفعّل نفس السياسة من جديد.
create or replace function nitaq_lead_is_mine(p_lead_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from nitaq_crm_records lr
    where lr.entity = 'lead' and lr.data->>'id' = p_lead_id
      and (lr.data->>'ownerId' = nitaq_my_profile_id() or lr.data->>'engineerId' = nitaq_my_profile_id())
  )
$$;

-- 4) أول حساب يسجّل = مالك تلقائياً. لو فيه دعوة سابقة بنفس الإيميل (بروفايل بدون auth_user_id)
--    بيتربط بيها بدل ما يتعمل بروفايل جديد — عشان سجلاته القديمة تفضل منسوبة له.
create or replace function nitaq_handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  existing_id text;
  cnt int;
begin
  select id into existing_id from nitaq_crm_profiles
    where lower(email) = lower(new.email) and auth_user_id is null limit 1;

  if existing_id is not null then
    update nitaq_crm_profiles set auth_user_id = new.id, active = true where id = existing_id;
  else
    select count(*) into cnt from nitaq_crm_profiles;
    insert into nitaq_crm_profiles (id, auth_user_id, name, email, role, active)
    values (
      gen_random_uuid()::text,
      new.id,
      coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)),
      new.email,
      case when cnt = 0 then 'owner' else 'engineer' end,
      true
    );
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function nitaq_handle_new_user();

-- ============================================================
-- 5) سياسات RLS — nitaq_crm_profiles
-- ============================================================
drop policy if exists profiles_select on nitaq_crm_profiles;
create policy profiles_select on nitaq_crm_profiles for select
  using ( nitaq_is_active_user() );

drop policy if exists profiles_update_self on nitaq_crm_profiles;
create policy profiles_update_self on nitaq_crm_profiles for update
  using ( auth_user_id = auth.uid() )
  with check ( auth_user_id = auth.uid() );

drop policy if exists profiles_update_owner on nitaq_crm_profiles;
create policy profiles_update_owner on nitaq_crm_profiles for update
  using ( nitaq_my_role() = 'owner' )
  with check ( true );

drop policy if exists profiles_insert_owner on nitaq_crm_profiles;
create policy profiles_insert_owner on nitaq_crm_profiles for insert
  with check ( nitaq_my_role() = 'owner' );

-- ============================================================
-- 6) سياسات RLS — nitaq_crm_records
-- ============================================================

-- قراءة
drop policy if exists records_select on nitaq_crm_records;
create policy records_select on nitaq_crm_records for select
  using (
    nitaq_is_active_user() and (
      entity in ('client','settings')
      or nitaq_see_all()
      or (entity = 'lead' and (data->>'ownerId' = nitaq_my_profile_id() or data->>'engineerId' = nitaq_my_profile_id()))
      or (entity = 'audit' and data->>'byId' = nitaq_my_profile_id())
      or (entity = 'inter' and nitaq_lead_is_mine(data->>'leadId'))
    )
  );

-- إضافة
drop policy if exists records_insert on nitaq_crm_records;
create policy records_insert on nitaq_crm_records for insert
  with check (
    nitaq_is_active_user() and (
      entity in ('client','audit','inter')
      or (entity = 'lead')
      or (entity = 'settings' and (nitaq_my_role() = 'owner' or exists(
            select 1 from nitaq_crm_profiles where auth_user_id = auth.uid() and (perms->>'lookups')::boolean)))
    )
  );

-- تعديل
drop policy if exists records_update on nitaq_crm_records;
create policy records_update on nitaq_crm_records for update
  using (
    nitaq_is_active_user() and (
      entity = 'client'
      or nitaq_see_all()
      or (entity = 'lead' and (data->>'ownerId' = nitaq_my_profile_id() or data->>'engineerId' = nitaq_my_profile_id()))
      or (entity = 'settings' and (nitaq_my_role() = 'owner' or exists(
            select 1 from nitaq_crm_profiles where auth_user_id = auth.uid() and (perms->>'lookups')::boolean)))
    )
  )
  with check ( true );

-- حذف — يحتاج صلاحية "del" أو مالك (منطبق أساساً على الاسكتشات ومحادثاتها)
drop policy if exists records_delete on nitaq_crm_records;
create policy records_delete on nitaq_crm_records for delete
  using (
    nitaq_is_active_user() and (
      nitaq_my_role() = 'owner'
      or exists(select 1 from nitaq_crm_profiles where auth_user_id = auth.uid() and (perms->>'del')::boolean)
      or (entity = 'inter' and nitaq_lead_is_mine(data->>'leadId'))
    )
  );

-- ============================================================
-- 7) تفعيل الـRealtime على الجدولين (لازم يتعمل مرة واحدة — الكود ده آمن
--    حتى لو اتشغّل أكتر من مرة، مش هيدّي خطأ "already member")
-- ============================================================
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'nitaq_crm_records'
  ) then
    alter publication supabase_realtime add table nitaq_crm_records;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'nitaq_crm_profiles'
  ) then
    alter publication supabase_realtime add table nitaq_crm_profiles;
  end if;
end $$;

-- ============================================================
-- ملاحظات:
-- • أول شخص يعمل "إنشاء حساب" من داخل نطاق يبقى المالك تلقائياً.
-- • عشان تربط سجلات موظف موجود بالفعل (مثلاً "أحمد" أو "مروة" اللي كانوا بالنظام القديم)
--   بحساب دخول حقيقي، يعمل المالك من شاشة "المستخدمون" دعوة بإيميل الموظف، وأول ما
--   الموظف يعمل "إنشاء حساب" بنفس الإيميل، هيتربط تلقائياً بنفس البروفايل القديم
--   وكل سجلاته القديمة (كمسؤول أو مهندس) تفضل زي ما هي.
-- ============================================================
