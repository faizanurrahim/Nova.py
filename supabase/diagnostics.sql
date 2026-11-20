-- Read-only inspection queries for the live NovaNX Supabase project.

select
  column_name,
  data_type,
  udt_name,
  is_nullable,
  column_default
from information_schema.columns
where table_schema = 'public'
  and table_name = 'profiles'
order by ordinal_position;

select
  tc.constraint_name,
  tc.constraint_type,
  kcu.column_name,
  ccu.table_schema as referenced_schema,
  ccu.table_name as referenced_table,
  ccu.column_name as referenced_column,
  rc.delete_rule
from information_schema.table_constraints tc
left join information_schema.key_column_usage kcu
  on kcu.constraint_catalog = tc.constraint_catalog
  and kcu.constraint_schema = tc.constraint_schema
  and kcu.constraint_name = tc.constraint_name
  and kcu.table_name = tc.table_name
left join information_schema.constraint_column_usage ccu
  on ccu.constraint_catalog = tc.constraint_catalog
  and ccu.constraint_schema = tc.constraint_schema
  and ccu.constraint_name = tc.constraint_name
left join information_schema.referential_constraints rc
  on rc.constraint_catalog = tc.constraint_catalog
  and rc.constraint_schema = tc.constraint_schema
  and rc.constraint_name = tc.constraint_name
where tc.table_schema = 'public'
  and tc.table_name = 'profiles'
order by tc.constraint_type, tc.constraint_name;

select
  con.conname as constraint_name,
  con.contype as constraint_type,
  pg_get_constraintdef(con.oid) as definition
from pg_constraint con
where con.conrelid = 'public.profiles'::regclass
order by con.contype, con.conname;

select
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced,
  pg_get_userbyid(c.relowner) as table_owner
from pg_class c
where c.oid = 'public.profiles'::regclass;

select *
from pg_policies
where schemaname = 'public'
  and tablename = 'profiles'
order by policyname;

select
  role_name,
  has_table_privilege(role_name, 'public.profiles', 'SELECT') as can_select,
  has_table_privilege(role_name, 'public.profiles', 'INSERT') as can_insert,
  has_table_privilege(role_name, 'public.profiles', 'UPDATE') as can_update,
  has_table_privilege(role_name, 'public.profiles', 'DELETE') as can_delete
from unnest(array['anon', 'authenticated', 'service_role', 'postgres']) as roles(role_name)
order by role_name;

select
  t.tgname as trigger_name,
  pg_get_triggerdef(t.oid) as trigger_definition,
  p.proname as function_name,
  pg_get_userbyid(p.proowner) as function_owner,
  p.prosecdef as security_definer,
  p.proconfig as function_settings,
  has_function_privilege('supabase_auth_admin', p.oid, 'EXECUTE') as auth_admin_can_execute,
  pg_get_functiondef(p.oid) as function_definition
from pg_trigger t
join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
join pg_proc p on p.oid = t.tgfoid
where n.nspname = 'auth'
  and c.relname = 'users'
  and not t.tgisinternal
order by t.tgname;

select
  count(*) as auth_user_count,
  count(p.id) as profile_count,
  count(*) filter (where p.id is null) as auth_users_missing_profiles
from auth.users u
left join public.profiles p on p.id = u.id;
