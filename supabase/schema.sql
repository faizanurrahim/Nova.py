create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9][a-z0-9_-]{2,29}$'),
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.packages (
  id uuid primary key default gen_random_uuid(),
  name text not null unique check (name ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
  description text not null default '' check (char_length(description) <= 500),
  owner_id uuid not null references public.profiles (id) on delete restrict,
  repository_url text not null default '',
  homepage_url text not null default '',
  is_deprecated boolean not null default false,
  download_count bigint not null default 0 check (download_count >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.package_versions (
  id uuid primary key default gen_random_uuid(),
  package_id uuid not null references public.packages (id) on delete cascade,
  version text not null check (version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'),
  archive_path text not null unique,
  checksum text not null check (checksum ~ '^[a-f0-9]{64}$'),
  readme text not null default '',
  license text not null default '',
  requires_nexa text not null default '',
  python_requires text not null default '',
  dependencies jsonb not null default '{}'::jsonb
    check (jsonb_typeof(dependencies) in ('object', 'array')),
  created_at timestamptz not null default now(),
  unique (package_id, version)
);

create table if not exists public.package_downloads (
  id uuid primary key default gen_random_uuid(),
  package_id uuid not null references public.packages (id) on delete cascade,
  version_id uuid not null references public.package_versions (id) on delete cascade,
  downloaded_at timestamptz not null default now()
);

create table if not exists public.package_maintainers (
  id uuid primary key default gen_random_uuid(),
  package_id uuid not null references public.packages (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  permission text not null check (permission in ('read', 'publish', 'manage')),
  created_at timestamptz not null default now(),
  unique (package_id, user_id)
);

create index if not exists package_versions_package_created_idx
  on public.package_versions (package_id, created_at desc);
create index if not exists package_downloads_package_idx
  on public.package_downloads (package_id, downloaded_at desc);
create index if not exists package_maintainers_user_idx
  on public.package_maintainers (user_id, package_id);

grant usage on schema public to anon, authenticated, service_role;
grant select on public.profiles, public.packages, public.package_versions
  to anon, authenticated;
grant insert, update on public.profiles to authenticated;
grant insert, update, delete on public.packages, public.package_versions
  to authenticated;
grant select, insert, delete on public.package_maintainers to authenticated;
grant select on public.package_downloads to authenticated;
grant all on public.profiles, public.packages, public.package_versions,
  public.package_downloads, public.package_maintainers to service_role;

create or replace function public.novanx_search_packages(
  search_text text default '',
  sort_order text default 'relevance',
  result_limit integer default 100
)
returns setof public.packages
language sql
stable
set search_path = ''
as $$
  select p.*
  from public.packages p
  where not p.is_deprecated
    and (
      coalesce(search_text, '') = ''
      or p.name ilike '%' || search_text || '%'
      or p.description ilike '%' || search_text || '%'
      or exists (
        select 1 from public.profiles pr
        where pr.id = p.owner_id and pr.username ilike '%' || search_text || '%'
      )
    )
  order by
    case when sort_order = 'relevance' and lower(p.name) = lower(search_text) then 0
         when sort_order = 'relevance' and lower(p.name) like lower(search_text) || '%' then 1
         else 2 end,
    case when sort_order = 'popular' then p.download_count end desc nulls last,
    case when sort_order = 'newest' then p.created_at end desc nulls last,
    p.download_count desc,
    p.created_at desc
  limit greatest(1, least(coalesce(result_limit, 100), 500));
$$;

create or replace function public.novanx_registry_stats()
returns table (package_count bigint, download_count bigint, author_count bigint)
language sql
stable
set search_path = ''
as $$
  select count(*), coalesce(sum(p.download_count), 0)::bigint, count(distinct p.owner_id)
  from public.packages p
  where not p.is_deprecated;
$$;
grant execute on function public.novanx_search_packages(text, text, integer)
  to anon, authenticated, service_role;
grant execute on function public.novanx_registry_stats()
  to anon, authenticated, service_role;

create or replace function public.novanx_create_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_username text;
  safe_username text;
  error_sqlstate text;
  error_message text;
  error_constraint text;
  error_context text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null or btrim(requested_username) = '' then
    raise exception 'NovaNX signup requires raw_user_meta_data.username'
      using errcode = '22023';
  end if;
  requested_username := lower(btrim(requested_username));
  safe_username := left(regexp_replace(requested_username, '[^a-z0-9_-]', '-', 'g'), 30);
  if safe_username is null or safe_username !~ '^[a-z0-9][a-z0-9_-]{2,29}$' then
    raise exception 'NovaNX signup metadata username is invalid'
      using errcode = '22023';
  end if;
  insert into public.profiles (id, username)
  values (new.id, safe_username)
  on conflict (id) do nothing;
  return new;
exception
  when others then
    get stacked diagnostics
      error_sqlstate = returned_sqlstate,
      error_message = message_text,
      error_constraint = constraint_name,
      error_context = pg_exception_context;
    raise warning
      'NovaNX profile trigger failed: operation=%, schema=%, table=%, trigger=%, function=public.novanx_create_profile, sqlstate=%, message=%, constraint=%, context=%',
      tg_op,
      tg_table_schema,
      tg_table_name,
      tg_name,
      error_sqlstate,
      error_message,
      error_constraint,
      error_context;
    raise;
end;
$$;
alter function public.novanx_create_profile() owner to postgres;

drop trigger if exists on_auth_user_created_novanx on auth.users;
create trigger on_auth_user_created_novanx
  after insert on auth.users
  for each row execute procedure public.novanx_create_profile();

create or replace function public.novanx_touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists packages_touch_updated_at on public.packages;
create trigger packages_touch_updated_at
  before update on public.packages
  for each row execute procedure public.novanx_touch_updated_at();

create or replace function public.novanx_count_download()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.packages
  set download_count = download_count + 1
  where id = new.package_id;
  return new;
end;
$$;

drop trigger if exists package_downloads_increment_count on public.package_downloads;
create trigger package_downloads_increment_count
  after insert on public.package_downloads
  for each row execute procedure public.novanx_count_download();

alter table public.profiles enable row level security;
alter table public.packages enable row level security;
alter table public.package_versions enable row level security;
alter table public.package_downloads enable row level security;
alter table public.package_maintainers enable row level security;

drop policy if exists "Profiles are publicly readable" on public.profiles;
create policy "Profiles are publicly readable" on public.profiles
  for select using (true);
drop policy if exists "Users create their own profile" on public.profiles;
create policy "Users create their own profile" on public.profiles
  for insert to authenticated with check (id = (select auth.uid()));
drop policy if exists "Users update their own profile" on public.profiles;
create policy "Users update their own profile" on public.profiles
  for update to authenticated using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

drop policy if exists "Packages are publicly readable" on public.packages;
create policy "Packages are publicly readable" on public.packages
  for select using (true);
drop policy if exists "Owners create packages" on public.packages;
create policy "Owners create packages" on public.packages
  for insert to authenticated with check (owner_id = (select auth.uid()));
drop policy if exists "Owners and managers update packages" on public.packages;
create policy "Owners and managers update packages" on public.packages
  for update to authenticated
  using (
    owner_id = (select auth.uid())
    or exists (
      select 1 from public.package_maintainers pm
      where pm.package_id = packages.id and pm.user_id = (select auth.uid())
        and pm.permission = 'manage'
    )
  )
  with check (
    owner_id = (select auth.uid())
    or exists (
      select 1 from public.package_maintainers pm
      where pm.package_id = packages.id and pm.user_id = (select auth.uid())
        and pm.permission = 'manage'
    )
  );
drop policy if exists "Owners delete packages" on public.packages;
create policy "Owners delete packages" on public.packages
  for delete to authenticated using (owner_id = (select auth.uid()));

drop policy if exists "Package versions are publicly readable" on public.package_versions;
create policy "Package versions are publicly readable" on public.package_versions
  for select using (true);
drop policy if exists "Owners and publishers create versions" on public.package_versions;
create policy "Owners and publishers create versions" on public.package_versions
  for insert to authenticated with check (
    exists (
      select 1 from public.packages p
      where p.id = package_id and (
        p.owner_id = (select auth.uid())
        or exists (
          select 1 from public.package_maintainers pm
          where pm.package_id = p.id and pm.user_id = (select auth.uid())
            and pm.permission in ('publish', 'manage')
        )
      )
    )
  );
drop policy if exists "Owners and managers update versions" on public.package_versions;
create policy "Owners and managers update versions" on public.package_versions
  for update to authenticated using (
    exists (
      select 1 from public.packages p
      where p.id = package_id and (
        p.owner_id = (select auth.uid())
        or exists (
          select 1 from public.package_maintainers pm
          where pm.package_id = p.id and pm.user_id = (select auth.uid())
            and pm.permission = 'manage'
        )
      )
    )
  );
drop policy if exists "Owners delete versions" on public.package_versions;
create policy "Owners delete versions" on public.package_versions
  for delete to authenticated using (
    exists (
      select 1 from public.packages p
      where p.id = package_id and p.owner_id = (select auth.uid())
    )
  );

drop policy if exists "Package owners and maintainers view maintainers" on public.package_maintainers;
create policy "Package owners and maintainers view maintainers" on public.package_maintainers
  for select to authenticated using (
    user_id = (select auth.uid())
    or exists (
      select 1 from public.packages p
      where p.id = package_id and p.owner_id = (select auth.uid())
    )
  );
drop policy if exists "Owners add maintainers" on public.package_maintainers;
create policy "Owners add maintainers" on public.package_maintainers
  for insert to authenticated with check (
    exists (
      select 1 from public.packages p
      where p.id = package_id and p.owner_id = (select auth.uid())
    )
  );
drop policy if exists "Owners remove maintainers" on public.package_maintainers;
create policy "Owners remove maintainers" on public.package_maintainers
  for delete to authenticated using (
    exists (
      select 1 from public.packages p
      where p.id = package_id and p.owner_id = (select auth.uid())
    )
  );

drop policy if exists "Downloads are private to package owners" on public.package_downloads;
create policy "Downloads are private to package owners" on public.package_downloads
  for select to authenticated using (
    exists (
      select 1 from public.packages p
      where p.id = package_id and p.owner_id = (select auth.uid())
    )
  );

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('novanx-packages', 'novanx-packages', false, 25165824, array['application/octet-stream', 'application/x-tar'])
on conflict (id) do update
set public = false, file_size_limit = 25165824;
