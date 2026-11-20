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
