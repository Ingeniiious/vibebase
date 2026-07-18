-- Run by supautils (as superuser) right after any role enables pgmq.
-- pgmq functions are SECURITY INVOKER and pgmq.create() makes tables inside
-- the pgmq schema, so the non-superuser <db>_app role needs usage + create
-- there and access to the pgmq meta tables.
do $$
declare
  app_role text := current_database() || '_app';
begin
  if exists (select 1 from pg_roles where rolname = app_role) then
    execute format('grant usage, create on schema pgmq to %I', app_role);
    execute format('grant select, insert, update, delete on all tables in schema pgmq to %I', app_role);
    execute format('grant usage, select on all sequences in schema pgmq to %I', app_role);
  end if;
end
$$;
