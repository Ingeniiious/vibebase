-- Run by supautils (as superuser) right after any role enables pg_cron.
-- The studio + apps connect as <db>_app (never superuser), so grant them
-- the cron schema; pg_cron's own RLS still limits rows to the job owner.
do $$
declare
  app_role text := current_database() || '_app';
begin
  if exists (select 1 from pg_roles where rolname = app_role) then
    execute format('grant usage on schema cron to %I', app_role);
    execute format('grant select, insert, update, delete on all tables in schema cron to %I', app_role);
  end if;
end
$$;
