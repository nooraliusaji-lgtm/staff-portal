-- Run this once in Supabase SQL Editor to add reversible staff deactivation.
alter table public.profiles
  add column if not exists is_active boolean not null default true,
  add column if not exists deactivated_at timestamptz,
  add column if not exists deactivated_by uuid references public.profiles(id);

create or replace function public.is_portal_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id=(select auth.uid()) and role='super_admin' and is_active);
$$;

create or replace function public.is_department_supervisor(target_department uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id=(select auth.uid()) and role='supervisor' and is_active and department_id=target_department);
$$;

create or replace function public.can_view_task(target_task uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id=(select auth.uid()) and is_active)
    and (public.is_portal_admin() or exists (
      select 1 from public.tasks t join public.profiles assignee on assignee.id=t.assigned_to
      where t.id=target_task and assignee.is_active
        and (t.assigned_to=(select auth.uid()) or public.is_department_supervisor(assignee.department_id))
    ));
$$;

create or replace function public.can_manage_profile(target_user uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select target_user <> (select auth.uid()) and exists (
    select 1 from public.profiles me join public.profiles target on target.id=target_user
    where me.id=(select auth.uid()) and me.is_active and target.role <> 'super_admin'
      and (me.role='super_admin' or (me.role='supervisor' and target.role='staff' and me.department_id is not null and me.department_id=target.department_id))
  );
$$;

create or replace function public.set_profile_active(target_user uuid, make_active boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.can_manage_profile(target_user) then raise exception 'You do not have permission to change this account.'; end if;
  update public.profiles set is_active=make_active,
    deactivated_at=case when make_active then null else now() end,
    deactivated_by=case when make_active then null else (select auth.uid()) end
  where id=target_user;
end;
$$;
revoke all on function public.set_profile_active(uuid, boolean) from public, anon;
grant execute on function public.set_profile_active(uuid, boolean) to authenticated;

-- A signed-in inactive person can see their own status row, but cannot access team/task data.
drop policy if exists "task read by role and department" on public.tasks;
create policy "task read by role and department" on public.tasks
  for select to authenticated using (public.can_view_task(id));
drop policy if exists "admin supervisor or assignee update task" on public.tasks;
create policy "admin supervisor or assignee update task" on public.tasks
  for update to authenticated using (public.can_view_task(id)) with check (public.can_view_task(id));
drop policy if exists "profile read by department" on public.profiles;
create policy "profile read by department" on public.profiles for select to authenticated
  using (id=(select auth.uid()) or public.is_portal_admin() or (department_id is not null and public.is_department_supervisor(department_id) and role='staff'));

-- Keep all task/comment history. Deactivation blocks access and assignment but does not erase records.
