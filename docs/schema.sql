-- BookHaven: схема базы и правила доступа (этап 1)
-- Выполнять целиком, один раз, в пустом проекте.

-- ===== Таблицы =====

-- Профиль каждого пользователя (создаётся автоматически при регистрации)
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null default '' check (char_length(name) <= 30),
  about       text not null default '' check (char_length(about) <= 300),
  avatar      text not null default '👤',
  color       text not null default '#245A7A' check (color ~ '^#[0-9A-Fa-f]{6}$'),
  photo       text not null default '',
  genres      text[] not null default '{}',
  fav_book    text not null default '',
  goal        int  not null default 0 check (goal between 0 and 500),
  role        text not null default 'user' check (role in ('user', 'admin')),
  created_at  timestamptz not null default now()
);

-- Книги каталога (наполнение каталога — отдельным шагом)
create table public.books (
  id          bigserial primary key,
  title       text not null unique,
  author      text not null default '',
  genre       text not null default '',
  pages       int  not null default 0,
  description text not null default ''
);

-- Отзывы и оценки: одна книга — один отзыв на пользователя
create table public.reviews (
  id          bigserial primary key,
  book_id     bigint not null references public.books(id) on delete cascade,
  user_id     uuid   not null references public.profiles(id) on delete cascade,
  rating      int    not null check (rating between 1 and 5),
  text        text   not null check (char_length(text) between 1 and 2000),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (book_id, user_id)
);

-- Тексты, которые пользователи загрузили сами (сам файл — в Storage, отдельным шагом)
create table public.user_texts (
  id          bigserial primary key,
  user_id     uuid not null references public.profiles(id) on delete cascade,
  book_id     bigint references public.books(id) on delete set null,
  title       text not null check (char_length(title) between 1 and 200),
  file_path   text not null default '',
  words       int  not null default 0,
  created_at  timestamptz not null default now()
);

-- Позиция чтения
create table public.read_progress (
  user_id     uuid   not null references public.profiles(id) on delete cascade,
  book_id     bigint not null references public.books(id) on delete cascade,
  position    numeric not null default 0,
  updated_at  timestamptz not null default now(),
  primary key (user_id, book_id)
);

-- Список прочитанных книг (для счётчика в профиле)
create table public.read_list (
  user_id     uuid   not null references public.profiles(id) on delete cascade,
  book_id     bigint not null references public.books(id) on delete cascade,
  read_at     timestamptz not null default now(),
  primary key (user_id, book_id)
);

-- ===== Вспомогательные функции =====

-- Проверка роли администратора для текущего пользователя
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and role = 'admin'
  );
$$;

-- При регистрации создаём профиль с ролью user
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, name)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', ''));
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Запрещаем менять роль кому-либо, кроме администратора.
-- В SQL Editor auth.uid() пустой, поэтому первого администратора можно назначить вручную.
create or replace function public.protect_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.role is distinct from old.role
     and auth.uid() is not null
     and not public.is_admin() then
    raise exception 'Менять роль может только администратор';
  end if;
  return new;
end;
$$;

create trigger profiles_protect_role
  before update on public.profiles
  for each row execute function public.protect_role();

-- ===== Публичный профиль: только безопасные поля =====
-- Имя, аватар и цвет видны всем; «о себе», цель и жанры — только владельцу и администратору.
create view public.public_profiles as
  select id, name, avatar, color, photo from public.profiles;

grant select on public.public_profiles to authenticated;

-- ===== Правила доступа (RLS) =====

alter table public.profiles       enable row level security;
alter table public.books          enable row level security;
alter table public.reviews        enable row level security;
alter table public.user_texts     enable row level security;
alter table public.read_progress  enable row level security;
alter table public.read_list      enable row level security;

-- profiles: свой профиль или администратор
create policy "profiles: читает свой или админ" on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
create policy "profiles: меняет свой или админ" on public.profiles
  for update to authenticated using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());

-- books: читают все вошедшие, меняет только админ
create policy "books: читают вошедшие" on public.books
  for select to authenticated using (true);
create policy "books: меняет админ" on public.books
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- reviews: читают все вошедшие; создаёт и меняет автор; удалять может автор или админ
create policy "reviews: читают вошедшие" on public.reviews
  for select to authenticated using (true);
create policy "reviews: создаёт свой" on public.reviews
  for insert to authenticated with check (user_id = auth.uid());
create policy "reviews: меняет свой или админ" on public.reviews
  for update to authenticated
  using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());
create policy "reviews: удаляет свой или админ" on public.reviews
  for delete to authenticated using (user_id = auth.uid() or public.is_admin());

-- user_texts: видит владелец и админ
create policy "user_texts: видит свои или админ" on public.user_texts
  for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "user_texts: создаёт свой" on public.user_texts
  for insert to authenticated with check (user_id = auth.uid());
create policy "user_texts: удаляет свой или админ" on public.user_texts
  for delete to authenticated using (user_id = auth.uid() or public.is_admin());

-- read_progress и read_list: только владелец
create policy "read_progress: только свой" on public.read_progress
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "read_list: только свой" on public.read_list
  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Гости (не вошедшие) не получают доступа ни к одной таблице:
-- политики выше даны только роли authenticated.

-- ===== Дата изменения отзыва (этап 3) =====
-- При любом изменении отзыва база сама ставит updated_at.
create or replace function public.touch_review()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger reviews_touch
  before update on public.reviews
  for each row execute function public.touch_review();

-- ===== Тексты пользователей в хранилище (этап 6) =====

-- Один текст на название у пользователя; пользователь может менять свой текст
alter table public.user_texts add constraint user_texts_user_title_key unique (user_id, title);

create policy "user_texts: меняет свой" on public.user_texts
  for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Закрытое хранилище для файлов с текстами. Папка = id пользователя.
insert into storage.buckets (id, name, public, file_size_limit)
values ('user-texts', 'user-texts', false, 10485760)
on conflict (id) do nothing;

create policy "texts: загружает в свою папку" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'user-texts' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "texts: читает свои или админ" on storage.objects
  for select to authenticated
  using (bucket_id = 'user-texts' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

create policy "texts: удаляет свои или админ" on storage.objects
  for delete to authenticated
  using (bucket_id = 'user-texts' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

-- ===== Статистика из базы (этап 7) =====

-- Посещения: одна запись при каждой загрузке страницы вошедшим пользователем
create table public.visits (
  id          bigserial primary key,
  user_id     uuid references public.profiles(id) on delete set null,
  created_at  timestamptz not null default now()
);

alter table public.visits enable row level security;

create policy "visits: записывает свой визит" on public.visits
  for insert to authenticated with check (user_id = auth.uid());

create policy "visits: читает админ" on public.visits
  for select to authenticated using (public.is_admin());

-- Сводка для администратора: посещения и отметки «прочитано» всех пользователей
create or replace function public.admin_stats()
returns json
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'Только для администратора';
  end if;
  return json_build_object(
    'visits', (select count(*) from public.visits),
    'reads', (select count(*) from public.read_list)
  );
end;
$$;

revoke execute on function public.admin_stats() from anon;
grant execute on function public.admin_stats() to authenticated;

-- ===== Изменение 2: гости читают, тексты книг загружает только администратор =====

-- Гости читают каталог, отзывы и публичные имена. Писать могут только вошедшие.
create policy "books: читают гости" on public.books
  for select to anon using (true);
create policy "reviews: читают гости" on public.reviews
  for select to anon using (true);
grant select on public.public_profiles to anon;

-- Общие тексты книг: читают все, загружает и меняет только администратор
create table public.book_texts (
  book_id     bigint primary key references public.books(id) on delete cascade,
  file_path   text not null,
  words       int  not null default 0,
  updated_at  timestamptz not null default now()
);
alter table public.book_texts enable row level security;
create policy "book_texts: читают все" on public.book_texts
  for select to anon, authenticated using (true);
create policy "book_texts: меняет админ" on public.book_texts
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

insert into storage.buckets (id, name, public, file_size_limit)
values ('book-texts', 'book-texts', false, 10485760)
on conflict (id) do nothing;
create policy "book-texts: читают все" on storage.objects
  for select to anon, authenticated using (bucket_id = 'book-texts');
create policy "book-texts: загружает админ" on storage.objects
  for insert to authenticated with check (bucket_id = 'book-texts' and public.is_admin());
create policy "book-texts: меняет админ" on storage.objects
  for update to authenticated using (bucket_id = 'book-texts' and public.is_admin());
create policy "book-texts: удаляет админ" on storage.objects
  for delete to authenticated using (bucket_id = 'book-texts' and public.is_admin());

-- Личные тексты пользователей больше не создаются: только администратор
drop policy "user_texts: создаёт свой" on public.user_texts;
create policy "user_texts: создаёт админ" on public.user_texts
  for insert to authenticated with check (user_id = auth.uid() and public.is_admin());
drop policy "texts: загружает в свою папку" on storage.objects;
create policy "texts: загружает админ" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'user-texts' and public.is_admin());
