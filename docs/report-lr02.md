# Звіт WEB ЛР 2

Валідація вхідних даних і захист пошуку від SQL-ін'єкції (SecureLab, варіант 2-A).

## 1. Ідентифікація

- ПІБ і група: Шуплик Андрій Олександрович, КБ-41.
- Спільний baseline 2-A; індивідуального номера немає.
- Заявлений рівень: відмінний («Відмінно»).
- Гілка lab/2-input-sqli, створена від тегу v0.1.0 ([Рис. 2](evidence/fig-02.png)).
- Release: lab-02-start-v1. base_commit і entry_parent: `bc735f62e11a19a99191a787e394864c02c5d5b8` ([Рис. 6](evidence/fig-06.png)).
- Vulnerable commit: `5d7d582c86fb2b06196919d8b3beeabce217c6b1` ([Рис. 39](evidence/fig-39.png)). Fixed commit коду: `0418118a6a78618a5889e442a182f1b7fcc866d2` ([Рис. 56](evidence/fig-56.png), [Рис. 57](evidence/fig-57.png)). Тег v0.2.0 стоїть на commit із цим звітом.
- DEL-01: приватний репозиторій https://github.com/AndriiShuplik/Lab1_Shuplik, гілка lab/2-input-sqli.

## 2. Контракт і CP-01

POST /api/incidents перевіряється на сервері, усі помилки збираються в один словник і повертаються як Validation Problem Details до звернення до бази даних.

| Поле | Правило |
|---|---|
| title | обов'язкове; після Trim() не довше 160 символів |
| description | обов'язкове; не довше 4000 символів; для High і Critical не коротше 40 (T-09) |
| severity | Enum.TryParse разом з Enum.IsDefined; рядок «7» відхиляється (CP-01) |
| occurredAtUtc | обов'язкове; не в майбутньому (допуск 5 хвилин); не раніше ніж 365 днів тому (T-10); зміщення зберігається як UTC |
| дубль заголовка (T-03) | той самий title серед інцидентів не в статусі Closed дає 409 без errors |
| серверні поля | id, ownerUserId, status, createdAtUtc задає лише сервер (A-02) |
| відповідь | 201 Created, заголовок Location, CreatedIncidentResponse без внутрішніх полів |

Код контракту: [Рис. 13](evidence/fig-13.png). Release-збірка: [Рис. 14](evidence/fig-14.png). CP-01: [Рис. 17](evidence/fig-17.png).

## 3. Security-сценарій і CP-02/CP-03

1. **Контекст.** Пошук GET /api/incidents/search у Lab02Endpoints.cs; усі сценарії виконані локально, на навчальних даних, лише для читання.
2. **Стан до.** Звичайний пошук і порожній результат працюють ([Рис. 28](evidence/fig-28.png), [Рис. 29](evidence/fig-29.png)), тести на vulnerable commit проходять ([Рис. 37](evidence/fig-37.png)).
3. **Дозволений сценарій.** Запити A–D із методики: звичайний, значення якого немає, єдиний дозволений контрольний ввід і легітимний апостроф ([Рис. 28](evidence/fig-28.png), [Рис. 29](evidence/fig-29.png), [Рис. 30](evidence/fig-30.png), [Рис. 31](evidence/fig-31.png)).
4. **Спостереження.** Контрольний ввід повертає всі записи таблиці замість порожнього результату, апостроф у слові дає 500 без внутрішніх деталей. У журналі Parameters=[] ([Рис. 33](evidence/fig-33.png), [Рис. 34](evidence/fig-34.png), [Рис. 35](evidence/fig-35.png)).
5. **Першопричина.** Обробник у Lab02Endpoints.cs: sortBy без перевірки потрапляє в order (рядки 13 до 17), q і order склеюються в текст запиту (рядки 18 і 19), його виконує FromSqlRaw (рядок 20) ([Рис. 36](evidence/fig-36.png)).
6. **Різниця виправлення.** LINQ з EF.Functions.ILike і ESCAPE, значення q іде параметром, EscapeLike робить \\, % і _ буквальними; sortBy працює через allowlist з трьох виразів OrderBy, невідоме значення дає 400; другий ключ Id і Take(50) ([Рис. 40](evidence/fig-40.png), [Рис. 41](evidence/fig-41.png)). Різниця між станами: [Рис. 56](evidence/fig-56.png), [Рис. 57](evidence/fig-57.png).
7. **Повторний сценарій.** Запити A і B дають той самий результат, контрольний ввід більше не розширює вибірку (200 і []), у журналі значення передані параметрами @pattern і @pattern0 ([Рис. 43](evidence/fig-43.png), [Рис. 44](evidence/fig-44.png), [Рис. 45](evidence/fig-45.png), [Рис. 53](evidence/fig-53.png)).
8. **Позитивний сценарій.** Апостроф у O'Brien і «комп'ютерного» знаходить по одному запису, % шукається буквально, невідомий sortBy дає 400, сортування за severity, status і за замовчуванням працює за рангами ([Рис. 46](evidence/fig-46.png), [Рис. 47](evidence/fig-47.png), [Рис. 48](evidence/fig-48.png), [Рис. 49](evidence/fig-49.png), [Рис. 50](evidence/fig-50.png), [Рис. 51](evidence/fig-51.png), [Рис. 52](evidence/fig-52.png)).

## 4. Фактичні перевірки DEL-02

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректне створення | після --reset-database | POST із коректним DTO | 201, Location, title без пробілів, status New | Збіглося | [Рис. 15](evidence/fig-15.png) |
| T-02 | Некоректний DTO | після --reset-database | POST із некоректними title, description і датою | 400, помилки title, description, occurredAtUtc | Збіглося; автотест | [Рис. 16](evidence/fig-16.png), [Рис. 54](evidence/fig-54.png) |
| CP-01 | severity = «7» | після --reset-database | POST із severity «7» | 400, ключ severity | Збіглося | [Рис. 17](evidence/fig-17.png) |
| T-02 (дата) | Відсутній occurredAtUtc | після --reset-database | POST без occurredAtUtc | 400, ключ occurredAtUtc | Збіглося | [Рис. 18](evidence/fig-18.png) |
| T-09 | High, 39 і 40 символів | після --reset-database | POST із High: опис у 39 і 40 символів | 39 дає 400, 40 дає 201 | Збіглося | [Рис. 19](evidence/fig-19.png), [Рис. 20](evidence/fig-20.png) |
| T-03 | Дубль активного заголовка | активний інцидент із таким title уже є | POST із тим самим title | 409 без errors | Збіглося | [Рис. 21](evidence/fig-21.png) |
| T-10 | Межа 365 днів | після --reset-database | POST із датами 2025-01-01 і 2026-09-01 | 2025-01-01 дає 400; 2026-09-01 дає 201 | Збіглося | [Рис. 22](evidence/fig-22.png), [Рис. 23](evidence/fig-23.png) |
| A-02 | Зайві серверні поля | після --reset-database | POST із зайвими id, ownerUserId, status, createdAtUtc, потім GET запису | 201; новий id, New, власник Alice | Збіглося | [Рис. 24](evidence/fig-24.png), [Рис. 25](evidence/fig-25.png) |
| T-06 | Неіснуючий інцидент | після --reset-database | GET за неіснуючим id | 404 Problem Details | Збіглося | [Рис. 26](evidence/fig-26.png) |
| UTC | Зміщення +03:00 | після --reset-database | POST із occurredAtUtc зі зміщенням +03:00 | occurredAtUtc у UTC (10:00) | Збіглося | [Рис. 27](evidence/fig-27.png) |
| S-01 | Пошук на vulnerable commit | vulnerable commit, seed після reset | запити A–D до /api/incidents/search | дефект відтворюється: розширення вибірки і 500 на апостроф | Відтворено | [Рис. 28](evidence/fig-28.png), [Рис. 29](evidence/fig-29.png), [Рис. 30](evidence/fig-30.png), [Рис. 31](evidence/fig-31.png), [Рис. 32](evidence/fig-32.png), [Рис. 33](evidence/fig-33.png), [Рис. 34](evidence/fig-34.png), [Рис. 35](evidence/fig-35.png), [Рис. 36](evidence/fig-36.png) |
| S-02 | Контрольний ввід після виправлення | fixed commit, seed після reset | пошук із контрольним вводом; автотест | 200 і [] | Збіглося; автотест з множиною id | [Рис. 45](evidence/fig-45.png), [Рис. 54](evidence/fig-54.png) |
| T-04 | Апостроф у пошуку | fixed commit | пошук за O'Brien і «комп'ютерного» | 200, один очікуваний запис | Збіглося | [Рис. 46](evidence/fig-46.png), [Рис. 47](evidence/fig-47.png) |
| T-05 | Невідомий sortBy | fixed commit | пошук із невідомим sortBy | 400, ключ sortBy | Збіглося | [Рис. 49](evidence/fig-49.png) |
| Сорт. | severity, status, за замовчуванням | fixed commit | пошук із sortBy за severity, status і без sortBy | порядок за рангами; рівні значення за Id | Збіглося | [Рис. 50](evidence/fig-50.png), [Рис. 51](evidence/fig-51.png), [Рис. 52](evidence/fig-52.png) |
| A-01 | Огляд доступу до БД | vulnerable і fixed commit | git grep і data-access-scan.py по src і tests | єдине raw-місце службове; пошук без raw SQL | Збіглося | [Рис. 38](evidence/fig-38.png), [Рис. 55](evidence/fig-55.png) |
| A-02 (чутливість) | Тимчасова зміна DTO | fixed commit | додати Status у request DTO і запустити тести | тест падає | Упав (Expected «New», Actual «Closed») | [Рис. 58](evidence/fig-58.png), [Рис. 59](evidence/fig-59.png) |

Release-збірка після останньої зміни пройшла без помилок ([Рис. 42](evidence/fig-42.png)). dotnet test: 28 тестів, 0 збоїв ([Рис. 54](evidence/fig-54.png); після git restore [Рис. 59](evidence/fig-59.png)). На старті baseline містив 5 тестів ([Рис. 8](evidence/fig-08.png)).

### A-01. Огляд усіх точок доступу до бази даних

| Файл / метод | Категорія | Висновок |
|---|---|---|
| Data/DatabaseBootstrap.cs, ExecuteSqlRawAsync | raw SQL | єдине raw-місце: константний TRUNCATE із фіксованими іменами таблиць; виконується лише за --reset-database у Development за Database:AllowReset |
| Scaffolding/Lab02Endpoints.cs, пошук | LINQ + EF.Functions.ILike | параметризований запит, sortBy через allowlist |
| Scaffolding/Lab02Endpoints.cs, перевірка дубля й створення | LINQ AnyAsync, Add + SaveChanges | параметризовано; серверні поля задає сервер |
| Application/Incidents/IncidentQueries.cs | LINQ | запити лише для читання без введення в тексті SQL |
| Scaffolding/Lab02Seed.cs, Data/DbSeeder.cs | EF seed | статичні навчальні дані |
| Program.cs, /health | CanConnectAsync | без SQL із введенням користувача |
| Data/DatabaseBootstrap.cs, MigrateAsync | міграції | службова операція при старті |
| SecureLabDbContext, DesignTimeDbContextFactory, Migrations | інфраструктура | не точки обробки запитів |

Докази огляду: [Рис. 38](evidence/fig-38.png), [Рис. 55](evidence/fig-55.png).

## 5. Обмеження і висновок

Перевірено контракт створення (поля, довжини, enum, дата й UTC, відповіді 400, 409 і 201), дефект пошуку на vulnerable commit у режимі лише читання, виправлення та регресію (HTTP-сценарії й 28 автоматичних тестів).

Обмеження: перевірка дубліката через AnyAsync виконується окремо від вставки, тому за паралельних створень з однаковим заголовком можливі два активні записи; надійне рішення потребує унікального індексу в базі даних. Помилки читання некоректного JSON окремо не досліджувалися. Дати у сценаріях розраховані на запуск у листопаді 2026; для пізнішого запуску допустимі дати треба зсунути.

Головне, що я з'ясував: дані користувача не можна склеювати з текстом SQL, а правила валідації мають працювати на сервері незалежно від клієнта. Я виправив саму причину, а не окремий прояв, і підтвердив це тестами та дослідом чутливості.

## 6. Декларація використання ШІ

| Сервіс | Задачі | Авторська адаптація/інтерпретація | Фактична перевірка |
|---|---|---|---|
| Claude (Anthropic) | перевірка звіту на відповідність вимогам методики ЛР 2, пошук неточностей, редагування формулювань | сам вирішував, які правки приймати; зміст звіту (результати, висновки, скріншоти) мій | звірив звіт із методикою та власними скріншотами |

## 7. Передавання

- Код і звіт передаю через приватний репозиторій GitHub (https://github.com/AndriiShuplik/Lab1_Shuplik, гілка lab/2-input-sqli, тег v0.2.0). Викладач має доступ до репозиторію.
- Файли звіту та докази (docs/report-lr02.md, docs/evidence/) завантажую в Moodle.
- Перед передачею перевіряю git diff та історію на відсутність секретів.
