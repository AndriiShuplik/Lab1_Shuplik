# Карта архітектури

Карта описує систему після ЛР 1: готовий маршрут details і власне розширення
`GET /api/incidents/severity-summary`.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарії отримання списку, деталей і підсумку інцидентів за severity |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents або GET /api/incidents/{id}
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs
  → PostgreSQL
  → response DTO у Presentation/Contracts/
  → JSON
  → textContent/createTextNode у Client/app.js
```

## Власний маршрут ЛР 1: підсумок за severity

Запит: `GET /api/incidents/severity-summary` з необов'язковим параметром `status`.

```text
кнопка «Показати підсумок» у Client/index.html
  → loadSeveritySummary у Client/app.js
  → GET /api/incidents/severity-summary[?status=...]
  → IncidentEndpoints.GetSeveritySummaryAsync
  → IncidentQueries.GetSeveritySummaryAsync
  → SecureLabDbContext.Incidents / таблиця incidents (GroupBy + Count)
  → IncidentSeveritySummaryResponse(Severity, Count)
  → JSON-масив
  → textContent у списку підсумку (createTextElement)
```

| Роль | Файл |
|---|---|
| Клієнт | `Client/index.html`, `Client/app.js` |
| Endpoint | `Presentation/Endpoints/IncidentEndpoints.cs` |
| Application layer | `Application/Incidents/IncidentQueries.cs` |
| DTO | `Presentation/Contracts/IncidentResponses.cs` |
| DbContext і таблиця | `Data/SecureLabDbContext.cs`, таблиця `incidents` |
| Відтворюваний сценарій | `tests/http/incidents.http` |
| Відображення на БД | `Data/SecureLabDbContext.cs`: `DbSet<Incident> Incidents`, таблиця `incidents`, колонка `severity` зберігається як текст |

### Контракт

- Успіх: `200`, JSON-масив елементів `{ "severity", "count" }`. Інші поля entity не повертаються.
- Параметр `status` перевіряється за allowlist: New, Triaged, InProgress, Resolved, Closed.
  Некоректне значення дає `400` Validation Problem Details із помилкою поля `status`.
- Фільтр `status` застосовується до групування.
- **Політика нульових груп:** лише наявні групи. Рівень без інцидентів (наприклад, Critical
  на baseline seed) у відповіді відсутній, порожній результат дає `[]`.
- **Порядок:** `count` за спаданням, за рівних значень за назвою severity (ordinal).
  Групи сортуються в пам'яті після завантаження агрегату, бо severity зберігається в БД
  як текст і SQL-сортування було б лексикографічним.
  «Severity зберігається в колонці severity як текст (HasConversion<string>), тому SQL-сортування за ним було б лексикографічним».
- Структурований log: кількість сформованих груп і значення фільтра, без чутливих даних.

## Межі довіри

| Межа | Дані, що її перетинають | Чому даним ще не можна довіряти | Де перевіряємо або обмежуємо |
|---|---|---|---|
| Користувач → Browser client | Вибір статусу у формі, клік по кнопці | Користувач контролює введення; обмеження форми діють лише в одному UI | Значення з форми кодується `encodeURIComponent`, але вважається недовіреним |
| Browser client → API | method, URL, query `status`, `id` у шляху | Клієнт і HTTP-запит можна змінити або повторити поза UI (curl, інший клієнт) | Серверний allowlist `status` (400), маршрутне обмеження `:guid` для `id` |
| API → PostgreSQL | Розпізнане значення `IncidentStatus` для фільтра | Параметр запиту не можна вважати безпечним лише тому, що він пройшов маршрутизацію | Запит через EF Core (параметризований), `AsNoTracking`, проєкція в DTO без зайвих полів |
| PostgreSQL → API → DOM | JSON з текстами з БД (title, description, comments) | У БД може зберігатися раніше введений недовірений текст, наприклад `<script>` | Response DTO без `OwnerUserId` та `email`; вивід лише через `textContent` / `createTextNode` |

## Конфігураційні входи

- `global.json` — вибір версії .NET SDK;
- `src/SecureLab.Api/appsettings.json` — рівні журналювання (зокрема SQL-команди EF Core в консолі) та прапорці `Database:ApplyMigrationsOnStartup` і `Database:AllowReset`, які за замовчуванням вимкнені;
- `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.

Реальні значення, паролі та connection string у цьому документі не наводяться.

## Повернення до відомого seed-стану

Зупинити API (`Ctrl+C`) і виконати:

```powershell
dotnet run --project src/SecureLab.Api -- --reset-database
```

Команда працює лише в середовищі Development, очищує відомі навчальні таблиці та повторно
заповнює їх seed-значеннями. Після цього API запускають знову.