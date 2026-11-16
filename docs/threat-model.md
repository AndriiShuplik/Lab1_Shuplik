# Модель загроз SecureLab, ЛР 6

Я розглядаю свій проєкт як одну систему: браузерний клієнт, API, PostgreSQL, конфігурацію й журнали. Модель мінімальна, без повного STRIDE і без CVSS. Її мета пояснити, чому саме ці маршрути, заголовки й журнали я перевіряю і де закінчуються мої висновки.

| Елемент | Що зафіксувати | Мій запис |
|---|---|---|
| Версія та середовище | commit початку огляду (review-start), профіль запуску, seed/reset, версія SDK | review-start `00cf249ebc4d07971b3798ea06433b2824ed45db` (гілка `lab/6-hardening-review` від `main`; відносно `v0.5.0` у `main` змінено лише `docs/`). SDK 10.0.402. Звичайні перевірки: Development, `http://localhost:5080`. Помилки й різницю профілів перевіряю в Production без launch profile (`--no-launch-profile`). Початковий стан даних: `dotnet run --project src/SecureLab.Api -- --reset-database` (лише Development, `Database:AllowReset=true`). Лише тестові облікові записи й штучні дані. |
| Компоненти в межах огляду | браузерний клієнт, API, PostgreSQL у Docker Compose, конфігурація, журнали; Redis лише якщо увімкнений | ASP.NET Core API (`src/SecureLab.Api`), статичний клієнт у `src/SecureLab.Api/Client` (`index.html`, `auth-lab.html`, `browser-lab.html`), PostgreSQL 54329 у Docker Compose (`infra/compose.yaml`), конфігурація `appsettings*.json`, `infra/.env.example`, консольні журнали API, NuGet-залежності з `packages.lock.json`. Redis не використовується. |
| Активи | облікові дані, власні записи, привілейовані переходи, дані аудиту, секрети конфігурації | Облікові дані користувачів (хеш пароля в `identity_users`, authentication cookie). Інциденти (Incident) та їхній власник. Право власника змінювати й видаляти лише свої інциденти. Привілейований перехід `New → Triaged` лише для Analyst. Internal comment (бачить лише Analyst). Події аудиту й діагностичні журнали. Connection string і пароль seed (поза Git). Цілісність request token (antiforgery). |
| Суб’єкти | анонімний відвідувач, автентифікований користувач, moderator/admin, локальний розробник | Анонім; Reporter (Alice, Bob); Analyst (Morgan); Administrator (як Reporter, без додаткових прав, див. `docs/access-matrix.md`); локальний розробник стенда; сторонній сайт у тому самому браузері користувача (джерело CSRF). |
| Entry points | HTTP-маршрути, login, форми браузера, завантаження конфігурації, restore пакетів, журнали | Змінювальні: `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`. Читання: `GET /api/me`, `/api/auth/session-check`, `/api/incidents`, `/api/incidents/{id}`, `/api/incidents/search`, `/api/incidents/severity-summary`, `/api/incident-comments/{id}`, `/health`. Статичні сторінки й `MapFallbackToFile`. Конфігурація зі змінних середовища (`ConnectionStrings__SecureLab`, `SeedUsers__Password`). `dotnet restore`. Консольний sink журналу. |
| Межі довіри | browser→API, API→PostgreSQL, repository→build, environment→configuration | browser→API (текст і cookie від браузера недовірені); API→PostgreSQL (параметри пошуку й ідентифікатори); repository→build (tracked файли й пакети NuGet); environment→configuration (Development і Production читають різну конфігурацію). |
| Наявні controls | validation, authentication, authorization, безпечна робота з DOM, CORS, CSP, antiforgery тощо, з посиланням на код, тест або конфігурацію | Server-side validation: `Lab02Endpoints.cs`, `IncidentEndpoints.UpdateAsync`, тести `CreateIncidentTests` (T-*). Параметризований ILike з екрануванням: `Lab02Endpoints.cs` (S-02). Identity з cookie HttpOnly, SameSite=Lax, Secure поза Development: `Lab03Identity.cs` (A-01…A-07 ЛР 3). Login limiter 20 запитів на 60 с за IP: `LoginRateLimitTests`. Resource-based авторизація й scoping: `IncidentAccessHandler`, A-01…A-12 ЛР 4. Safe DOM і CSP: `BrowserSecurityTests` (REG-XSS-01). Exact-origin CORS лише в Development: REG-CORS-01. Заголовки nosniff, no-referrer, CSP з `frame-ancestors 'none'`: middleware в `Program.cs`. Antiforgery на момент початку огляду відсутній, його я додаю в цій роботі. |
| Виключення | що не перевірялося й чому | Зовнішній penetration test; production host, TLS termination і HSTS на реальному домені; reverse proxy; історія Git поза явно переглянутими файлами; чужі клони, stash, зовнішній CI; DoS і навантажувальне тестування; сторонні ресурси сторінки Scalar у Development. Усі перевірки лише на локальному стенді. |

## Схема меж довіри

```
сторінка клієнта у браузері   (недовірений ввід, cookie додається автоматично)
        │  межа 1: browser → API (локальний HTTP http://localhost:5080)
        ▼
ASP.NET Core API   (validation, authN/authZ, antiforgery, rate limit, логування)
        │  межа 2: API → PostgreSQL (connection string, EF Core, параметри)
        ▼
PostgreSQL 54329 у Docker (дані застосунку)

репозиторій + NuGet   ──► межа 3: repository → build (restore, lockfile)
змінні середовища + appsettings ──► межа 4: environment → configuration (старт API)
```

## Очікувані властивості на межах

Колонка з перевірками заповнена за фактично виконаними запусками (розділи 8 і 9 звіту `docs/security-review.md`).

| Межа | Очікувана властивість (усі рівні) | Конкретний test або перевірка (добрий і відмінний) |
|---|---|---|
| browser→API | Змінювальний запит з authentication cookie без валідного request token відхилено без зміни стану. Текст користувача не виконується як код. Origin, якого немає в allowlist, не читає відповідь. | REG-CSRF-01 (`CsrfProtectionTests`, розділ 8.3 review). REG-XSS-01 (`BrowserSecurityTests` і браузерний DOM-тест). REG-CORS-01 (`Cors_*` тести, розділ 8.7). |
| API→PostgreSQL | Параметр пошуку не змінює структуру SQL. API не довіряє `OwnerUserId` з тіла запиту. | S-02, T-04 (`SearchSecurityTests`). A-05 (`A05_ForgedOwnerInBody_IsIgnored`), A-02/A-04 ЛР 4. |
| repository→build | Tracked файли не містять реальних credentials, відомі навчальні значення класифіковано. Restore не змінює lockfile непомітно. | `git grep` по tracked files і класифікація збігів (розділ 9.1, 9.3). `dotnet restore --locked-mode` і `dotnet package list --vulnerable --include-transitive` (розділ 9.2): без помилок і без advisories. |
| environment→configuration | У Production не діє Development-конфігурація, reset заборонено, клієнт одержує безпечну помилку з trace id. | Доказ `Hosting environment: Production`, відмова `--reset-database`, контрольована 500 із `traceId` (розділ 8.1), тест `ProductionErrorTests`. |

## Зв'язок актив → загроза → control → перевірка

Для обраного рівня («Добре») повний ланцюг для кожного активу не вимагається. Приклад для одного активу: право Alice змінювати лише власні інциденти → стороння сторінка в тому самому браузері надсилає змінювальний запит з автоматичною cookie Alice (CSRF) → antiforgery validation до зміни даних на кожному cookie-маршруті → REG-CSRF-01 (відмова без токена, незмінний стан, успіх із валідною парою). Решту зв'язків «control → ризик → перевірка → межа» подано в розділі 8.9 review.
