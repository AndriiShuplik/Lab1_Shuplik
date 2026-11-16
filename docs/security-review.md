# Security review SecureLab, ЛР 6

Рівень: добрий («Добре»); рівні накопичувальні, тому виконано всі вимоги достатнього рівня й додатково вимоги доброго. Пункти відмінного рівня (третя finding поза чек-листом, пріоритизація трьох findings, доказ відсутності чутливих даних у шести сценаріях логів, зв'язок asset → threat → control → verification для всіх активів, погоджене розширення) не входять до обраного рівня й не позначаються як PASS. Автоматизований REG-CSRF-01 і enforced CSP я зберіг, бо вони вже були виконані. Commit початку огляду (review-start): `00cf249ebc4d07971b3798ea06433b2824ed45db`. Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата початку: 2026-11-16. SDK: 10.0.402. Профіль запуску: Development (`http://localhost:5080`), для перевірок помилок окремо Production без launch profile. Клієнт для кожного спостереження вказую в самому записі.

## 1. Executive summary
Я перевірив власний проєкт SecureLab (ASP.NET Core, PostgreSQL, cookie-автентифікація) на commit початку огляду `00cf249ebc4d07971b3798ea06433b2824ed45db` у межах локального стенда: клієнт, API, база в Docker, конфігурація й консольні журнали. Обраний рівень: добрий. Зафіксовано три знахідки, усі виправлено: F-01 (відповідь 500 без заголовків безпеки, P3), F-02 (на жодному cookie-маршруті, що змінює стан, не було antiforgery, P2), F-03 (успішний перехід `Incident.Status` не залишав audit event, P3). Додано також rate limiting для пошуку (квота на користувача). Повний набір із 96 автоматизованих тестів пройшов на commit `b78e5bd` після reset, браузерний DOM-тест REG-XSS-01 дав PASS. Фінальний прогін на прийнятому merge commit і його hash додає скрипт експорту на першу сторінку PDF. Найважливіші залишкові ризики: login і register не захищені antiforgery (прийнятий ризик з компенсаціями), обидва rate limiter працюють у пам'яті одного екземпляра, audit лишається звичайним консольним журналом, HTTPS і HSTS у локальному стенді не перевірялися.

## 2. Scope та exclusions

У межах огляду: поточні tracked файли commit `00cf249` (API, клієнт у `src/SecureLab.Api/Client`, тести, `infra/`, `docs/`), локальна PostgreSQL у Docker Compose, консольні журнали API, NuGet-залежності з `packages.lock.json`. Історію Git я переглядав лише для п'яти конфігураційних файлів (розділ 9.1), решту історії не перевіряв.

Поза межами: зовнішній penetration test, production host, TLS termination і HSTS на реальному домені, reverse proxy, навантажувальне тестування й DoS, stash, чужі клони й зовнішній CI, сторонні ресурси сторінки Scalar у Development. Усе виконано лише на локальному стенді зі штучними даними й тестовими акаунтами.

## 3. System overview і trust boundaries

Систему утворюють браузерний клієнт, ASP.NET Core API і PostgreSQL. Автентифікація cookie-based (ASP.NET Core Identity), ролі Reporter, Analyst, Administrator. Активи, суб'єкти, entry points, схема й очікувані властивості на чотирьох межах (browser→API, API→PostgreSQL, repository→build, environment→configuration) описані в `docs/threat-model.md`. Зв'язок «актив → загроза → control → перевірка» подано в розділі 8.

## 4. Methodology та test environment

- **Початковий стан.** Review-start commit `00cf249ebc4d07971b3798ea06433b2824ed45db` (`main`). Гілку `lab/6-hardening-review` я створив від `main`, а не від `v0.5.0`: різниця `v0.5.0..main` містить лише `docs/` (команда `git diff v0.5.0 main --stat -- . ":(exclude)docs"` повернула порожній вивід), а ці docs потрібні в ЛР 6. Тег `v0.5.0` (`b77f2a3`) не змінював.
- **Стартова перевірка (2026-11-16, Terminal1):** `git status` чисте; теги `v0.1.0`…`v0.5.0`; `dotnet --version` дало `10.0.402`; `dotnet restore SecureLab.sln --locked-mode` без помилок і попереджень; `dotnet build SecureLab.sln -c Release --no-restore` успішно для обох проєктів; PostgreSQL контейнер `secure-lab-postgres-1` Healthy; `dotnet run --project src/SecureLab.Api -- --reset-database` завершився повідомленням про очищення й повторне заповнення seed; `dotnet test SecureLab.sln -c Release` дав `всього: 84; сбій: 0; успішно: 84; пропущено: 0`; Development API на `http://localhost:5080`, `/health` дало 200 `{"status":"ready"}`.
- **Локальна БД:** PostgreSQL у Docker, `127.0.0.1:54329`, база `securelab`, том `postgres-data`.
- **Профілі:** Development (`launchSettings.json`, profile `http`) і Production-like (`--no-launch-profile -c Release`, `Production.ps1`). Для кожного спостереження вказую профіль і клієнт (curl.exe, браузер Chrome, cookie-aware тестовий host).
- **Терміналі:** Terminal1 для команд, Terminal2 для API.
- **Секрети:** `SeedUsers__Password` задано лише в змінній середовища Terminal1, у Git і в докази він не потрапляє.
- **Перегляд diff перед merge:** я переглянув `git diff 00cf249..HEAD` (37 файлів): у ньому немає пароля seed, значень cookie чи токенів, журналів, `.env`, змін `.csproj` і `packages.lock.json`. README доповнено лише фактичними командами ЛР 6 (розділ 8 README).
- **Controlled errors і debug hooks:** для помилки з розділу 8.1 я не додавав жодного debug endpoint: її викликає лише тимчасовий запуск із недосяжною БД, який після експерименту прибрано. На фінальному прогоні у Production-like профілі `/openapi/v1.json` дає 404, `/scalar/v1` повертає сторінку клієнта (fallback), а не Scalar, `csrf-token` без входу дає 401.
## 5. Findings summary
| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Повторна перевірка |
|---|---|---|---|---|---|---|
| F-01 | браузерні заголовки безпеки на відповіді 500 | Low | Low | P3 | Fixed (`f6d2315`) | REG-ERR-01 (`ProductionErrorTests`) |
| F-02 | право змінювати власні інциденти, triage, logout (CSRF) | Medium | Medium | P2 | Fixed (`f6d2315`) | REG-CSRF-01 (`CsrfProtectionTests`) |
| F-03 | журнал аудиту привілейованого переходу | Low | Medium | P3 | Fixed (`b78e5bd`) | REG-AUD-01 (`TriageAuditTests`) |

Порядок дій: F-02 першою, бо це єдина знахідка, яка допускала неавторизовану зміну даних авторизованого користувача; F-01 і F-03 не дають прямого доступу до даних і розглядаються після неї.

## 6. Detailed findings
Кожна знахідка має окрему картку з передумовами, відтворенням, першопричиною, виправленням, retest, positive regression і залишковим ризиком:

- `docs/findings/F-01-error-path-headers.md`: відповідь 500 без `X-Content-Type-Options`, `Referrer-Policy` і CSP.
- `docs/findings/F-02-no-antiforgery.md`: відсутня antiforgery-валідація на cookie-маршрутах, що змінюють стан.
- `docs/findings/F-03-triage-audit-trail.md`: дозволений перехід triage не фіксувався в audit trail.

Інші мої перевірки (limiter пошуку, CORS, залежності, журнали) дефектів не виявили, тому в findings їх немає: у розділах 8 і 9 вони описані як перевірені контролі.

## 7. Regression results
Передумови для всіх рядків: Development, `dotnet run --project src/SecureLab.Api -- --reset-database`, SDK 10.0.402, змінна `SeedUsers__Password` у терміналі. Повний набір: `dotnet test SecureLab.sln -c Release` на commit `b78e5bd` після reset, результат: усього 96, збоїв 0, пройдено 96, пропущено 0. Браузерний DOM-тест виконано в Chrome на тому самому стані з адаптованим `tests/browser/description-dom.js`. Прогін на прийнятому merge commit і фінальний hash додає скрипт експорту окремо (розділ 12).

| ID | Властивість | Негативний сценарій | Позитивна перевірка | Команда або тест | Результат |
|---|---|---|---|---|---|
| S-02, T-04 | query не змінює структуру SQL | контрольний ввід, `%` і `_` як літерали | апостроф у `O'Brien`, звичайний пошук | `SearchSecurityTests` (`Search_ControlInput_…`, `Search_WildcardCharacters_AreMatchedLiterally`, `Search_LegitimateApostrophe_…`) | pass |
| A-01…A-07 (ЛР 3) | автентифікація й життєвий цикл сеансу | анонім, хибний пароль, невідомий користувач, підроблений `X-Demo-UserId` і `ownerUserId` | вхід, `/api/me`, вихід | `AuthSecurityTests`, `SessionRevocationTests`, `AuthenticationMechanicsTests` | pass |
| A-02…A-12 (ЛР 4) | серверна перевірка власника й ролі | чужий інцидент (404), Reporter triage (403), чужий коментар | власник змінює, Analyst виконує triage | `IncidentAuthorizationTests`, `IncidentEndpointTests` | pass |
| REG-XSS-01 | text не виконується як код | marker `<img onerror=…>` в описі й коментарі | `O'Brien`, `<b>`, 4000 символів, Unicode | `ClientScripts_DoNotUseDangerousHtmlSinks`, `ClientPages_HaveNoInlineScriptsStylesOrHandlers`, браузерний DOM-тест | pass; DOM-тест 15 PASS, `RESULT: PASS` |
| REG-CSRF-01 | пара токенів обов'язкова для змінювальних маршрутів | `PUT` без токена і з невалідним токеном, create, DELETE, triage, logout без токена, токен іншого користувача | `PUT` із валідною парою, create і logout із токеном | `CsrfProtectionTests` | pass; стан ресурсу перевірено до і після |
| T-02, T-03, T-09, T-10 | серверна валідація | некоректні поля, дубль заголовка, 39 символів для High, дата старша за рік | допустимі значення зберігаються, 40 символів приймається | `CreateIncidentTests` | pass |
| REG-CORS-01 | точний origin | origin 4174, `null`, префікс-хост, слеш, https | origin 4173, preflight | `Cors_*` у `BrowserSecurityTests`, розділ 8.7 (Chrome і curl) | pass |
| login limiter (ЛР 3) | зловживання входом обмежено | 4-та спроба у вікні | вхід після вікна | `LoginRateLimitTests` | pass |
| search limiter (ЛР 6) | зловживання пошуком обмежено, partitions окремі | 4-й запит у вікні, вичерпана квота Alice | Bob отримує 200, відновлення після вікна | `SearchRateLimitTests` | pass |
| REG-ERR-01 | безпечна 500 із заголовками | недосяжна БД у Production | заголовки на 200 і 404 | `ProductionErrorTests`, розділ 8.1 | pass (до виправлення падав) |
| REG-AUD-01 | audit привілейованого переходу triage | Reporter triage → `authorization.denied`, статус незмінний | Analyst triage → `authorization.allowed` | `TriageAuditTests` | pass (до виправлення падав) |

Результат фактичного повторного запуску кожної групи окремо я не друкував: усі перелічені тести входять до повного набору, який дав 96 з 96. Для REG-CSRF-01, REG-ERR-01 і REG-AUD-01 додатково показано, що без виправлення тест падає.

## 8. Hardening controls

### 8.1. Production-like профіль і безпечна помилка (етап 1, п. 4-5, CP-01)

Дата 2026-11-16, commit `00cf249`, API запущено без launch profile: `Production.ps1 -Mode normal` (`ASPNETCORE_ENVIRONMENT=Production`, `ASPNETCORE_URLS=http://localhost:5080`, connection string через `ConnectionStrings__SecureLab` з `Include Error Detail=false`, `Logging__Console__IncludeScopes=true`, `-c Release`).

| Властивість | Клієнт | Результат | Доказ |
|---|---|---|---|
| Профіль активний | консоль API (Terminal2) | `Now listening on: http://localhost:5080`, `Hosting environment: Production` | `docs/evidence/lab06/01-production-env.png` |
| OpenAPI вимкнено | curl (Git Bash), анонімний `GET /openapi/v1.json` | 404 `application/problem+json`, у Development цей маршрут давав 200 | `curl.exe -s -D - http://localhost:5080/openapi/v1.json` |
| `/scalar/v1` | curl (Git Bash), `GET /scalar/v1` | 200 `text/html`, тіло починається з `<html lang="uk">`: це сторінка клієнта через `MapFallbackToFile`, а не Scalar | `curl.exe -s -D - http://localhost:5080/scalar/v1` |
| `GET /health` | curl (Git Bash) | 200 `{"status":"ready"}` | `curl.exe -s http://localhost:5080/health` |
| Reset заборонений | `dotnet run ... --no-launch-profile -c Release -- --reset-database` | процес завершується з `InvalidOperationException: Reset даних дозволено лише в явно налаштованому Development environment.`, SQL `TRUNCATE` не виконувався | вивід консолі |

**Контрольована неочікувана помилка.** Для Production запустив API з недосяжною БД (порт 54399, пароль `unreachable-study-value`, значення вигадані). Публічний `POST /api/auth/login` з вигаданим паролем (`alice` / синтетичний рядок) повернув:

```
HTTP/1.1 500 Internal Server Error
Content-Type: application/problem+json
{"type":"https://tools.ietf.org/html/rfc9110#section-15.6.1","title":"An error occurred while processing your request.","status":500,"traceId":"00-84f5d8414f6d0d019023089e4cf5197c-0e57ced990f9d204-00"}
```

У відповіді немає stack trace, SQL, шляху файлової системи, connection string чи версій пакетів. Є `traceId`. Запис внутрішнього журналу того самого запиту (категорія `ExceptionHandlerMiddleware`, stack trace опущено):

```
fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]
      => SpanId:0e57ced990f9d204, TraceId:84f5d8414f6d0d019023089e4cf5197c, ParentId:0000000000000000 => ... => RequestPath:/api/auth/login ...
      An unhandled exception has occurred while executing the request.
```

Правило зіставлення: середній 32-символьний сегмент `traceId` з відповіді дорівнює `TraceId` у журналі (`84f5d8414f6d0d019023089e4cf5197c`), а останні 16 символів до `-00` дорівнюють `SpanId`. Доказ: `docs/evidence/lab06/02-prod-500-response.png` (відповідь у Terminal1) і `docs/evidence/lab06/03-prod-500-log.png` (запис у Terminal2). У журналі немає пароля із запиту й connection string; причина `Failed to connect to 127.0.0.1:54399` видна лише у внутрішньому каналі.

**Відновлення після експерименту (CP-01).** Після контрольованої помилки я зупинив Production-запуск, прибрав тимчасові змінні середовища (`ASPNETCORE_ENVIRONMENT`, `ASPNETCORE_URLS`, `ConnectionStrings__SecureLab`, `Logging__Console__IncludeScopes`) і повернув звичайний Development-запуск із правильним connection string. `/health` дав 200, вхід і нормальний клієнтський потік підтверджено в розділі 8.4.

**Обмеження для захищених 4xx у Production.** Перевірки `GET /api/incidents?status=Unknown` (400) і `GET /api/incidents/<неіснуючий id>` (404) я виконав у Development тим самим клієнтом із cookie Alice (розділ 8.2). Cookie-aware Production-host для цих двох запитів я окремо не налаштовував: штатний `SecureLabApiFactory` працює в Development, а в Production cookie має `Secure`, тому на `http://localhost` вона не повертається. Для Production підтверджено лише відповіді, що не потребують входу (404 для OpenAPI, 500 із `traceId`), і це обмеження висновку.

**Спостереження, яке стає finding.** На цій 500 відповідь не має `X-Content-Type-Options`, `Referrer-Policy` і `Content-Security-Policy`, хоча на 200 і 404 того ж профілю вони є. Це оформлю як F-01 і виправлю на етапі 2.

Межі: це спостереження в локальному Production-like профілі на HTTP, воно не доводить production transport safety.

### 8.2. Заголовки безпеки на п'яти класах відповідей (етап 2, п. 1)

Профіль, клієнт і сеанс: Development, `http://localhost:5080`, скрипт на Node.js (fetch з cookie-сеансом Alice, значення cookie не друкуються). Клас 5 (500) спостерігався в Production-like профілі за розділом 8.1. Значення CSP на всіх рядках, де її видно, однакове: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.

| Клас | Method + route | Status | X-Content-Type-Options | Referrer-Policy | CSP | Ризик, який зменшує | Межа |
|---|---|---|---|---|---|---|---|
| статична сторінка | `GET /` | 200 `text/html` | nosniff | no-referrer | є | MIME sniffing; витік referrer; скрипти й вбудовування з чужих джерел | не замінює правильний Content-Type і заборону секретів в URL |
| успішний API | `GET /api/me` (Alice) | 200 `application/json` | nosniff | no-referrer | є | те саме | не замінює авторизацію |
| validation | `GET /api/incidents?status=Unknown` (Alice) | 400 `application/problem+json` | nosniff | no-referrer | є | те саме | не замінює валідацію |
| невідомий ресурс | `GET /api/incidents/99999999-9999-9999-9999-999999999999` (Alice) | 404 `application/problem+json` | nosniff | no-referrer | є | те саме | не замінює авторизацію ресурсу |
| неочікувана помилка до виправлення | `POST /api/auth/login`, Production, недосяжна БД | 500 `application/problem+json` | відсутній | відсутній | відсутній | заголовки не діяли саме на шляху помилки | F-01 |
| неочікувана помилка після виправлення | той самий запит у тестовому host | 500 `application/problem+json` | nosniff | no-referrer | є | заголовки на всіх класах | тест `ProductionErrorTests`, F-01 |

Додатково для cookie сеансу після входу Alice (Development, HTTP): `.AspNetCore.Identity.Application` має `HttpOnly`, `SameSite=Lax`, `path=/`. Прапорця `Secure` немає: у Development політика `SameAsRequest`, а на HTTP-запиті cookie без `Secure`. У Production політика `Always` (`Lab03Identity.cs`), це підтверджує існуючий тест `Login_OverHttps_SetsExpectedCookieAttributes` для HTTPS-адреси тестового host.

CSP: у ЛР 5 вона вже enforced (`Content-Security-Policy`, не report-only), тож для відмінного рівня я не додавав її заново, а повторно перевірив на фактичних відповідях і в `BrowserSecurityTests` (`Responses_CarryEnforcedCspAndBrowserHeaders`: немає `unsafe-inline`, `unsafe-eval` і `*`). Роботу клієнта з CSP перевірю в браузері окремо (розділ 8.4).

### 8.3. Периметр змінювальних маршрутів і antiforgery (етап 2, п. 3-5)

**Контракт antiforgery.** Header: `X-CSRF-TOKEN`. Cookie-частина: `SecureLab.Antiforgery` (HttpOnly, SameSite=Strict, Secure поза Development). Маршрут видачі: `GET /api/auth/csrf-token` (лише після входу, повертає `{"token": ...}`). Валідація: один `AntiforgeryFilter` (`src/SecureLab.Api/Security/AntiforgeryFilter.cs`), explicit, підключений до кожного cookie-маршруту окремо; відмова: 400 `application/problem+json`, `title = "Antiforgery token is missing or invalid."`. Токен живе лише в пам'яті сторінки (`Client/csrf.js`), після login і logout helper скидається, 4xx автоматично не повторюється.

**Джерела периметра.** Звірено три джерела: `git grep -n -E "\.Map(Post|Put|Patch|Delete)\(" -- src` (7 маршрутів), `GET /openapi/v1.json` у Development (ті самі 7 операцій) і виклики клієнта `git grep -n -E "mutate\(|method: *.(POST|PUT|PATCH|DELETE)" -- src/SecureLab.Api/Client` (4 маршрути: register, login, logout, створення; обидві сторінки `auth-lab.js` і `browser-lab.js` створюють інцидент). `GET /api/auth/csrf-token` стан застосунку не змінює (лише ставить antiforgery cookie), інші GET не змінюють стану.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | `POST /api/auth/register` | ЛР 3 / OpenAPI / client call | створює акаунт Reporter | ні | так (`auth-lab.js`) | absent: рішення scope (див. нижче) | `Register_Duplicates_Return409_AndResponseHasNoSecrets`, A-07 |
| SC-02 | `POST /api/auth/login` | ЛР 3 / OpenAPI / client call | створює сеанс | ні | так (`auth-lab.js`) | absent: рішення scope (див. нижче) | `LoginRateLimitTests`, A-07 |
| SC-03 | `POST /api/auth/logout` | ЛР 3 / OpenAPI / client call | завершує сеанс | так | так (`auth-lab.js`) | explicit, `AntiforgeryFilter` | REG-CSRF-01 (`Perimeter_…`, `ValidPair_AllowsCreate_AndLogout`) |
| SC-04 | `POST /api/incidents` | ЛР 2 / OpenAPI / client call | створює Incident | так | так (`auth-lab.js`, `browser-lab.js`) | explicit, `AntiforgeryFilter` | REG-CSRF-01 (`Perimeter_…`, `ValidPair_…`), T-01 |
| SC-05 | `PUT /api/incidents/{id}` | ЛР 4 / OpenAPI / DISCREPANCY: є на сервері й в OpenAPI, виклику в клієнті немає | змінює title і description | так | так (доступний із браузера, UI немає) | explicit, `AntiforgeryFilter` | REG-CSRF-01 (`RegCsrf01_…`), A-02 |
| SC-06 | `DELETE /api/incidents/{id}` | ЛР 4 / OpenAPI / DISCREPANCY: виклику в клієнті немає | видаляє Incident у статусі New | так | так (UI немає) | explicit, `AntiforgeryFilter` | REG-CSRF-01 (`Perimeter_…`), A-04 |
| SC-07 | `POST /api/incidents/{id}/triage` | ЛР 4 / OpenAPI / DISCREPANCY: виклику в клієнті немає | `New → Triaged` | так | так (UI немає) | explicit, `AntiforgeryFilter` | REG-CSRF-01 (`Perimeter_…`), A-06, A-07 |

DISCREPANCY-рядки (SC-05…SC-07) не помилка документації: ці маршрути реалізовані в ЛР 4 і доступні браузеру, але клієнт їх не викликає. Я не вважаю їх захищеними через відсутність кнопки: CSRF оцінює HTTP endpoint, а не інтерфейс, тому фільтр підключено й до них.

**Рішення щодо login і register.** Обидва не довіряють наявній authentication cookie, тому до cookie-периметра не входять. Захищати їх токеном, який можна одержати лише після login, не можна, а окремий анонімний bootstrap токена виходить за межі цієї роботи. Ризики: login-CSRF (вхід жертви в акаунт атакувальника) і створення акаунта зі сторонньої сторінки. Компенсації: login limiter (повторно перевірений нижче), однакова 401 для невідомого користувача й хибного пароля (A-07), у сеансі немає чутливих даних. Рішення: accepted, residual risk у розділі 10.

**REG-CSRF-01.** Передумови: Development, `--reset-database`, Alice входить cookie-клієнтом (без токена), у БД створено її інцидент. Послідовність (`CsrfProtectionTests.RegCsrf01_PutWithoutOrWithInvalidToken_IsRejected_StateIsUnchanged_ValidPairSucceeds`): вхід і cookie-сеанс → стан до → `PUT` без токена → 400 і Problem Details → повторне читання (та запит у БД): `title` і `description` незмінні → `PUT` із невалідним значенням header → 400, стан незмінний → видача токена (`GET /api/auth/csrf-token`) → `PUT` з валідною парою → 200 → читання показує нові `title` і `description`. Це та сама автоматизована послідовність, яку вимагає відмінний рівень. Додатково: `Perimeter_EveryCookieMutation_RejectsMissingToken_AndKeepsState` (create, PUT, DELETE, triage, logout без токена: 400 і незмінний стан), `Token_IssuedForAnotherUser_IsRejected_AndStateIsUnchanged`, `TokenRoute_WithoutSession_Returns401`, `ValidPair_AllowsCreate_AndLogout`.

Результат запуску після виправлення (2026-11-16): `dotnet test SecureLab.sln -c Release` дав 91 пройдено, 0 збоїв, 0 пропущено. Перевірка чутливості: після тимчасового вилучення фільтра з `PUT` тести падали з `Expected: BadRequest, Actual: OK`, після відновлення проходять. Це проміжний результат, фінальний прогін на final commit запишу окремо в розділ 7.

Браузерний прохід усіх змінювальних дій клієнта описано в розділі 8.4.

### 8.4. Браузерний прохід мутацій клієнта і CSP (етап 2, п. 5)

Профіль і клієнт: Development, `http://localhost:5080`, Chrome (справжній браузер, керований через DevTools Protocol), окремий профіль без розширень, користувачі Alice і Bob. Сценарій виконано скриптом на Node.js, який керує Chrome: він заповнює справжні форми сторінок і натискає їх кнопки, а перелік запитів і статусів береться з подій Network браузера (значення cookie й токена не друкуються, фіксується лише наявність header). Дані: після reset, створені записи видалено.

| Крок | Дія клієнта | Запити (з подій Network) | Результат |
|---|---|---|---|
| 1 | вхід Alice на `auth-lab.html` | `POST /api/auth/login` | `Login: 204`, токен не потрібен (login поза cookie-периметром) |
| 2 | створення інциденту на `auth-lab.html` | `GET /api/auth/csrf-token` 200 → `POST /api/incidents` 201, header `X-CSRF-TOKEN` присутній | `Створено: …` |
| 3 | F5 і повторне створення | знову `GET /api/auth/csrf-token` 200 → `POST /api/incidents` 201, header присутній | токен у пам'яті сторінки після перезавантаження новий, дія працює |
| 4а | прямий `fetch` `POST /api/incidents` без header (з консолі сторінки) | `POST /api/incidents` 400, header відсутній | 400 `application/problem+json`, `title: Antiforgery token is missing or invalid.` |
| 4б | той самий `fetch` із header `X-CSRF-TOKEN: not-a-real-token` | `POST /api/incidents` 400, header присутній | 400, невалідний токен не приймається |
| 5 | натискання «Вийти» | `POST /api/auth/logout` 204, header присутній → `GET /api/me` 401 | `Logout: 204; GET /api/me: 401` |
| 6 | вхід Bob (новий principal) | `GET /api/me` 401 → `POST /api/auth/login` 204 → `GET /api/me` 200 | вхід працює |
| 7 | створення інциденту як Bob | `GET /api/auth/csrf-token` 200 → `POST /api/incidents` 201, header присутній | новий токен для нового користувача, `Створено: …` |
| 8 | створення на `browser-lab.html` | `GET /api/auth/csrf-token` 200 → `POST /api/incidents` 201 → `GET /api/incidents/{id}` 200, header на POST присутній | `GET: 200`, запис прочитано |

Рис. 4 (`docs/evidence/lab06/04-csrf-flow-ok.png`, SHA-256 `2db418620dc7325f5d5b76f7e89df9599d9b43c745f84fde57d98b17496a1f18`): ліворуч сторінка `auth-lab.html` після створення інциденту, праворуч вкладка Network справжнього DevTools того самого сеансу: `csrf-token` 200 і `incidents` 201, у колонці Initiator `csrf.js:19` і `csrf.js:52`, тобто обидва запити виконує helper. Кадр складено з двох справжніх знімків (сторінка й DevTools).

Рис. 5 (`docs/evidence/lab06/05-csrf-missing.png`, SHA-256 `f8fd27635d22f344cfb89ea97ba514a9689352287b349605ffbce5f881757099`): та сама сторінка й сеанс. Ліворуч результат попереднього успішного створення через helper, праворуч Network: перші два запити helper, третій `incidents` позначений помилкою: прямий `fetch` без header, вкладка Response показує `"title": "Antiforgery token is missing or invalid."`, `"status": 400`, `traceId`. Кадр також складено з двох справжніх знімків.

**CSP на клієнті.** Тими самими сеансом і браузером я відкрив `/`, `/auth-lab.html` і `/browser-lab.html` з увімкненою enforced CSP (`script-src 'self'`, без `unsafe-inline`) і зібрав повідомлення консолі через події Runtime і Log: порушень CSP немає, повідомлень про помилки немає. Усі дії таблиці вище працюють у цьому ж режимі, тож `csrf.js` (окремий файл `'self'`) CSP не порушує, а саму CSP я не послаблював. Межа: перевірено Development у Chrome, сторінку Scalar (поза CSP за рішенням ЛР 5) не перевіряв.

Межі: токен існує лише в пам'яті сторінки; XSS на власному origin прочитав би його так само, як helper, тому safe DOM (REG-XSS-01) лишається окремим контролем.

### 8.5. Rate limiting: login (повторна перевірка) і search (етап 2, п. 7)

Обидва limiter реалізовано через `AddRateLimiter` у `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` (fixed window, `QueueLimit = 0`, відмова 429). Тести використовують окремий host з малою квотою (`WithWebHostBuilder`, значення `LoginRateLimit:*` або `SearchRateLimit:*`), тому кожен експеримент має власний лічильник.

**Login limiter (існував з ЛР 3), повторна перевірка за планом із п. 7.** Partition key: IP з'єднання; за замовчуванням 20 спроб на 60 с; у тестах 3 спроби на 2 с.

| Крок плану | Що перевірено | Тест | Результат |
|---|---|---|---|
| 1. у межах квоти нічого не ламається | три спроби з хибним паролем дають звичайну 401 | `FourthAttemptInWindow_Returns429_RegardlessOfUserName` | пройдено |
| 2. вичерпання квоти → 429 | четверта спроба в тому самому вікні | той самий тест | 429 |
| 3. відновлення | після вікна легітимний вхід знову 204 | `AfterWindow_LoginWorksAgain` | пройдено |
| 4. відповідь не розкриває акаунт | четверта спроба з випадковим неіснуючим іменем дає той самий 429, що й для `alice`; без вичерпання невідомий користувач і хибний пароль дають однаковий 401 | `FourthAttemptInWindow…`, A-07 | пройдено |
| 5. authorization окремо | 429 не видає ресурсів; наявність квоти не дає прав: у тесті search Bob у межах квоти не бачить чужого запису | `Search_PartitionsAreSeparate_…` | пройдено |

Також `SeparateHost_HasIndependentCounter` підтверджує, що лічильник належить екземпляру застосунку (in-memory).

**Search limiter (новий, `GET /api/incidents/search`).** Partition key: `NameIdentifier` автентифікованого користувача (ключ береться з principal, не з IP і не з довільного client header: IP може бути спільним, header не є перевіреною identity). Квота й вікно з конфігурації: `SearchRateLimit:PermitLimit` (60) і `SearchRateLimit:WindowSeconds` (60) за замовчуванням; у тестах 3 на 2 с. `UseRateLimiter()` стоїть після `UseAuthentication()` і `UseAuthorization()`, тому анонімний запит отримує 401 до витрати квоти. Рішення про quota 60 на хвилину: звичайний інтерактивний пошук не наближається до такої частоти, а автоматизоване перебирання значень `q` обмежується.

| Властивість | Тест | Результат |
|---|---|---|
| у межах квоти пошук працює як раніше (200 і очікуваний запис Alice) | `Search_WithinQuota_KeepsExpectedBehavior_ThenFourthRequestReturns429` | пройдено |
| наступний запит у вікні дає 429 | той самий тест | 429 |
| partition A не блокує partition B: Alice вичерпала квоту, Bob отримує 200 і не бачить записів Alice | `Search_PartitionsAreSeparate_ExhaustedQuotaOfOneUserDoesNotBlockAnother` | пройдено |
| інші маршрути не обмежені (`GET /api/me` → 200 при вичерпаній квоті search) | `Search_Quota_DoesNotLimitOtherRoutes_AndRecoversAfterWindow` | пройдено |
| відновлення після вікна (200) | той самий тест | пройдено |
| анонімний запит → 401 до витрати квоти | `Search_Anonymous_Returns401_BeforeAnyQuotaIsSpent` | пройдено |

Команда: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RateLimitTests"` (збігається з `LoginRateLimitTests` і `SearchRateLimitTests`). Повний набір після зміни: 95 пройдено, 0 збоїв.

Межі: обидва limiter працюють у пам'яті одного екземпляра і не діляться між кількома екземплярами; login limiter рахує за IP, тому користувачі за одним NAT ділять квоту; rate limiting не замінює authentication і authorization. Загальне вікно fixed window дозволяє короткий сплеск на межі двох вікон. Redis не використовується (не входить до обраного рівня).

### 8.6. HTTPS, redirect і HSTS як конфігурація (етап 2, п. 6)

Фактична конфігурація: `src/SecureLab.Api/Properties/launchSettings.json` містить лише profile `http` з `http://localhost:5080`; у `Program.cs` немає `UseHttpsRedirection()` і `UseHsts()`; reverse proxy або інша зовнішня межа TLS у проєкті не описана. Cookie сеансу й antiforgery мають політику `Secure` = `Always` поза Development (`Lab03Identity.cs`, `CsrfEndpoints.cs`), а тест `Login_OverHttps_SetsExpectedCookieAttributes` перевіряє атрибути cookie на адресі `https://localhost` у тестовому host.

Висновок: локальний HTTP profile не доводить production transport safety. Я не додавав HTTPS endpoint, redirect чи HSTS, щоб «закрити» перелік. Різницю між поняттями зафіксовано: HTTPS захищає з'єднання, redirect (за замовчуванням 307) лише перенаправляє HTTP-запит, HSTS є політикою браузера після довіреної HTTPS-відповіді. Відсутність `Strict-Transport-Security` на `localhost` очікувана (loopback входить до `ExcludedHosts`) і дефектом не вважається. Не перевірялися: реальний deployment, TLS termination і HSTS на production host.

### 8.7. CORS і REG-CORS-01 (етап 2, п. 2)

Профіль: Development, `http://localhost:5080` (політика `Lab05BrowserProbe` реєструється лише в Development, у Production її немає). Allowlist: рівно `http://localhost:4173`, метод `GET`, header `X-Lab-Cors-Probe`, credentials. Клієнти: Chrome (проби з `demonstrations/cors-probe`, що їх обслуговують локальні сервери на портах 4173 і 4174, кадри через справжній DevTools) і `curl` без браузера. Висновки робив не з рядка `WithOrigins` у коді, а з фактичних відповідей.

| Сценарій | Клієнт, Origin | Запит | Результат |
|---|---|---|---|
| browser, дозволений origin | Chrome, сторінка `http://localhost:4173` | `GET /health` з `credentials: include` (кнопка проби) | 200, відповідь `{"status":"ready"}` доступна сторінці; у відповіді `Access-Control-Allow-Origin: http://localhost:4173` і `Access-Control-Allow-Credentials: true` |
| browser, недозволений origin | Chrome, сторінка `http://localhost:4174` | той самий запит | сервер віддав 200, але `Access-Control-Allow-*` немає; браузер не надав відповідь JavaScript (повідомлення проби «Браузер не надав response JavaScript…», `Failed to fetch`) |
| direct HTTP, дозволений | curl, `Origin: http://localhost:4173` | `GET /health` | 200, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true` |
| direct HTTP, недозволений | curl, `Origin: http://localhost:4174` | `GET /health` | 200, жодного `Access-Control-*` |
| preflight, дозволений | curl, `OPTIONS` + `Access-Control-Request-Method: GET` + `Access-Control-Request-Headers: x-lab-cors-probe` | `OPTIONS /health` | 204, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`, `Allow-Origin: http://localhost:4173`, `Allow-Credentials: true` |
| preflight, недозволений | curl, `Origin: http://localhost:4174` | `OPTIONS /health` | 204 без `Access-Control-*` |
| CORS не є authorization | curl без cookie, `Origin: http://localhost:4174` | `GET /api/incidents` | 401: працює authentication, а не CORS |

Рис. 6 (`docs/evidence/lab06/06-cors-allowed.png`, SHA-256 `07bb0c3f3a283047a67d7807f90ebcd05d93b8bccd6e2cbcc4285b00628b49f5`) і Рис. 7 (`docs/evidence/lab06/07-cors-disallowed.png`, SHA-256 `4f7d5e97d6bd67492a035a2054cdd286ce43249e343d0b835fce8c3c4d5328eb`): ліворуч сторінка проби з власним текстом результату, праворуч вкладка Network справжнього DevTools того самого сеансу з відкритими Headers запиту `health`. Кожен кадр складено з двох справжніх знімків. На Рис. 7 видно, що запит дійшов до сервера (200 OK), але відповідь без `Access-Control-Allow-Origin`, тому сторінка її не отримала.

Автоматична перевірка (`BrowserSecurityTests`): `Cors_AllowedOrigin_GetsExactAllowOriginAndCredentials`, `Cors_DisallowedOrigin_GetsNoCorsHeaders_ButRequestIsStillServed`, `Cors_Preflight_AllowedOrigin_ListsExactMethodAndHeader`, `Cors_Preflight_DisallowedOrigin_HasNoAccessControlHeaders`, `Cors_OriginsThatAreNotExactlyTheAllowedOne_AreNotReflected` (`null`, префікс-хост, слеш, https). Усі пройдено в повному наборі.

Межі: CORS керує лише читанням cross-origin відповіді в браузері. Він не замінює authentication, authorization і antiforgery, не зупиняє запити curl чи server-to-server (сервер усе одно виконав запит з `Origin` 4174), і два порти `localhost` це різні origins для CORS, але не доказ поведінки SameSite. Дозволений origin з credentials міг би прочитати й antiforgery token, тому він фактично довірений, і allowlist лишається точним.

### 8.8. Різниця Development і Production-like профілю (добрий рівень)

Усе нижче перевірено або в коді (`Program.cs`, `Lab03Identity.cs`, `CsrfEndpoints.cs`, `appsettings*.json`), або на запуску (розділ 8.1).

| Властивість | Development | Production-like | Як перевірено |
|---|---|---|---|
| OpenAPI і Scalar | `/openapi/v1.json` 200, `/scalar/v1` справжній Scalar | `/openapi/v1.json` 404, `/scalar/v1` це SPA fallback клієнта | `curl` у обох профілях (8.1) |
| CSP | для `/scalar` у Development CSP не ставиться | CSP на всіх відповідях, `/scalar` без винятку | `Program.cs`, `BrowserSecurityTests` |
| CORS `Lab05BrowserProbe` | є | немає | `Program.cs` (реєстрація лише в Development), 8.7 |
| Міграції при старті і reset | `ApplyMigrationsOnStartup=true`, `AllowReset=true` | обидва `false`; `--reset-database` завершується `InvalidOperationException` | `appsettings.Development.json`, запуск (8.1) |
| Connection string | з `appsettings.Development.json` (відкрите навчальне значення) | лише через `ConnectionStrings__SecureLab` поза Git | запуск `Production.ps1` (8.1) |
| Cookie сеансу й antiforgery | `Secure` = `SameAsRequest` | `Secure` = `Always` | `Lab03Identity.cs`, `CsrfEndpoints.cs` |
| Помилка відповіді | `ProblemDetails` без stack trace (спільний `AddProblemDetails` + `UseExceptionHandler`) | та сама безпечна 500 з `traceId` | 8.1, F-01, `ProductionErrorTests` |

Безпечна відповідь на неочікувану помилку у Development і Production однакова за дизайном starter, тому різницю профілів показують пункти вище, а не вигляд 500.

### 8.9. Hardening controls: control, ризик, перевірка, межа

| Control | Ризик | Перевірка | Межа |
|---|---|---|---|
| antiforgery validation на 5 cookie-маршрутах | CSRF (автоматична cookie) | REG-CSRF-01, `CsrfProtectionTests` | не зупиняє XSS на власному origin; login і register поза периметром |
| безпечні помилки і `traceId` | витік внутрішніх деталей | 8.1, `ProductionErrorTests` | не замінює контроль доступу до журналів |
| заголовки nosniff, no-referrer | MIME sniffing, витік referrer | 8.2, `BrowserSecurityTests` | не замінюють правильний Content-Type і заборону секретів в URL |
| CSP з `frame-ancestors 'none'` | injection-наслідки, clickjacking | 8.2, 8.4, `BrowserSecurityTests` | не замінює safe DOM; Scalar у Development поза CSP |
| точний CORS | читання відповіді чужим origin | 8.7, `Cors_*` | не замінює authN, authZ, antiforgery |
| resource-based authorization | IDOR/BOLA | A-01…A-12 (ЛР 4) | не замінює authentication |
| server-side validation | некоректні дані | T-*, `CreateIncidentTests` | не замінює авторизацію |
| параметризований пошук з екрануванням LIKE | SQL injection | S-02, T-04, `SearchSecurityTests` | лише цей маршрут пошуку |
| safe DOM | XSS | REG-XSS-01, `ClientScripts_DoNotUseDangerousHtmlSinks` | не замінює CSP |
| login limiter | перебір паролів | 8.5, `LoginRateLimitTests` | in-memory, ключ IP |
| search limiter | зловживання пошуком | 8.5, `SearchRateLimitTests` | in-memory, не замінює авторизацію |
| audit events triage | відсутність підзвітності | F-03, `TriageAuditTests` | консольний журнал, без захисту цілісності |
| `.gitignore`, `.env.example`, `--locked-mode` | витік конфігурації, неконтрольована зміна залежностей | 9.1, 9.2 | історія Git поза п'ятьма файлами не перевірялась |

Периметр змінювальних маршрутів, контракт antiforgery і REG-CSRF-01 описано в розділі 8.3.
## 9. Dependency and secret audit

### 9.1. Огляд відстежуваної конфігурації (етап 1, п. 3)

Стан: commit `00cf249ebc4d07971b3798ea06433b2824ed45db`, лише tracked files, дата 2026-11-16.

Команди:

```
git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'
git check-ignore -v infra/.env src/SecureLab.Api/appsettings.Local.json
git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .
git log --all -p -- <кожен конфігураційний файл>
```

Перша команда повернула чотири конфігураційні файли: `infra/.env.example`, `infra/compose.yaml`, `src/SecureLab.Api/appsettings.json`, `src/SecureLab.Api/appsettings.Development.json`. Друга команда (код завершення 0) показала, що `infra/.env` (правило `.gitignore:15`) і `appsettings.Local.json` (`.gitignore:18`) ігноруються. Третя команда дала 112 збігів. Широкий шаблон збігається з назвами полів, тому кожен збіг я класифікував за контекстом.

| Де | Кількість збігів | Контекст | Рішення | Причина і межа |
|---|---|---|---|---|
| `infra/compose.yaml:9`, `src/SecureLab.Api/appsettings.Development.json:3`, `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` | 3 | значення `local-study-password` для локальної БД, порт прив'язаний до 127.0.0.1 | accepted, study-only | відкрите навчальне значення, `README.md:63` забороняє повторне використання. Не поширюється на інші БД і середовища. Три значення узгоджені між собою, тому їх не видаляв. |
| `src/SecureLab.Api/Data/DbSeeder.cs` | 12 | код читає ключ `SeedUsers:Password`, значення немає | не секрет, джерело конфігурації | пароль seed задається змінною середовища поза Git |
| `tests/SecureLab.Api.Tests/*.cs` | 49 | читання `SeedUsers__Password` із середовища та вигадані негативні рядки на кшталт `Wrong-Password-1!` | не секрет | значення з Git не береться, негативні рядки не відповідають жодному акаунту |
| `tests/http/lab-04-access.http` | 6 | `{{$processEnv SeedUsers__Password}}` | не секрет | підстановка зі змінної середовища |
| `src/SecureLab.Api/Scaffolding/Lab03Identity.cs`, `Client/auth-lab.js`, `Client/auth-lab.html` | 16 | назви полів DTO, поле форми, правила валідації | не секрет | значень немає |
| `src/SecureLab.Api/Data/Migrations/*` | 4 | колонка `PasswordHash` | не секрет | назва колонки |
| `.gitignore:14`, `README.md:63,138`, `docs/browser-security-evidence.md`, `docs/git-workflow.md:124` | 6 | пояснення в документації | не секрет | тексти без значень |
| `docs/report-lab-05.md`, `docs/report-lr03.md` | 14 | згадки в звітах | не секрет | тексти без значень |
| `*/packages.lock.json` | 2 | ідентифікатор пакета `Microsoft.Extensions.Configuration.UserSecrets` | не секрет | назва залежності |

Сума за групами: 3 + 12 + 49 + 6 + 16 + 4 + 6 + 14 + 2 = 112, що збігається з кількістю рядків виводу (`git grep -c` по файлах). Кількість для final commit я перерахую окремо, бо мої нові docs її змінять.

`infra/.env.example` містить лише `POSTGRES_PORT=54329` і коментар, значень credentials немає.

Історія: для п'яти конфігураційних файлів (`infra/compose.yaml`, `appsettings.json`, `appsettings.Development.json`, `infra/.env.example`, `SecureLabDesignTimeDbContextFactory.cs`) я переглянув `git log --all -p`. Кожен файл має по одному коміту в історії, єдине значення пароля в них `local-study-password`. Інших значень немає.

Межа висновку: перевірено tracked files цього commit і історію лише названих п'яти файлів. Не перевірено stash, чужі клони, видалені refs, зовнішній CI і untracked файли. Збіг шаблону з назвою поля не доводить відсутності секрету в інших словах (`token`, `connectionstring` я додатково не шукав у цьому кроці).

Для реального витоку одного видалення з останнього commit було б недостатньо: значення лишається в історії, клонах і кешах, тому credential відкликають або замінюють (rotate). Тут такого витоку не виявлено, `local-study-password` є відкритим навчальним значенням.

### 9.2. Dependency audit (етап 3, п. 1-2)

Дата 2026-11-16, SDK 10.0.402, корінь solution. Команди й результат:

| Команда | Код завершення | Результат |
|---|---|---|
| `dotnet restore` | 0 | без помилок і без попереджень NU1901-NU1904 (раніше `restore --locked-mode` теж без помилок) |
| `dotnet package list --vulnerable --include-transitive` | 0 | джерела `https://api.nuget.org/v3/index.json` і локальний `C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\`; для `SecureLab.Api` і `SecureLab.Api.Tests` повідомлення: «не містить вразливих пакетів для поточних джерел» |
| `dotnet package list --outdated` | 0 | доступні лише мажорні оновлення (див. таблицю) |

`packages.lock.json` обох проєктів після перевірки не змінились (`git status` не показує їх).

Advisories для прямих і транзитивних пакетів не знайдено, тому окремих `dotnet nuget why` і аналізу досяжності не було потреби виконувати. Це не доказ безпеки пакетів: джерело повідомляє лише про відомі на цю дату advisories для перевіреного набору версій, невідомі вразливості й досяжність коду не оцінювалися.

Таблиця рішень (прямі пакети; транзитивні advisories відсутні):

| Package | Version | Direct / transitive | Advisory / severity | Чи використовується relevant functionality | Доступне оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| Microsoft.AspNetCore.Identity.EntityFrameworkCore | 10.0.10 | direct | немає | не застосовується | 11.0.0 | не оновлюю: advisory немає, 11.0.0 мажорне й може змінити API та target framework |
| Microsoft.AspNetCore.OpenApi | 10.0.10 | direct | немає | не застосовується | 11.0.0 | не оновлюю, причина та сама |
| Microsoft.EntityFrameworkCore (+ `.Relational`, `.Design`) | 10.0.10 | direct | немає | не застосовується | 11.0.0 | не оновлюю, причина та сама |
| Microsoft.OpenApi | 2.7.5 | direct | немає | не застосовується | 3.11.0 | не оновлюю: мажорне оновлення, advisory немає |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | direct | немає | не застосовується | немає | оновлення не потрібне |
| Scalar.AspNetCore | 2.16.16 | direct | немає | лише Development (`MapScalarApiReference`) | 3.0.0 | не оновлюю: мажорне оновлення, пакет використовується лише в Development |
| тестові пакети: coverlet.collector 6.0.4, Microsoft.AspNetCore.Mvc.Testing 10.0.10, Microsoft.NET.Test.Sdk 17.14.1, xunit 2.9.3, xunit.runner.visualstudio 3.1.4 | | direct (лише тести) | немає | не входять до застосунку | мажорні | не оновлюю, не входять до runtime застосунку |

Придушень (`NuGetAuditSuppress`, `WarningsNotAsErrors`) я не додавав, `TreatWarningsAsErrors` лишається ввімкненим. Наступна дія: повторити `dotnet package list --vulnerable --include-transitive` перед кожним релізом; за появи advisory оцінити досяжність, а оновлення виконувати окремо з `restore`, `build`, повною регресією й закомітити оновлений lockfile разом із `.csproj`. Відповідальний: автор роботи.

### 9.3. Систематичний пошук у tracked files (етап 3, п. 3)

Межа в термінах Git: перевірено всі поточні tracked files (`git ls-files`), робоче дерево на 2026-11-16. Не перевірено: історію (крім п'яти конфігураційних файлів розділу 9.1), stash, інші клони, зовнішній CI.

Команди (в таблиці нижче на них посилається номер):

```
(1) git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .
(2) git grep -n -I -i -E 'token|connectionstring|bearer|private.?key' -- . ':(exclude)docs' ':(exclude)*packages.lock.json'
(3) git grep -n -I -i -E '(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}\.)' -- .
```

| Команда | Кількість matches | Рішення |
|---|---|---|
| (1) password, passwd, secret, api key | 112 на review-start commit (розбивка й класифікація кожної групи в розділі 9.1) | credentials немає; три відкриті навчальні значення `local-study-password` класифіковано accepted, study-only |
| (2) token, connectionstring, bearer, private key (без docs і lockfiles) | 116 | усі збіги це ідентифікатори коду (`CancellationToken`, змінна `token` у `csrf.js`, назви таблиць `identity_user_tokens`, `IsConcurrencyToken`) і згадки в README про `ConnectionStrings__SecureLab` без значень; значень credentials немає |
| (3) відомі формати ключів (AWS, PEM, JWT) | 0 | відомих форматів ключів немає |

Файл `infra/.env.example` містить лише `POSTGRES_PORT`. Кількості для final commit я перерахую окремо.

### 9.4. Діагностичний журнал і audit event (етап 3, п. 4)

Для перевірки я запустив другий екземпляр API (Development, порт 5081, `Logging__Console__IncludeScopes=true`), записав консольний журнал у файл поза репозиторієм (317 рядків), проганяв сценарії HTTP-скриптом на Node.js і шукав у файлі значення, яких там бути не повинно. Файл журналу й тимчасові значення після перевірки видалено.

| Сценарій | Що спостерігається в журналі (очищено) | Чого немає |
|---|---|---|
| успішний вхід | `Authentication event login: result success, user alice, trace <id>` | пароль, cookie, token |
| хибний пароль / невідомий користувач | `Authentication event login: result failure, trace <id>` (однаковий запис для обох випадків) | пароль, ім'я користувача, ознака існування акаунта |
| відмова захищеної дії | `authorization.denied subject=<id Alice> action=incident.triage resource=<id> result=denied at=<UTC> trace=<id>` | дані чужих користувачів, токени |
| помилка валідації (400 `status=Unknown`) | окремого запису немає, лише коректна 4xx відповідь | повне тіло запиту |
| відмова antiforgery (400) | окремого запису немає | значення токена |
| неочікувана помилка | `ExceptionHandlerMiddleware` з тим самим `TraceId`, що й у відповіді (розділ 8.1) | пароль, connection string |
| привілейований перехід | `authorization.allowed subject=<id Morgan> action=incident.triage resource=<id> result=allowed at=<UTC> trace=<id>` | credentials, dump моделі |

Підрахунок збігів у файлі журналу (команди `grep -c -F`/`-i -E`): пароль seed 0, вигаданий пароль `NotARealPassword1!` 0, `cookie:|set-cookie` 0, `x-csrf-token` 0, чотири значення cookie сеансу й antiforgery token, зібрані під час сценаріїв, у журналі не знайдені (0 з 4). Висновок обмежений цими сценаріями, цим sink (консоль) і цим запуском. Додатково: EF Core пише SQL-команди на рівні Information, але значення параметрів замасковано як `'?'`, тому значення пошукових рядків і ідентифікаторів у журнал не потрапляють.

Спостереження: успішний вхід записує `user alice` (ім'я користувача), це мінімальний суб'єктний ідентифікатор, інших персональних даних запис не містить. Структуровані повідомлення використовують шаблони з параметрами, а не конкатенацію введення, тому ввід користувача не будує текст повідомлення.

Audit trail привілейованого переходу `Incident.Status`: дозволений перехід Morgan (Analyst) і відмова Reporter без зміни ресурсу відтворено тестом `TriageAuditTests` (див. F-03) і в HTTP-проході вище (Morgan 200, Alice 403).
## 10. Residual risks
| Ризик | Статус | Компенсація | Наступна дія і відповідальний |
|---|---|---|---|
| `login` і `register` без antiforgery (login-CSRF, створення акаунта зі сторонньої сторінки) | прийнято | login limiter, однакова 401, відсутність чутливих даних у сеансі | окремий анонімний bootstrap токена у разі реального deployment; автор |
| обидва rate limiter in-memory, не спільні між екземплярами, login за IP | прийнято | окремий лічильник на екземпляр, квота на користувача для search | спільне сховище лічильників (у цій роботі не входить до рівня); автор |
| audit і журнали лише в консолі | прийнято | у записах немає credentials | захищене сховище з контролем цілісності й строками зберігання; автор |
| HTTPS, redirect і HSTS не перевірялися (локальний HTTP) | не перевірено | cookie `Secure` у Production | перевірити на реальному deployment з TLS; автор |
| `AllowedHosts: *` | не перевірено | локальний стенд | обмежити перелік хостів для deployment; автор |
| токен antiforgery доступний коду на власному origin (XSS) | залишається | safe DOM, CSP, REG-XSS-01 | не знімається цією роботою; автор |
| невідомий `/api/...` без розширення повертає 200 `text/html` (fallback `index.html`) | спостережено, без експлуатації | клієнт API перевіряє статус і Content-Type | розглянути 404 JSON для невідомих `/api/*`; автор |
| ручні `.http` процедури ЛР 2 і 4 не отримують токен | відомо | автоматизовані A-тести | оновити файли або вилучити; автор |
| історія Git, stash, чужі клони, зовнішній CI не перевірялися, Scalar у Development без CSP | не перевірено | рішення ЛР 5 | у межах огляду не входило |

## 11. Conclusion
У межах цього огляду (локальний стенд, commit початку `00cf249`) три власні знахідки виправлено й підтверджено retest та positive regression, а повний набір із 96 тестів проходить після reset. Висновок обмежується перевіреними сценаріями: він не означає, що вразливостей немає, і не стосується production-інфраструктури, TLS, зовнішніх залежностей поза відомими advisories цього джерела та історії Git. Пункти відмінного рівня (третя знахідка поза чек-листом, пріоритизація, доказ відсутності чутливих даних у шести логах, зв'язок asset → threat → control → verification для всіх активів, погоджене розширення) не входять до обраного рівня.

## 12. Evidence appendix
Усі докази без паролів, cookie, токенів і повних журналів. Шляхи відносно кореня проєкту.

| ID | Що доводить | Де лежить / як повторити | Результат |
|---|---|---|---|
| EV-01 | Production-профіль активний | `docs/evidence/lab06/01-production-env.png`, SHA-256 `ab085cc0bb7e4acc80b4d7ce52c20d1c4f274edbea0856e9c8622063f2fa6acc` | `Hosting environment: Production` |
| EV-02 | безпечна 500 із `traceId` | `docs/evidence/lab06/02-prod-500-response.png`, SHA-256 `c7a5c37ddf76bc334b39f8ae2c5ce820d5d7c2b30b8d7ea50d727fb93e9f0c32` | 500 `application/problem+json`, без stack trace |
| EV-03 | той самий `TraceId` у журналі | `docs/evidence/lab06/03-prod-500-log.png`, SHA-256 `7436b0ed4ca912fda769476fc1d888f246823ee547da47ecca01925ac6b9e250` | `ExceptionHandlerMiddleware` із `84f5d841…97c` |
| EV-04 | helper отримує токен і створює запис | `docs/evidence/lab06/04-csrf-flow-ok.png`, SHA-256 `2db418620dc7325f5d5b76f7e89df9599d9b43c745f84fde57d98b17496a1f18` | `csrf-token` 200, `incidents` 201 |
| EV-05 | запит без токена відхилено | `docs/evidence/lab06/05-csrf-missing.png`, SHA-256 `f8fd27635d22f344cfb89ea97ba514a9689352287b349605ffbce5f881757099` | 400 Problem Details |
| EV-06 | CORS, дозволений origin | `docs/evidence/lab06/06-cors-allowed.png`, SHA-256 `07bb0c3f3a283047a67d7807f90ebcd05d93b8bccd6e2cbcc4285b00628b49f5` | `Access-Control-Allow-Origin: http://localhost:4173` |
| EV-07 | CORS, недозволений origin | `docs/evidence/lab06/07-cors-disallowed.png`, SHA-256 `4f7d5e97d6bd67492a035a2054cdd286ce43249e343d0b835fce8c3c4d5328eb` | 200 без `Access-Control-*`, відповідь сторінці не видана |
| EV-08 | повний набір тестів | `dotnet test SecureLab.sln -c Release` після `--reset-database` на `b78e5bd` | 96 пройдено, 0 збоїв |
| EV-09 | REG-CSRF-01 | `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~CsrfProtectionTests"` | пройдено; без фільтра на PUT падає |
| EV-10 | F-01 | `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~ProductionErrorTests"` | пройдено; до виправлення падав |
| EV-11 | F-03 | `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~TriageAuditTests"` | пройдено; до виправлення падав |
| EV-12 | limiters | `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RateLimitTests"` | пройдено |
| EV-13 | журнал без чутливих даних | скрипт сценаріїв і `grep -c` по файлу журналу (розділ 9.4) | 0 збігів із паролями, cookie й токенами |
| EV-14 | аудит залежностей | `dotnet package list --vulnerable --include-transitive` (розділ 9.2) | вразливих пакетів немає |
| EV-15 | браузерний DOM-тест REG-XSS-01 | `tests/browser/description-dom.js` у Chrome | 15 PASS, `RESULT: PASS` |

Знімки EV-01…EV-07 справжні: EV-01…EV-03 зроблено мною системним знімком екрана з термінала VS Code, EV-04…EV-07 це кадри з DevTools справжнього Chrome, яким керував скрипт через DevTools Protocol (кожен кадр складено з двох справжніх знімків: сторінка й DevTools). Передача: гілку `lab/6-hardening-review`, `main` і тег `v1.0.0` передано в репозиторій https://github.com/AndriiShuplik/Lab1_Shuplik; результат `git rev-list -n 1 v1.0.0` дорівнює hash на першій сторінці PDF.

Відмінність від методики: гілку `lab/6-hardening-review` створено від `main` (різниця з `v0.5.0` лише `docs/`).
