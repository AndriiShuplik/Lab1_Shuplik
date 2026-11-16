# F-02. Cookie-маршрути, що змінюють стан, не перевіряють antiforgery token

**Статус:** Fixed
**Актив:** право власника змінювати й видаляти власні інциденти, привілейований перехід `New → Triaged`, цілісність сеансу (logout)
**Компонент:** усі browser-accessible маршрути, що довіряють authentication cookie: `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `POST /api/auth/logout`
**Пріоритет:** P2

## Передумови і межі огляду

Review-start commit `00cf249ebc4d07971b3798ea06433b2824ed45db`, Development, `http://localhost:5080`, користувачі Alice (Reporter) і Morgan (Analyst). Початковий стан: `dotnet run --project src/SecureLab.Api -- --reset-database`. Усі перевірки через тестовий host (`https://localhost`, cookie-клієнт) і локальну БД зі штучними даними. Поза межами: `POST /api/auth/login` і `POST /api/auth/register` (не довіряють наявній authentication cookie, окреме рішення нижче).

## Відтворення

1. Alice входить через `CookieClient.LoginAsync`, отримує authentication cookie.
2. У БД створено інцидент Alice зі значенням заголовка `T`.
3. `PUT /api/incidents/{id}` з валідним JSON, але без жодного antiforgery token.
4. Очікувано: узгоджений 4xx і заголовок лишається `T`. Фактично на коді без валідації: 200 OK (обробник `UpdateAsync` повертає 200 лише після `SaveChangesAsync`, тобто запит без токена виконав зміну). Тест REG-CSRF-01 на цьому стані падає на `Expected: BadRequest, Actual: OK`.
5. Для `POST /api/incidents`, `DELETE`, `POST .../triage` і `POST /api/auth/logout` на review-start commit жодної перевірки немає: `git grep -n -i -e antiforgery -e csrf 00cf249 -- src tests` дав 0 збігів, у конвеєрі відсутні `AddAntiforgery` і будь-який фільтр.

## Вплив і ймовірність

**Статус перевірки:** для PUT спостережено локально (запуск тесту з вимкненим фільтром), для решти маршрутів оцінено за кодом і конфігурацією.

Browser автоматично додає authentication cookie до запитів на цей сайт, тому сторінка в тому самому браузері користувача могла б ініціювати зміну або видалення його інцидентів, створення запису, triage або logout без його волі. Impact Medium (неавторизована зміна власних даних, видалення тільки в статусі New). Likelihood Medium: потрібен користувач із чинним сеансом, що відкриває чужу сторінку. Частково ризик зменшують `SameSite=Lax`, `Content-Type: application/json` (preflight) і точний CORS, але вони не гарантовані: same-site сторінка на іншому порту `localhost`, зміни правил браузерів, ендпоінт, що колись прийме форму. Тому P2.

## Першопричина

Сервер вважав достатнім наявність authentication cookie для змінювальної дії і не вимагав від клієнта другої половини доказу свідомої дії (request token). Antiforgery-сервіс, маршрут видачі токена і клієнтський helper у проєкті були відсутні.

## Виправлення

Fixed commit: `f6d2315fd896f8ca76080df9c4a11172331be25f`.

- Реєстрація стандартного `IAntiforgery`: header `X-CSRF-TOKEN`, cookie `SecureLab.Antiforgery` (HttpOnly, SameSite=Strict, Secure поза Development), `src/SecureLab.Api/Security/CsrfEndpoints.cs`.
- Маршрут видачі `GET /api/auth/csrf-token` лише для автентифікованого користувача, повертає `{ "token": ... }`; cookie-частину ставить framework.
- Один спільний `AntiforgeryFilter` (`src/SecureLab.Api/Security/AntiforgeryFilter.cs`): викликає `ValidateRequestAsync` до зміни стану, `AntiforgeryValidationException` перетворює на 400 Problem Details з `title = "Antiforgery token is missing or invalid."`. Підключено явно (`AddEndpointFilter<AntiforgeryFilter>()`) до п'яти cookie-маршрутів. До `logout` додано також `RequireAuthorization()`, щоб анонімний запит давав 401, а не 400.
- Клієнтський helper `src/SecureLab.Api/Client/csrf.js` (токен лише в пам'яті сторінки, ледача видача перед першою мутацією, скидання після login і logout та при `pageshow`, без автоматичного повтору після 4xx), підключений перед page script на `auth-lab.html` і `browser-lab.html`; `auth-lab.js` і `browser-lab.js` викликають мутації через `SecureLabCsrf.mutate`.
- Узгоджені з цим наявні мутаційні тести: токен після входу додається лише там, де мутація є передумовою (`SessionsFixture`, `CreateIncidentTests`, A-04, A-05, A-06). Негативна частина REG-CSRF-01 токена не має, глобально в harness його не додавав.

## Retest

Той самий сценарій після виправлення: `PUT` без header → 400 `application/problem+json`, `title = "Antiforgery token is missing or invalid."`, без `errors`, є `traceId`; повторне читання й запит у БД показують незмінні `title` і `description`. Те саме для невалідного значення header (`not-a-real-token`). Для `POST /api/incidents` без токена запису з таким заголовком немає, для `DELETE` запис лишається, для `triage` статус лишається `New`, для `logout` сеанс лишається чинним (`/api/auth/session-check` → 204). Токен, виданий Alice, не діє в сеансі Bob (400, стан незмінний). Команда: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~CsrfProtectionTests"`.

Перевірка чутливості: після тимчасового вилучення фільтра з `PUT` ці тести падали (`Expected: BadRequest, Actual: OK`), після відновлення фільтра проходять.

## Positive regression

З валідною парою (cookie `SecureLab.Antiforgery` + request token у `X-CSRF-TOKEN`, отриманий тим самим клієнтом після входу): `PUT` → 200, наступне читання показує нові `title` і `description` (REG-CSRF-01); `POST /api/incidents` → 201, запис існує; `POST /api/auth/logout` → 204, далі `session-check` → 401 (`ValidPair_AllowsCreate_AndLogout`). Повний набір після виправлення: 91 з 91 (`dotnet test SecureLab.sln -c Release`).

## Наслідки для попередніх перевірок

Браузерний DOM-тест REG-XSS-01 (`tests/browser/description-dom.js`) створював запис через `fetch` без токена і після виправлення перестав би працювати. Я адаптував його: створення тепер іде через `window.SecureLabCsrf.mutate`. Після цього тест у справжньому Chrome дав 15 PASS і `RESULT: PASS`. Ручні процедури `tests/http/lab-02-checks.http` (ЛР 2, анонімні запити) і `tests/http/lab-04-access.http` (мутації PUT, DELETE, POST create і triage після входу) токена не отримують і не входять до regression pack ЛР 6: їхні сценарії покриті автоматизованими тестами A-02…A-07. Для повторного запуску змінювальних запитів із цих файлів вручну потрібно спочатку викликати `GET /api/auth/csrf-token` тим самим cookie-сеансом і передати значення в header `X-CSRF-TOKEN`.

## Залишковий ризик

- `POST /api/auth/login` і `POST /api/auth/register` не входять до cookie-периметра (не довіряють наявній cookie) і antiforgery не мають: захист токеном, який можна одержати лише після входу, неможливий без окремого анонімного bootstrap. Login-CSRF (вхід у чужий акаунт) і створення акаунта зі сторонньої сторінки лишаються прийнятим ризиком з компенсацією: login limiter, однакова відповідь для невідомого користувача й хибного пароля, відсутність чутливих даних у сеансі.
- Код, що виконується на нашому origin (XSS), прочитає токен так само, як helper: antiforgery не замінює safe DOM (його перевірено окремо в REG-XSS-01).
- Origin з дозволеним CORS-доступом із credentials міг би прочитати токен, тому allowlist лишається точним (REG-CORS-01).
- Браузерний walkthrough усіх мутацій клієнта і поведінка простроченого токена окремо описані в розділі 8.3 review.

## Доказ

Тести `CsrfProtectionTests` (`RegCsrf01_PutWithoutOrWithInvalidToken_IsRejected_StateIsUnchanged_ValidPairSucceeds`, `Perimeter_EveryCookieMutation_RejectsMissingToken_AndKeepsState`, `Token_IssuedForAnotherUser_IsRejected_AndStateIsUnchanged`, `TokenRoute_WithoutSession_Returns401`, `ValidPair_AllowsCreate_AndLogout`), команди вище. Cookie, токени й пароль у доказах не зберігаються.
