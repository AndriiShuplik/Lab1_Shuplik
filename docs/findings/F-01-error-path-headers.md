# F-01. Відповідь 500 без браузерних заголовків безпеки

**Статус:** Fixed
**Актив:** захисні заголовки браузера (nosniff, Referrer-Policy, CSP з `frame-ancestors 'none'`) для кожної відповіді API
**Компонент:** конвеєр middleware в `src/SecureLab.Api/Program.cs` (порядок `UseExceptionHandler` і middleware заголовків)
**Пріоритет:** P3

## Передумови і межі огляду

Review-start commit `00cf249ebc4d07971b3798ea06433b2824ed45db`, гілка `lab/6-hardening-review`. Production-like профіль (`Production.ps1`, без launch profile), локальна БД навмисно недосяжна (порт 54399, значення вигадані). Анонімний публічний `POST /api/auth/login` з синтетичним паролем. Reset не потрібен: сценарій не змінює дані. Поза межами: інші класи помилок, HTTPS і HSTS.

## Відтворення

1. Зупинити API, запустити в Production з недосяжною БД: змінна `ConnectionStrings__SecureLab` з портом 54399, `Include Error Detail=false`.
2. Надіслати `POST http://localhost:5080/api/auth/login` з тілом `{"userName":"alice","password":"NotARealPassword1!"}`.
3. Очікувано: безпечна 500 і ті самі заголовки, що й на 200 і 404 (`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy`).
4. Фактично: 500 `application/problem+json` із `traceId`, але трьох заголовків немає (`docs/evidence/lab06/02-prod-500-response.png`). На 200 і 404 того ж профілю вони є.

Автоматичне відтворення: тест `ProductionErrorTests.UnexpectedError_InProduction_IsSafe_HasTraceId_AndKeepsBrowserHeaders` до виправлення падав на перевірці `X-Content-Type-Options` («The given header was not found»), хоча перевірки безпечного тіла й `traceId` перед цим проходили.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Відповідь 500 не розкриває внутрішніх даних, тож конфіденційність не порушена. Втрачено захист у глибину: браузер міг би інтерпретувати відповідь без `nosniff`, а CSP і `Referrer-Policy` для цього класу відповідей не діяли. Сценарій потребує збою всередині запиту (наприклад, недоступність БД), який анонімний користувач сам не викликає, а наслідок для самої відповіді `application/problem+json` малий. Impact Low, likelihood Low, тому P3.

## Першопричина

Middleware, що ставить заголовки, був зареєстрований після `UseExceptionHandler()`. Обробник винятків очищає заголовки відповіді перед формуванням `ProblemDetails`, тому заголовки, поставлені раніше в конвеєрі для цього запиту, зникали саме на шляху помилки. На успішних і очікуваних 4xx відповідях цього не відбувалося, тому розбіжність була непомітна.

## Виправлення

У `Program.cs` middleware заголовків перенесено перед `UseExceptionHandler()`, а самі заголовки встановлюються у `Response.OnStarting`, тобто безпосередньо перед відправленням відповіді, вже після очищення обробником. Рішення про виняток CSP для `/scalar` у Development зберігається (прапорець обчислюється на початку запиту). Другий паралельний catch-all не додавав. Тест `ProductionErrorTests` додано в `tests/SecureLab.Api.Tests/ProductionErrorTests.cs`. Fixed commit: `f6d2315fd896f8ca76080df9c4a11172331be25f` (змінено `src/SecureLab.Api/Program.cs`, додано `tests/SecureLab.Api.Tests/ProductionErrorTests.cs`).

## Retest

Той самий сценарій (Production-like host, недосяжна БД, публічний login із синтетичним паролем) у тестовому host з перевіреним `IHostEnvironment.EnvironmentName == "Production"`: 500 `application/problem+json`, `traceId` у форматі W3C, у тілі немає `Npgsql`, порту, вигаданого пароля й stack trace, є `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` і CSP з `frame-ancestors 'none'`. Сценарій позначено REG-ERR-01. Команда: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~ProductionErrorTests"`. Фактичний результат після виправлення: пройдено 1 з 1.

## Positive regression

Звичайні відповіді не змінилися: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~BrowserSecurityTests"` пройшов (18 тестів перевіряють CSP, nosniff і no-referrer на статичній сторінці, API, 4xx і 404, а також точні CORS-заголовки). Спільний запуск із новим тестом: пройдено 19 з 19. Повна регресія на final commit буде записана в розділі 7 review.

## Залишковий ризик

Перевірено лише клас «неочікувана 500 із недоступної БД». Інші джерела винятків ідуть тим самим шляхом, але я їх окремо не відтворював. Сторінка Scalar у Development навмисно без CSP. Реальний HTTPS і HSTS не перевірялися.

## Доказ

Файли `docs/evidence/lab06/02-prod-500-response.png` і `03-prod-500-log.png` (до виправлення), тест `ProductionErrorTests`, команди вище. Секретів, cookie і токенів у доказах немає; значення БД вигадані.
