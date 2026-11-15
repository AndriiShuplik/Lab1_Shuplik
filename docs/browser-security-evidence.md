# Докази безпеки браузера (DEL-01)

Рівень: відмінний («Відмінно»). Паролі, cookie/token values і export browser storage сюди не записую. Рисунки лежать у `docs/evidence/lab05/`, їхні номери збігаються зі звітом `docs/report-lab-05.md`.

## Стенд і Git-стан

- ОС: Windows 10 Pro. Браузер: Chrome 157.0.8103.78. .NET SDK 10.0.402, PostgreSQL 18 у Docker Compose, Python 3.14 для probes.
- API і штатний клієнт: `http://localhost:5080`. Probes: `http://localhost:4173` (дозволений) і `http://localhost:4174` (контроль).
- Scaffold: release `lab-05-start-v1`, `base_commit` = `7ce14f164eeb8f4b5eaa9299596c19ecbf884118` (fixed commit ЛР 4, тег `v0.4.0`), `entry_parent` = `1611825d420aab6b93f846c9f28428ea385916ba`.
- Гілка `lab/5-browser-xss` створена від `main` (1611825, тільки звіт ЛР 4 поверх `v0.4.0`).
- Scaffold commit: `4a70603f67a04376374a4ffdc41bd1a66a35381c` («lab5: install scaffold lab-05-start-v1 (vulnerable state)»), у ньому лише квитанція й probes.
- Vulnerable commit: `0ea0de49118159c46908bb7de95389cc0bbb18a2` («lab5: add browser-lab page (vulnerable innerHTML sinks)»), перший commit із небезпечними sinks у `browser-lab.js`.
- Seed-коментар, DOM-тест і карта: `96f3e99cbd715b711a2a4a8ba4b813a432e7948c`. Safe rendering: `5d377d807a36e3ceb9f2fce80f708d0daa244a32`.
- Fixed commit: `b77f2a3df8b77bda21c1a5ef8bc68a54bdb9faaf` («lab5: add exact-origin CORS policy, enforced CSP and browser security tests»). Тег `v0.5.0` (анотований) указує на нього.
- `main` і спосіб передавання: fast-forward `main` до гілки, `git push` гілки, тега і `main` до `https://github.com/AndriiShuplik/Lab1_Shuplik`.

Механізм сеансу (Application → Cookies → `http://localhost:5080`), без Value:

| Назва | Domain | Path | HttpOnly | SameSite | Secure |
|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | localhost | / | так | Lax | ні (HTTP-стенд) |

## Гіпотеза й REG-XSS-01

Карта: `docs/source-to-sink.md`. Гіпотеза: значення з поля `description` форми `#edit` зберігається в `incidents.description`, повертається через JSON-поле `description` відповіді `GET /api/incidents/{id}` і передається в `#description.innerHTML` як HTML-контекст; тому за умови, що значення містить схожий на тег рядок, браузер може інтерпретувати дані не як звичайний текст. Те саме для `comments[].text` → `paragraph.innerHTML`.

Передумови: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`; `SeedUsers__Password` задано в поточному терміналі; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`; користувачі alice, morgan, bob; marker з `Lab_5/lab05-marker.txt`.

Кроки: увійти як alice на `/auth-lab.html`; на `/browser-lab.html` виконати команду `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` (очікується `null`); створити запис із marker в описі; скопіювати Guid; у приватному вікні увійти як morgan, прочитати Guid і повторити команду; для коментаря відкрити як alice інцидент `20000000-0000-0000-0000-000000000001`; запустити `tests/browser/description-dom.js`.

| Спостереження | До fix (vulnerable `0ea0de4`) | Після fix (fixed `b77f2a3`) |
|---|---|---|
| Значення в БД/API | marker збережено без змін (`psql`, Network) | те саме значення, без змін |
| DOM основного Description | дочірній елемент `<img src="x" onerror="...">` | один текстовий вузол, `<img>` немає |
| Дія marker | `data-lab05-marker="executed"`, перед тим `null` | `null`, запиту `x` немає |
| Апостроф/лапки | текст, 0 елементів | текст, 0 елементів |
| `5 < 7 і 9 > 3` | текст | текст |
| Unicode `Київ — Ω` | текст | текст |
| `<b>жирний</b> текст` | елемент `<b>`, дужки зникли | текст із дужками, 0 елементів |
| Довжина 4000 символів | текст, 0 елементів | текст, 0 елементів |
| Вікно Morgan: GET і перевірка marker | `GET: 200`, `executed` (stored XSS) | `GET: 200`, `null` |
| Контроль Bob | `GET: 404`, `null` | `GET: 404`, `null` |
| Seed-інцидент `…0003` з `<script>` | видно лише слово «Текст» | видно все речення |
| Seed-коментар `…0005` в інциденті Alice | `<img>` у `#comments`, `executed` | текст, `null` |

### Finding

| Пункт | Опис |
|---|---|
| Актив | сеанс браузера й дані, доступні від імені користувача (Analyst Morgan читає записи інших) |
| Передумови | тестовий акаунт, що може створити інцидент (Alice), контроль над текстовим полем |
| Першопричина | недовірене значення з API потрапляє в HTML-контекст: `#description.innerHTML = current.description` і `paragraph.innerHTML = comment.text` у `browser-lab.js`, функція `load()` |
| Вплив на стенді | marker виконав лише безпечну локальну дію: атрибут на `#lab05-marker-target` |
| Виправлення | текстовий вузол через єдиний helper `renderPlainText` (`replaceChildren` + `createTextNode`) для Description і коментарів; значення в БД не змінюю |
| Retest | той самий marker, той самий порядок дій; DOM-тест FAIL → PASS |
| Залишковий ризик | нові екрани виведення; сторонній код; CSP лише додатковий шар |

Негативний контроль REG-XSS-01: на vulnerable commit marker виконується, DOM-тест дає `RESULT: FAIL`. На fixed: `RESULT: PASS`.

## CORS і REG-CORS-01

Прогноз (до зміни policy):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | CORS не потрібен |
| simple GET 4173 → API | так | ні | SOP/CORS, у відповіді немає Allow-Origin |
| simple GET 4174 → API | так | ні | origin не в allowlist |
| curl/.http → API | так | не застосовується | це не browser JavaScript |
| preflighted 4173 → API | OPTIONS; actual GET залежить від відповіді | ні без успішного preflight | preflight і CORS |

Команди запуску probes (з кореня проєкту):

```
py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe
```

Policy `Lab05BrowserProbe`: лише Development, один exact origin `http://localhost:4173`, метод GET, заголовок `X-Lab-Cors-Probe`, `AllowCredentials()`. Origin 4174 лишається негативним контролем. Це навчальний стенд, а штатна топологія same-origin `http://localhost:5080`.

| Клієнт / запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | 200 | 200 | CORS не потрібен |
| Allowed 4173, простий | TypeError, MissingAllowOriginHeader | `{status: 200}` | `Access-Control-Allow-Origin: http://localhost:4173` |
| Allowed 4173, з заголовком | OPTIONS 405, GET не надіслано | OPTIONS 204 + GET 200 | три `Access-Control-Allow-*` |
| Disallowed 4174, простий | TypeError | TypeError | GET дійшов до API, відповідь без `Access-Control-*` |
| Disallowed 4174, з заголовком | OPTIONS 405 | OPTIONS 204 без `Access-Control-*`, GET не надіслано | PreflightMissingAllowOriginHeader |
| Direct HTTP / curl | 200 | 200 | `Access-Control-Allow-Origin` лише для 4173 |

REG-CORS-01: browser evidence (probes 4173/4174, запит на абсолютну адресу API, `Origin` у Network) і HTTP evidence:

```
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" "http://localhost:5080/health"
```

Для 4173: `Access-Control-Allow-Origin: http://localhost:4173` і `Access-Control-Allow-Credentials: true`. Для 4174 жодного `Access-Control-*`; в обох відповідях 200, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Перевірка порядку UseCors: запит без cookie з 4173 до `/api/incidents` повертає 401, який JavaScript читає. Браузер блокує читання, але запит із 4174 виконано сервером: журнал API показав ще один виклик перевірки БД з `/health` (лічильник 10 → 11). CORS не зупиняє request і не замінює authorization та CSRF-захист.

## Додатково для Добре та Відмінно

Другий flow `IncidentComment.Text`: seed-коментар `30000000-0000-0000-0000-000000000005` (публічний, автор Morgan) до інциденту Alice `20000000-0000-0000-0000-000000000001`. До fix `<img>` у `#comments` і `executed`, після fix текст і `null`. Тести ЛР 4 не залежать від кількості коментарів, змін у них не було. Єдиний safe helper `renderPlainText` у `browser-lab.js` викликається для опису і для кожного коментаря.

Preflight: з 4173 `OPTIONS` 204 з `Access-Control-Allow-Origin: http://localhost:4173`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`, потім `GET` 200. З 4174 `OPTIONS` 204 без `Access-Control-*`, actual GET не надіслано. Cookie-дослід: 4173 з `credentials: "include"` отримує 200 з `Access-Control-Allow-Credentials: true`; 4174 у тому самому сеансі response не отримує (запит із cookie виконано); без `AllowCredentials()` відмова через `Access-Control-Allow-Credentials`; без входу 401 з 4173 читається. `AllowCredentials()` лишається лише в Development policy для 4173.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | fallback | `'self'` |
| script-src | `app.js`, `auth-lab.js`, `browser-lab.js` | `'self'`, без `unsafe-inline` |
| style-src | `styles.css`, `auth-lab.css` (inline `<style>` винесено в зовнішній файл) | `'self'` |
| connect-src | fetch до API на тому самому origin | `'self'` |
| img-src | зображень немає | `'self'` |
| frame-ancestors | вбудовування не потрібне | `'none'` |

Додатково: `font-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`. Місце зміни: наявна middleware заголовків у `Program.cs` (поруч із nosniff і Referrer-Policy), без другої middleware. `/scalar` у Development виключено з CSP.

Enforcement: документ 200, header `Content-Security-Policy` (один), три сторінки flow працюють без порушень; кероване порушення `new Image().src = "http://localhost:4173/x.png"` заблоковано (`The action has been blocked`, `blocked:csp`).

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` | MIME sniffing; не замінює правильний Content-Type |
| Referrer-Policy | `no-referrer` | зайве передавання referrer; клієнту посилання назовні не потрібні; не дозволяє класти secrets в URL |
| frame-ancestors | `'none'` | clickjacking через embedding; не замінює authorization і XSS fix |

Review XSS / CORS / CSRF / authorization: `docs/report-lab-05.md`, розділ 13.

## Додатково для Відмінно

DOM-тест: `tests/browser/description-dom.js` (вставляється в Console на `/browser-lab.html` після входу alice). Vulnerable (`0ea0de4` + seed): `RESULT: FAIL`, перевірки опису, коментарів і `<b>` не пройдено. Fixed (`b77f2a3`): `RESULT: PASS`, усі перевірки (marker, текстовий вузол, повторний render без дублювання, кожен `comments[].text`, позитивні рядки, 4000 символів).

CSP report-only → enforcement: спочатку header `Content-Security-Policy-Report-Only`; legitimate flow без порушень, кероване порушення лише записано («The policy is report-only»), marker через `innerHTML` на тимчасовому елементі виконався. Потім `Content-Security-Policy`: те саме порушення заблоковано, елемент `<img>` створено, але marker не виконався (CSP маскує небезпечний sink, тому висновок про fix роблю лише за DOM).

URL / атрибут: `tests/browser/safe-url.js` виводить `https://example.com/a`, `http://localhost:5080/incidents/1`, тричі `null`, `href` посилання і `null` для `onclick`. Для текстового вузла потрібні `textContent`/`createTextNode`, для атрибута дозволений атрибут і перевірка значення, для URL розбір `new URL` і allowlist протоколів, для JavaScript заборона `eval`/`new Function`/рядкових обробників. Third-party scripts у клієнті відсутні; ризик дає лише довідник Scalar у Development (виключений із CSP, окремий аудит у ЛР 6).

Автоматичні C# тести: `tests/SecureLab.Api.Tests/BrowserSecurityTests.cs` (18), разом 84 з 84.
