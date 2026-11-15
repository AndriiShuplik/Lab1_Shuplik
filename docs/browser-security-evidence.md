# Докази безпеки браузера (DEL-01)

Рівень: відмінний («Відмінно»). Паролі, cookie/token values і export browser storage сюди не записую.

## Стенд і Git-стан

- ОС: Windows 10 Pro. Браузер: Chrome 157.0.8103.78 (керований через DevTools Protocol, скріншоти й журнал Network записано скриптом). .NET SDK 10.0.402, PostgreSQL 18 у Docker Compose.
- API і штатний клієнт: `http://localhost:5080`. Probes: `http://localhost:4173` (дозволений) і `http://localhost:4174` (контроль).
- Scaffold: release `lab-05-start-v1`, `base_commit` = `7ce14f164eeb8f4b5eaa9299596c19ecbf884118` (fixed commit ЛР 4, тег `v0.4.0`), `entry_parent` = `1611825d420aab6b93f846c9f28428ea385916ba`.
- Гілка `lab/5-browser-xss` створена від `main` (1611825, тільки звіт ЛР 4 поверх `v0.4.0`).
- Scaffold commit: `4a70603` («lab5: install scaffold lab-05-start-v1 (vulnerable state)»), у ньому лише квитанція й probes.
- Vulnerable commit: `0ea0de4` («lab5: add browser-lab page (vulnerable innerHTML sinks)»), перший commit із небезпечними sinks у `browser-lab.js`.
- Seed-коментар з marker, DOM-тест і карта: окремий commit «observation» (hash додано нижче).
- Fixed commit, `v0.5.0`, `main`, спосіб передавання: заповнюю наприкінці.

Механізм сеансу (Application → Cookies → `http://localhost:5080`), без Value:

| Назва | Domain | Path | HttpOnly | SameSite | Secure |
|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | localhost | / | так | Lax | ні (HTTP-стенд) |

## Гіпотеза й REG-XSS-01

Карта: `docs/source-to-sink.md`. Гіпотеза: значення з поля `description` форми `#edit` зберігається в `incidents.description`, повертається через JSON-поле `description` відповіді `GET /api/incidents/{id}` і передається в `#description.innerHTML` як HTML-контекст; тому за умови, що значення містить схожий на тег рядок, браузер може інтерпретувати дані не як звичайний текст. Те саме для `comments[].text` → `paragraph.innerHTML`.

Передумови: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`; `SeedUsers__Password` задано в поточному терміналі; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`; користувачі alice, morgan, bob; marker береться з `Lab_5/lab05-marker.txt`.

### Стан «до» (vulnerable, `browser-lab.js` без змін)

| Спостереження | До fix |
|---|---|
| Значення в БД/API | `incidents.description` і `description` у JSON дорівнюють marker (`psql`, Network) |
| DOM основного Description | у `#description` створено дочірній елемент `<img src="x" onerror="...">`, значок «зламаного» зображення |
| Дія marker | `data-lab05-marker="executed"` на `#lab05-marker-target`; перед створенням було `null` |
| Апостроф/лапки | показано як текст, 0 елементів |
| `5 < 7 і 9 > 3` | показано як текст (`<` перед пробілом не початок тегу) |
| Unicode `Київ — Ω` | показано як текст |
| `<b>жирний</b> текст` | **створено елемент `<b>`**, дужки зникли |
| Довжина 4000 символів | показано повністю, 0 елементів |
| Вікно Morgan | `GET: 200`, marker `executed`: stored XSS у сеансі Analyst |
| Контроль Bob | `GET: 404`, marker `null` |
| Seed-інцидент `…0003` з `<script>` | видно лише слово «Текст», решта пропала в невиконаному `<script>` |
| Seed-коментар `…0005` у інциденті Alice | `<img>` у `#comments`, marker `executed` |

Фактичні відповіді й DOM збережено скриптом (`res-vuln.json`), скріншоти у звіті.

DOM-тест `tests/browser/description-dom.js`, vulnerable: `RESULT: FAIL`, 9 з 14 перевірок не пройдено (Description, comments, `<b>` у позитивних рядках).

### Finding

| Пункт | Опис |
|---|---|
| Актив | сеанс браузера й дані, доступні від імені користувача (Analyst Morgan читає записи інших) |
| Передумови | тестовий акаунт з правом створити інцидент (Alice), контроль над текстовим полем |
| Першопричина | недоведене значення з API потрапляє в HTML-контекст: `#description.innerHTML = current.description` і `paragraph.innerHTML = comment.text` у `browser-lab.js`, функція `load()` |
| Вплив на стенді | marker виконав лише безпечну локальну дію: атрибут на `#lab05-marker-target` |
| Виправлення | текстовий вузол через єдиний helper `renderText` (`createElement` + `textContent`) для Description і коментарів; значення в БД не змінюю |
| Retest | той самий marker, той самий запис і reset-процедура; DOM-тест FAIL → PASS |
| Залишковий ризик | інші поля й екрани в майбутньому; сторонні скрипти; CSP лише додатковий шар |
