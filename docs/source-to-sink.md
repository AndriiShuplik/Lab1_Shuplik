# Карта source-to-sink (ЛР 5, DEL-01)

Рівень: відмінний («Відмінно»). Baseline 2-A. Стан для карти: vulnerable commit `0ea0de4` (scaffold `lab-05-start-v1` плюс сторінка `browser-lab`), клієнт `src/SecureLab.Api/Client/browser-lab.js`.

## Потік 1. Incident.Description

Запис для спостереження: Guid створюється на стенді при кожному reset, тому в таблиці дано шлях, а не фіксований Guid. Значення: канонічний harmless marker з `Lab_5/lab05-marker.txt`.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `browser-lab.html`, поле `<textarea name="description">` форми `#edit` | рядок, який вводить користувач | контрольоване користувачем |
| Request | `browser-lab.js`, обробник submit форми `#edit`: `fetch("/api/incidents", { method: "POST" ... })` | JSON-поле `description` у тілі `POST /api/incidents` | Network: POST 201, payload містить marker; контрольоване користувачем |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`, `CreateIncidentRequest.Description` → `Incident.Description` | обов'язковий, не довше 4000 символів, `Trim()` | перевірка формату, не очищення від HTML: значення не стає довіреним |
| Storage | сутність `Incident`, таблиця `incidents`, колонка `description` | marker збережено без змін | `psql`: `description` дорівнює marker; збережене значення користувача |
| Response | `Application/Incidents/IncidentQueries.cs`, `GetDetailsAsync` → `Presentation/Contracts/IncidentResponses.cs`, `IncidentDetailsResponse.Description` | JSON-поле `description` у `GET /api/incidents/{id}` | Network: GET 200, у JSON те саме значення (лапки як `\"`, це запис JSON); недовірене для відображення |
| Client transform | `browser-lab.js`, `load()`: `current = await response.json()` | `current.description` | перетворення відсутнє: значення передається далі без змін |
| Sink/context | `browser-lab.js`, `load()`: `document.querySelector("#description").innerHTML = current.description` | елемент `<div id="description">` | небезпечний sink, контекст HTML parser: рядок стає елементом `<img>` |

Класифікація: stored XSS (значення спершу зберігається в PostgreSQL і виконується під час наступного перегляду) з DOM-based sink на клієнті (небезпечне перетворення виконує JavaScript через `innerHTML`). Reflected XSS у цій роботі не відтворюю: у спільному scope його окремого flow немає.

## Потік 2. IncidentComment.Text (Добре / Відмінно)

Source у продукті: будь-який автор коментаря. Endpoint створення коментаря в успадкованому API немає, тому на стенді source: seed-коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal=false`, інцидент Alice `20000000-0000-0000-0000-000000000001`), доданий у `Data/DbSeeder.cs`, `SeedAsync`.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker` | marker у `IncidentComment.Text` | синтетичний seed; у продукті контрольоване користувачем |
| Request | відсутній: коментар не створюється через API | | GET `/api/incidents/{id}` лише читає |
| Validation/mapping | відсутнє | | |
| Storage | сутність `IncidentComment`, таблиця `incident_comments`, колонка `text` | marker без змін | `psql`: `text` дорівнює marker |
| Response | `IncidentQueries.GetDetailsAsync` → `IncidentCommentResponse.Text`; для Reporter відфільтровано internal | `comments[].text` | Network: GET 200, `comments[1].text` містить marker; недовірене |
| Client transform | `browser-lab.js`, `load()`: цикл `for (const comment of current.comments ?? [])` | `comment.text` | без змін |
| Sink/context | `browser-lab.js`, `load()`: `paragraph.innerHTML = comment.text` | абзац `<p>` у `<div id="comments">` | небезпечний sink, HTML parser |

## Інвентаризація DOM sinks у `src/SecureLab.Api/Client/`

| Файл і місце | Дані, що потрапляють у sink | Категорія даних | Контекст | Рішення |
|---|---|---|---|---|
| `browser-lab.js`, `load()`: `#title.textContent = current.title` | `title` | збережене значення користувача | текстовий вузол | безпечно, лишаю |
| `browser-lab.js`, `load()`: `#description.innerHTML = current.description` | `description` | збережене значення користувача | HTML parser | небезпечно: замінити safe helper (текстовий вузол) |
| `browser-lab.js`, `load()`: `paragraph.innerHTML = comment.text` | `comments[].text` | збережене значення користувача | HTML parser | небезпечно: замінити тим самим helper |
| `browser-lab.js`: `#status.textContent = \`GET: ${response.status}\`` | HTTP status | server-generated | текстовий вузол | безпечно |
| `browser-lab.js`: `elements.description.value = current.description` | `description` | збережене значення користувача | значення поля форми (властивість `value`) | безпечно: значення не розбирається як HTML |
| `browser-lab.html`: статичний шаблон | literal | trusted constant | HTML | допустимо: user data немає |
| `app.js`: `createTextElement(tag, text, className)` та `textContent` | `title`, `status`, `ownerDisplayName` тощо | збережене значення користувача / server-generated | текстовий вузол | безпечно (перевірено ще в ЛР 4: `innerHTML` у `app.js` немає) |
| `auth-lab.js`: `renderProfile` через `textContent` | профіль | server-generated | текстовий вузол | безпечно |
| Динамічні URL-атрибути (`href`, `src`) з даних | не використовуються | | URL | відсутні; для демонстрації контексту використаю `safe-url.js` |
| `eval`, `new Function`, string handler | не використовуються | | code | відсутні |
| Сторонні скрипти (`<script src>`) | не використовуються | | | відсутні; залишковий ризик описано в звіті |

Третього прихованого sink у клієнті немає: `innerHTML` трапляється рівно двічі (опис і коментарі).
