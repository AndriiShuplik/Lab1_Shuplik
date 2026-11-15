# Звіт ЛР 4. Авторизація, ролі та контроль доступу (SecureLab, 2-A)

Виконав: Шуплик Андрій Олександрович, КБ-41. Рівень: «Відмінно». Гілка: `lab/4-authorization`, тег `v0.4.0`.

## Паспорт

| Параметр | Значення |
|---|---|
| Обраний рівень | Відмінний («Відмінно»): усі вимоги рівня «Добре», окремий scoping пошуку й зведення за severity (A-11), окремий resource-based handler та обґрунтування (least privilege, видимість ресурсів, залишковий ризик) |
| Baseline | 2-A, профіль A «Пошук»; навчальний трекер кібербезпекових інцидентів (Incident, IncidentComment) |
| Попередній стан | тег v0.3.0 (commit 1fc883b), після ЛР 3 |
| Робоча гілка | lab/4-authorization (Рис. 1) |
| Vulnerable commit | f8d605658b30e8514fe8dfe10aef909a94f6f327<br>«Vulnerable state for lab 4» (Рис. 25) |
| Fixed commit | 7ce14f164eeb8f4b5eaa9299596c19ecbf884118<br>«Enforce resource authorization for incidents» (Рис. 45) |
| Тег | анотований тег v0.4.0 «Laboratory work 4 completed» указує на fixed commit 7ce14f1 (Рис. 45, 46) |
| Репозиторій | https://github.com/AndriiShuplik/Lab1_Shuplik |
| ОС і SDK | Windows, .NET SDK 10, PostgreSQL у Docker Compose, перевірка запитів через tests/http/lab-04-access.http |
| Користувачі seed | Alice (Reporter, 10000000-…-0001), Bob (Reporter, …-0002), Morgan (Analyst, …-0003), Admin (Administrator, …-0004) |
| Обрана політика відмов | анонім: 401; чужий і неіснуючий ресурс: однаковий 404; Reporter на triage: 403 з audit-подією; недозволений поточний status: 409 |
| Overposting | варіант A-08a: DTO не містить owner, role і status, зайві поля ігноруються (A-08b не виконував) |
| Результат тестів | 66 з 66 тестів без збоїв, з них 20 тестів IncidentAuthorizationTests (Рис. 43, 44) |
| Період виконання | 12–14 листопада 2026 року |

## Докази A-01…A-12

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | достатній | Анонімний доступ до захищених маршрутів | Без cookie | GET список, search, severity-summary, деталі, коментар; POST, PUT, DELETE (8 запитів) | 401, без редиректу на HTML-сторінку | 401 для всіх 8 запитів, редиректу немає | Рис. 5, 6; тест A01 ×8 (Рис. 44) |
| A-02 | достатній | Власник змінює свій інцидент | Alice, власний інцидент | PUT title і description | 200, змінюється лише content | До і після: 200, змінено лише title і description | Рис. 10, 30; тест A02 |
| A-03 | достатній | Читання чужого інциденту (IDOR) | Alice, id інциденту Bob | GET /api/incidents/{id Bob} | 404, даних Bob немає | До: 200 і дані Bob. Після: 404 | Рис. 11, 31; тест A03 |
| A-03R | добрий | Analyst читає чужий інцидент, але не змінює | Morgan, інцидент Alice або Bob | GET, потім PUT | GET 200, PUT 403 | GET 200, PUT 403 (перевірено тестом) | Тест A03R (Рис. 44) |
| A-04 | добрий | Зміна й видалення чужого інциденту | Alice, id інциденту Bob | PUT і DELETE | 404, стан Bob не змінюється | До: 200 і 204, дані змінено, запис видалено. Після: 404 для обох, стан Bob той самий | Рис. 13–15б, 32; тест A04 |
| A-05 | добрий | Список лише власних інцидентів | Alice (Reporter) | GET /api/incidents | Лише її записи (1, 3, 5) | До: у списку чужі записи. Після: лише інциденти 1, 3, 5 | Рис. 16, 33; тест A05 |
| A-06 | добрий | Reporter виконує triage | Alice, власний інцидент | POST /api/incidents/{id}/triage | 403, статус не змінюється | До: 200 і Triaged. Після: 403, статус не змінено | Рис. 21, 34; тест A06 |
| A-07 | добрий | Analyst: дозволений перехід і повтор | Morgan, інцидент у New | POST triage двічі | Перший 200 (Triaged), повтор відхилено | 200 і Triaged; повтор відхилено | Рис. 35; тест A07 |
| A-08a | добрий | Overposting у PUT | Alice, власний інцидент | PUT зі зайвими ownerUserId, role, status | Зайві поля ігноруються | 200, owner і status не змінилися (DTO без захищених полів) | Рис. 22а, 22б; тест A08a |
| A-09 | добрий | Audit відмови triage | Alice (Reporter) | POST triage на інцидент | 403 і подія authorization.denied без чутливих даних | 403, подія з subject, action, resource, trace; trace збігається з traceId | Рис. 34, 36 |
| A-10 | добрий | Однакові відповіді для чужого й неіснуючого id | Alice | GET чужого id і випадкового GUID | Однакові status, Content-Type і тіло | 404 для обох, різниться лише traceId | Рис. 38; тест A10 |
| A-11 | відмінний | Scoping пошуку й зведення за severity | Alice (Reporter) | GET search?q=O'Brien; GET severity-summary | Лише записи, видимі Alice | До: search повертає запис Bob, High 1, Medium 1, Low 3. Після: порожньо; Medium 1, Low 2 | Рис. 18, 19, 39, 40; тест A11 ×2 |
| A-12 | добрий | Child-ресурси та internal comment | Alice; comment-2 до інциденту Bob; internal comment-3 | GET /api/incident-comments/{id}; деталі свого інциденту | 404 для чужого; internal не повертається Reporter | До: 200 для обох. Після: 404, internal прихований | Рис. 17а, 17б, 37; тест A12 |

## Finding: відсутня авторизація ресурсів Incident (IDOR/BOLA)

| Пункт | Опис |
|---|---|
| 1. Опис | Авторизація ресурсів Incident була відсутня: endpoint-и перевіряли лише факт входу, а не належність ресурсу користувачеві й не його роль. |
| 2. Передумови | Дві автентифіковані особи з роллю Reporter (Alice і Bob), Analyst Morgan, відтворюваний seed, вразливий commit f8d6056. |
| 3. Відтворення | Cookie Alice, у URL id інциденту Bob: GET, PUT, DELETE за id; GET коментаря за id; POST triage від Reporter (Рис. 11–15б, 17а, 21). |
| 4. Результат до | Alice читає, змінює й видаляє чужий інцидент, бачить чужі записи у списку, пошуку та зведенні, читає internal comment, а Reporter виконує triage. |
| 5. Причина | Запити шукають ресурс лише за id (Where Id == id), а рішення про доступ залежить тільки від автентифікації. Немає ні перевірки власника, ні перевірки ролі на дії Analyst (Рис. 23, 24). |
| 6. Виправлення | IncidentAccess + IncidentAccessHandler: власник визначається з principal, видимість задається умовою VisibleTo у самому запиті, рішення приймається до зміни стану. Triage перевіряє роль і status, пише audit. Для чужого й неіснуючого ресурсу однаковий 404 (Рис. 26–29). |
| 7. Результат після | Alice → Bob: 404 для читання, зміни й видалення; список, пошук і зведення містять лише записи Alice; Reporter на triage: 403 з audit; internal comment прихований. 66 з 66 тестів, 20 з 20 authorization-тестів (Рис. 30–44). |
| 8. Хеші й докази | Vulnerable: f8d605658b30e8514fe8dfe10aef909a94f6f327. Fixed: 7ce14f164eeb8f4b5eaa9299596c19ecbf884118 (тег v0.4.0). Докази: Рис. 10–46, тести A01…A12. |

## Окремий finding A-11

| Пункт | Опис |
|---|---|
| До | GET /api/incidents/severity-summary для Alice повертав High 1, Medium 1, Low 3, тобто враховував інциденти Bob. GET /api/incidents/search?q=O'Brien повертав запис Bob 20000000-…-0004 (Рис. 18, 19). |
| Причина | Список, пошук і підсумок будувались із dbContext.Incidents без умови власника. Перевірка за id нічого не змінювала, бо ці маршрути не приймають id. |
| Виправлення | Спільний фільтр VisibleTo(user) застосовується першою умовою в запиті, до фільтра status, пошуку, сортування, Take(50) і GroupBy (Рис. 28а, 28б). |
| Після | Зведення Alice: Medium 1, Low 2. Пошук за O'Brien для Alice порожній (Рис. 39, 40). Тести A11_Search і A11_SeveritySummary пройшли (Рис. 44). |

## Схема рішення

| Крок | Перевірка | Результат відмови |
|---|---|---|
| 1 | Автентифікація: cookie і principal | 401, без редиректу |
| 2 | Роль для дії (CanTriage: лише Analyst) | 403 і audit authorization.denied |
| 3 | Завантаження ресурсу з умовою VisibleTo(user): власник або Analyst | 404, однаковий для чужого й неіснуючого id |
| 4 | Resource-based handler: операція Update або Delete лише для власника | 404 для чужого; 403 для Analyst на update і delete |
| 5 | Поточний status ресурсу (triage лише з New, delete лише з New) | 409 |
| 6 | Зміна стану і SaveChangesAsync; next status визначає сервер | Успіх: 200 або 204 |

## Git-артефакти

| Артефакт | Значення |
|---|---|
| Робоча гілка | lab/4-authorization |
| Основна гілка | main (злито fast-forward, поточний commit e147917 «Record lab 4 hashes») |
| Тег | v0.4.0 (анотований) на fixed commit |
| Vulnerable commit | f8d605658b30e8514fe8dfe10aef909a94f6f327 |
| Fixed commit (тег v0.4.0) | 7ce14f164eeb8f4b5eaa9299596c19ecbf884118 |
| Репозиторій | https://github.com/AndriiShuplik/Lab1_Shuplik |
| Документація DEL-01 | docs/report-lab-04.md (commit e147917, створений після тегу v0.4.0) |
| Докази | tests/http/lab-04-access.http, docs/access-matrix.md, Рис. 1–46 у цьому звіті |

Рисунки 1–46 див. у Word-звіті для Moodle.
