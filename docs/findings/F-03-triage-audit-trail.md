# F-03. Успішний привілейований перехід Incident.Status не залишає audit event

**Статус:** Fixed
**Актив:** журнал аудиту привілейованого переходу `New → Triaged` (ким, над яким ресурсом, з яким результатом і коли)
**Компонент:** `POST /api/incidents/{id}/triage`, `AuthorizationAudit` (`src/SecureLab.Api/Application/Incidents/AuthorizationAudit.cs`, `IncidentEndpoints.TriageAsync`)
**Пріоритет:** P3

## Передумови і межі огляду

Commit `f6d2315fd896f8ca76080df9c4a11172331be25f`, Development, тестовий host з власним провайдером журналу, користувачі Alice (Reporter) і Morgan (Analyst), інциденти Alice у статусі New створюються самим тестом. Reset не потрібен. Поза межами: інші привілейовані дії (їх немає в застосунку), зберігання журналу, строки зберігання.

## Відтворення

1. Morgan входить, отримує токен antiforgery.
2. `POST /api/incidents/{id}/triage` для інциденту Alice зі статусом New → 200, статус `Triaged`.
3. Alice (Reporter) надсилає той самий запит для іншого інциденту → 403, статус лишається `New`.
4. Очікувано: у журналі два записи аудиту з полями subject, action, resource, result, time і trace: дозволений перехід і відмова.
5. Фактично: є лише `authorization.denied` для Alice. Запису про дозволений перехід Morgan немає. Тест `TriageAuditTests` на цьому коді падає: `Assert.Single() Failure: The collection did not contain any matching items` (шукався запис `authorization.allowed`).

## Вплив і ймовірність

**Статус перевірки:** спостережено локально (тест на коді коміту `f6d2315`).

Привілейована зміна стану проходила без сліду: за журналом не можна було відновити, хто й коли перевів інцидент у `Triaged`, хоча відмови фіксувалися. Це слабкість підзвітності (non-repudiation), а не пряма загроза даним. Impact Low, likelihood Medium (кожен дозволений перехід), тому P3.

## Першопричина

`AuthorizationAudit` мав єдиний метод `Denied`, а `TriageAsync` викликав його лише на гілці відмови. Для дозволеного переходу відповідного виклику не було.

## Виправлення

У `AuthorizationAudit` додано метод `Allowed` з тими самими полями, що й `Denied`: `subject`, `action`, `resource`, `result=allowed`, `at` (UTC, ISO 8601) і `trace`. `TriageAsync` викликає його після успішного `SaveChangesAsync`. Паролів, cookie й тіла запиту в записі немає. Тест `TriageAuditTests` додано в `tests/SecureLab.Api.Tests/TriageAuditTests.cs`. Fixed commit: `b78e5bdf465a95609ab777a5029596350fd10ffc`.

## Retest

Той самий сценарій після виправлення: Morgan → 200 `Triaged` і запис `authorization.allowed subject=<id Morgan> action=incident.triage resource=<id> result=allowed at=<UTC> trace=<id>`; Alice → 403, статус `New` і запис `authorization.denied … result=denied`. Тест перевіряє значення кожного поля та відсутність слів `password`, `cookie` і значення пароля seed у цих записах. Сценарій позначено REG-AUD-01. Команда: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~TriageAuditTests"`. Результат: пройдено.

## Positive regression

Звичайна поведінка triage не змінилася: A-06 (Reporter → 403, статус незмінний) і A-07 (Analyst переводить `New` у `Triaged`, повтор відхилено) проходять; повний набір після зміни: 96 з 96.

## Залишковий ризик

Audit event лишається звичайним записом консольного журналу застосунку, а не окремим захищеним сховищем: немає контролю цілісності, відокремленого доступу й строків зберігання. Дозволене читання даних (список, деталі) аудитом не охоплено навмисно, щоб не перетворювати журнал на «кожне читання». Перехід, виконаний поза застосунком (прямо в БД), у цьому журналі не видно.

## Доказ

Тест `TriageAuditTests.Triage_AllowedForAnalyst_IsAudited_DeniedForReporter_IsAudited_AndStatusIsUnchanged`; на коді без виправлення тест падає (`did not contain any matching items`), після виправлення проходить. Значення cookie, токенів і пароля в доказі немає.
