# Адаптация Salary Online по ТЗ 152-ФЗ

Основание: документ «CRM с персональными данными — юридический чек-лист и техническое задание для разработчиков», версия 1.0 от 30.09.2026.

Статус: кодовый baseline реализован. Документ НЕ является заявлением о полном соответствии 152-ФЗ. Полное соответствие требует настройки production-инфраструктуры, юридических документов, модели угроз, определения уровня защищённости ИСПДн, организационных мер и приемочных испытаний.

## Реализовано в коде

### Tenant isolation baseline
- Добавлен tenant_id в users, employees, objects, salary_records, employee_balances, bank_statement_payments.
- Выполнен безопасный backfill tenant_id из существующей организации/employee.
- PostgreSQL triggers автоматически поддерживают tenant_id при INSERT/UPDATE.
- Существующие backend permission checks и organization/project scope сохранены.
- Добавлен npm run test:cross-tenant для negative API/IDOR тестов на двух синтетических tenants.
- Security preflight блокирует tenant mismatches и строки без tenant_id.

### RBAC
- Permission checks выполняются на backend.
- Добавлены permissions: compliance.view, compliance.manage, incidents.manage, legal.manage.
- Site-only permissions не выдаются обычным tenant-пользователям.

### Consent ledger и публичная регистрация
- Пользовательское соглашение и согласие на ПД — разные обязательные действия.
- Marketing consent — отдельный необязательный checkbox.
- Согласие хранит document version/hash, timestamp, purpose, method, source form, IP и user-agent evidence.
- Старые версии legal document не перезаписываются.
- Withdrawal фиксируется отдельно; для marketing создаётся suppression record.
- Актуальные legal pages доступны через /legal/:type.

### DSAR
- Пользователь может создать запрос access, correction, blocking, deletion или consent withdrawal.
- Есть workflow status и due_at.
- Базовый срок рассчитывается как 10 будних дней; доступно мотивированное продление ещё на 5 будних дней.
- ВАЖНО: производственный расчёт официальных рабочих дней РФ с учётом праздников требует календаря производственных дней.

### Incident response
- Реестр incidents.
- detected_at и confirmed_at разделены.
- После confirmed_at автоматически рассчитываются deadlines +24/+72 часа.
- Есть severity/status/root cause/corrective actions/notification status.
- Доступ ограничен permissions/tenant scope.

### Audit
- Для mutation API создаётся отдельный audit_events event.
- Есть actor, tenant, action, route, result, IP, user-agent, correlation ID.
- Request/response body с ПД в этот audit не пишется.
- PostgreSQL запрещает UPDATE/DELETE audit_events обычным путём.
- Restore получает специальное transaction-local разрешение на восстановление audit trail.

### Authentication/session security
- Пароли остаются стойкими hashes; reversible encryption не используется.
- MFA-механизм для ADMIN/Руководитель сайта реализован через одноразовый email code.
- В production P0 считается выполненным только после PLATFORM_MFA_ENABLED=true и настройки адреса/SMTP.
- Сессии перенесены из MemoryStore в PostgreSQL.
- Пользователь видит активные сессии и может завершать другие.
- Raw session IDs не раскрываются frontend: используются SHA-256 handles.
- Есть смена пароля; после неё остальные сессии отзываются.
- Sensitive export/backup/restore/import/clear требуют recent password re-authentication.
- Secure/HttpOnly/SameSite cookie, CSRF и origin control сохранены.
- Автосоздание ADMIN с паролем ADMIN удалено. Для bootstrap нового ADMIN нужен INITIAL_ADMIN_PASSWORD >= 12 символов.
- Если legacy ADMIN всё ещё имеет пароль ADMIN, security preflight выдаёт blocker.

### Backup evidence
- In-app backup format обновлён до version 4.
- Backup v4 включает consent/DSAR/audit/incidents/legal docs/integrations/retention/deletion evidence.
- Restore v4 восстанавливает compliance evidence.
- Legacy backup восстанавливается с явным предупреждением об отсутствии compliance evidence.
- Отдельные PostgreSQL pg_dump/SHA-256/restore verification scripts уже существуют.

### Compliance admin baseline
- Compliance status.
- DSAR dashboard.
- Incident register.
- Audit view.
- Integration/subprocessor registry backend + UI.
- Retention rules registry backend + UI.
- Deletion jobs workflow backend + UI; завершение требует result + evidence_ref.
- Из DSAR типа deletion создаётся отдельная deletion job.
- Legal document version/hash backend.
- Пользовательская история согласий.
- Active sessions.

### P0 preflight
npm run security:preflight теперь проверяет:
- обязательные таблицы/колонки;
- TLS для hosted PostgreSQL;
- DATA_REGION=RU;
- реквизиты оператора;
- SESSION_SECRET;
- включение platform MFA;
- legacy default ADMIN password;
- legal document versions;
- consent evidence integrity;
- tenant mismatch;
- append-only audit triggers;
- внешние browser assets для egress review;
- существующие проверки целостности зарплатной/организационной модели.

## Требует настройки перед production launch

1. Заполнить LEGAL_OPERATOR_NAME, LEGAL_OPERATOR_INN, LEGAL_OPERATOR_OGRNIP, LEGAL_OPERATOR_ADDRESS, LEGAL_PRIVACY_EMAIL.
2. Проверить и утвердить фактические тексты Политики, согласия, пользовательского соглашения и DPA с юристом под реальную бизнес-модель.
3. Настроить SMTP и включить PLATFORM_MFA_ENABLED=true.
4. Немедленно сменить legacy пароль ADMIN, если он ещё равен ADMIN.
5. Задать стабильный случайный SESSION_SECRET не короче 32 символов.
6. Подтвердить документами/настройками, что production DB/storage/logs/backups расположены в РФ.
7. Провести data-egress review внешних browser assets/CDN. Предпочтительно перенести XLSX/html2canvas/jsPDF на локальную раздачу из российского production-контура.
8. Создать test/staging без production ПД и выполнить npm run test:cross-tenant.
9. Фактически выполнить Stage 1 DB preflight.
10. Создать независимый encrypted PostgreSQL backup и выполнить restore test.
11. Настроить secret manager/Vault/KMS для production secrets и будущих encryption keys.
12. Внедрить application-level encryption чувствительных HR/банковских данных отдельным этапом.
13. Провести модель угроз, определить уровень защищённости ИСПДн и применимые меры.
14. Провести security review/pentest и закрыть high/critical.
15. Подать/актуализировать необходимые уведомления Роскомнадзора и проверить DPA/договоры.
16. Документировать incident runbook и провести учебный 24/72 incident drill.

## Ещё не реализовано полностью

### P0/P1 gaps
- Полное отделение platform control plane от tenant content и обязательный JIT workflow для технического support/admin. Таблица admin_access_sessions создана, но enforcement пока не включён, чтобы не заблокировать действующий ADMIN без согласованной операционной процедуры.
- Полная автоматическая deletion orchestration по DB/files/cache/search с фактическим purge. Управляемые retention rules, deletion jobs, DSAR→deletion job и обязательное evidence уже реализованы, но автоматическое физическое уничтожение intentionally не запускается без утверждённых retention/legal-hold правил.
- Tombstone/replay mechanism после restore, исключающий «воскрешение» ранее уничтоженных субъектов.
- Автоматический календарь рабочих/праздничных дней РФ для DSAR deadlines.
- Локальное размещение frontend vendor libraries вместо cdnjs.
- Vault/KMS и app-layer AES-256-GCM.
- Автоматическое шифрование независимых backup-копий.
- WORM/tamper-evident hash chain для audit (P1).
- MFA для owner/org-admin как настраиваемая enterprise policy (P1).
- Полная JIT support approval/customer visibility (P1).

## Команды приемки

Syntax:
    npm run check:syntax

Read-only DB/P0 preflight:
    npm run security:preflight

Cross-tenant negative tests — только staging + synthetic data:
    npm run test:cross-tenant

Verified PostgreSQL backup:
    npm run backup:database

Restore verification:
    CONFIRM_TEST_RESTORE=yes npm run restore:verify -- secure-backups/<file>.dump

## Правило релиза

Наличие кода в main не означает автоматического соответствия 152-ФЗ.

Публичный production launch с реальными ПД считается готовым только после:
- успешного P0 preflight;
- успешных cross-tenant acceptance tests;
- backup + restore verification;
- фактической настройки РФ-инфраструктуры;
- MFA;
- legal/operator configuration;
- утверждения организационных/юридических документов;
- security acceptance review.
