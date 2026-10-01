# Адаптация KORVEX по ТЗ 152-ФЗ

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

### Consent ledger и регистрация по приглашениям
- Пользовательское соглашение и согласие на ПД — разные обязательные действия.
- Marketing consent — отдельный необязательный checkbox.
- Согласие хранит document version/hash, timestamp, purpose, method, source form, IP и user-agent evidence.
- Старые версии legal document не перезаписываются.
- Withdrawal фиксируется отдельно; для marketing создаётся suppression record.
- Актуальные legal pages доступны через /legal/:type.
- Политика ПД вынесена из checkbox согласия: согласие и ознакомление с Политикой не объединены в одно действие.
- Регистрация по умолчанию разрешена только по ограниченному invitation-токену организации; токен хранится только как SHA-256.
- Публичный список организаций из registration flow удалён.
- Телефон при регистрации необязателен; отчество технически не требуется.

### DSAR
- Пользователь может создать запрос access, correction, blocking, deletion или consent withdrawal.
- Есть workflow status и due_at.
- Базовый срок рассчитывается как 10 рабочих дней; доступно мотивированное продление ещё на 5 рабочих дней.
- Поддерживаются официальные overrides производственного календаря РФ через RU_NONWORKING_DATES / RU_WORKING_DATES.
- Production preflight требует подтверждённого календаря (RU_BUSINESS_CALENDAR_CONFIRMED=true).

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
- Deletion jobs workflow backend + UI; ручное завершение требует result + evidence_ref.
- Из DSAR типа deletion создаётся отдельная deletion job.
- Для аккаунтных данных реализовано фактическое удаление account/session/email-code данных и минимальный hash-tombstone.
- Tombstone защищает встроенный restore/startup от восстановления старого удалённого аккаунта; повторная законная регистрация создаёт release marker, не разрешающий воскресить более старую запись.
- Кадровые/расчётные записи клиента не уничтожаются автоматически без решения клиента-оператора и проверки обязательного хранения.
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
- отсутствие внешних browser script/link assets (в production это blocker);
- обязательность invitation-only регистрации;
- retention settings и производственный календарь РФ;
- внешние production attestations: РФ-инфраструктура, РКН, DPA, legal texts, организационные меры, модель угроз, incident runbook, subprocessors review, backup/restore и security acceptance;
- существующие проверки целостности зарплатной/организационной модели.

## Требует настройки перед production launch

1. Заполнить LEGAL_OPERATOR_NAME, LEGAL_OPERATOR_INN, LEGAL_OPERATOR_OGRNIP, LEGAL_OPERATOR_ADDRESS, LEGAL_PRIVACY_EMAIL.
2. Проверить и утвердить фактические тексты Политики, согласия, пользовательского соглашения и DPA с юристом под реальную бизнес-модель.
3. Настроить SMTP и включить PLATFORM_MFA_ENABLED=true.
4. Немедленно сменить legacy пароль ADMIN, если он ещё равен ADMIN.
5. Задать стабильный случайный SESSION_SECRET не короче 32 символов.
6. Подтвердить документами/настройками, что production DB/storage/logs/backups расположены в РФ.
7. Заполнить и подтвердить официальный производственный календарь РФ (RU_NONWORKING_DATES / RU_WORKING_DATES).
8. Утвердить retention-периоды и оставить REGISTRATION_INVITE_REQUIRED=true.
9. Создать test/staging без production ПД и выполнить npm run test:cross-tenant.
10. Фактически выполнить Stage 1 DB/P0 preflight.
11. Создать независимый PostgreSQL backup и выполнить restore test; сохранить evidence.
12. Настроить безопасное хранение production secrets/ключей.
13. Провести модель угроз, определить уровень защищённости ИСПДн и применимые меры.
14. Провести security review/pentest и закрыть high/critical.
15. Подать/актуализировать необходимые уведомления Роскомнадзора и проверить DPA/договоры.
16. Утвердить incident runbook и провести учебный 24/72 incident drill.
17. Заполнить реестр subprocessors/integrations, включая SMTP/hosting/storage/monitoring.
18. После фактического выполнения выставить соответствующие *_CONFIRMED / *_APPROVED / *_ACCEPTED flags в production env.

## Ещё не реализовано полностью

### P0/P1 gaps
- Полное отделение platform control plane от tenant content и обязательный JIT workflow для технического support/admin. Таблица admin_access_sessions создана, но enforcement пока не включён, чтобы не заблокировать действующий ADMIN без согласованной операционной процедуры.
- Полная автоматическая deletion orchestration кадровых/расчётных данных клиента не запускается без решения клиента-оператора и утверждённых retention/legal-hold правил; account-контур удаляется фактически.
- Полный disaster-recovery сценарий из старого снимка всей БД требует отдельного актуального deletion/tombstone ledger вне восстанавливаемого snapshot; встроенный application restore защищён tombstones.
- Vault/KMS и app-layer шифрование отдельных чувствительных HR/банковских полей остаются дополнительным security-hardening этапом, состав которого определяется моделью угроз.
- Политика шифрования независимых backup-копий должна быть подтверждена в production-инфраструктуре.
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
