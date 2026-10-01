# Production readiness 152-ФЗ — KORVEX

Этот файл разделяет то, что проверяется автоматически, и то, что требует фактического организационного действия. Наличие кода само по себе не является подтверждением соответствия.

## Автоматические BLOCKER-проверки

Команда:

```bash
npm run security:preflight
```

Production baseline блокируется, если:
- не заполнены ФИО/наименование оператора, ИНН, ОГРНИП, адрес и privacy email;
- DATA_REGION не равен RU;
- внешняя PostgreSQL-сессия работает без TLS;
- отсутствует tenant isolation / обязательная схема;
- административный MFA выключен;
- актуальные обязательные consent evidence не enforced;
- SESSION_SECRET короче 32 символов;
- браузер загружает script/link с внешнего HTTP(S)-источника;
- открытая регистрация разрешена без invitation;
- не настроены retention-периоды;
- отсутствуют обязательные production attestations.

## Attestations, которые нельзя получить из GitHub автоматически

Значение `true` ставить только после получения и хранения доказательств.

- `INFRA_RU_CONFIRMED=true` — подтверждены российские регионы DB, storage, logs, backups и используемой инфраструктуры.
- `RKN_OPERATOR_NOTIFICATION_CONFIRMED=true` — уведомление оператора в Роскомнадзор подано/актуализировано под фактическую обработку.
- `DPA_APPROVED=true` — финальный DPA/поручение с клиентами согласован юристом и встроен в договорную модель.
- `THREAT_MODEL_APPROVED=true` — утверждена модель угроз и определён применимый уровень защищённости ИСПДн/меры.
- `INCIDENT_RUNBOOK_APPROVED=true` — назначены ответственные, каналы и проведён учебный 24/72 drill.
- `BACKUP_RESTORE_VERIFIED=true` — выполнена независимая backup + restore verification с сохранённым актом/evidence.

## Перед включением production

1. Заполнить legal env.
2. Включить `PLATFORM_MFA_ENABLED=true`.
3. Установить `COMPLIANCE_ENFORCE_CURRENT_CONSENTS=true`.
4. Оставить `REGISTRATION_INVITE_REQUIRED=true`.
5. Утвердить retention values в env.
6. Запустить syntax check.
7. Запустить migration/security preflight.
8. Провести cross-tenant negative test только на staging с синтетическими данными.
9. Сделать backup и restore test.
10. Проверить, что браузер не делает сторонних script/link запросов.
11. Сохранить документы, подтверждающие все attestations.
12. После этого запускать production с реальными ПД.

## Ограничение tombstone-механизма

Встроенный hash-tombstone защищает от «воскрешения» удалённого аккаунта при встроенном восстановлении данных приложения и при старте, если tombstone присутствует в текущей БД. Полное восстановление всей БД из старого snapshot может удалить и сам tombstone. Для production-процедуры аварийного восстановления необходимо хранить актуальный реестр deletion/tombstone evidence отдельно от восстанавливаемого snapshot либо гарантированно накатывать его после restore.
