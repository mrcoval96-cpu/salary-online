# Security Stages 1–2 — Database diagnostics and verified backup

Дата: 2026-09-30

## Цель

До внедрения шифрования:

1. выполнить полную read-only диагностику production PostgreSQL;
2. создать консистентный PostgreSQL dump;
3. сохранить контрольную сумму и snapshot counts;
4. восстановить dump в отдельную одноразовую PostgreSQL;
5. подтвердить идентичность критических таблиц;
6. сохранить вторую независимую копию dump + manifest.

Ни один из этих этапов не изменяет production-данные.

## Stage 1 — read-only диагностика

Команда:

```bash
npm run security:preflight
```

Скрипт работает внутри:

`REPEATABLE READ READ ONLY`

Он проверяет:

- критические таблицы и колонки;
- количество записей;
- ссылки пользователей/сотрудников/объектов/зарплаты на организации;
- зарплатные записи без организации;
- соответствие зарплатных записей сотрудникам и объектам;
- ответственных пользователей, привязанных к чужой организации;
- руководителей проектов без назначенных объектов;
- дубли нормализованных названий организаций;
- дубли ИНН/ОГРН;
- дубли ФИО сотрудников внутри организации;
- корректность JSON в текстовых полях `extra_charges` и `payments`.

Успешный результат:

`RESULT: SECURITY STAGE 1 PASSED`

При наличии `BLOCKER` к шифрованию не переходить.

## Stage 2 — backup

Требуются PostgreSQL client tools: `pg_dump` и `pg_restore`.

Команда:

```bash
npm run backup:database
```

По умолчанию создаются:

`secure-backups/salary-online-<timestamp>.dump`

`secure-backups/salary-online-<timestamp>.manifest.json`

Каталог `secure-backups/` исключён из Git.

Backup использует экспортированный PostgreSQL snapshot. В manifest записываются:

- SHA-256 dump-файла;
- размер;
- дата;
- версия PostgreSQL;
- source database;
- snapshot;
- точные количества записей критических таблиц в том же snapshot.

Успешный результат:

`RESULT: BACKUP CREATED`

## Вторая независимая копия

После создания `.dump` и `.manifest.json` оба файла необходимо скопировать в второе защищённое хранилище, не являющееся тем же production-сервером.

После копирования SHA-256 второй копии должен совпасть с `sha256` в manifest.

Production dump запрещено сохранять в GitHub/GitVerse или прикладывать к issue/commit.

## Проверка восстановления

Создать отдельную тестовую PostgreSQL.

Задать:

```bash
RESTORE_DATABASE_URL=postgresql://...
CONFIRM_TEST_RESTORE=yes
```

Затем:

```bash
npm run restore:verify -- secure-backups/salary-online-<timestamp>.dump
```

Защита:

- скрипт запрещает restore в ту же host/port/database, что и `DATABASE_URL`;
- без `CONFIRM_TEST_RESTORE=yes` restore не запускается;
- перед восстановлением проверяется SHA-256;
- `pg_restore` выполняется с `--single-transaction` и `--exit-on-error`;
- после восстановления количества строк сравниваются с snapshot counts из manifest.

Успешный результат:

`RESULT: RESTORE VERIFIED`

## Условие завершения Stage 1

Stage 1 завершён только после фактического запуска на production и результата:

`RESULT: SECURITY STAGE 1 PASSED`

## Условие завершения Stage 2

Stage 2 завершён только когда одновременно выполнены все условия:

1. `RESULT: BACKUP CREATED`;
2. dump имеет валидный SHA-256;
3. существует вторая независимая копия dump + manifest;
4. `RESULT: RESTORE VERIFIED` на отдельной PostgreSQL;
5. количества критических таблиц совпали со snapshot;
6. backup не находится в Git.

До этого существующие персональные данные не шифровать и plaintext не удалять.
