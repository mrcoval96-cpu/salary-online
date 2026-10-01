'use strict';

const crypto=require('crypto');

const LEGAL_DOC_TYPES={
  privacy_policy:'Политика обработки персональных данных',
  pd_consent:'Согласие на обработку персональных данных',
  terms:'Пользовательское соглашение',
  marketing_consent:'Согласие на рекламные и информационные сообщения'
};
const DSAR_TYPES=new Set(['access','correction','blocking','deletion','consent_withdrawal']);
const DSAR_STATUSES=new Set(['received','identity_check','in_review','action_required','completed','rejected']);
const INCIDENT_SEVERITIES=new Set(['low','medium','high','critical']);
const INCIDENT_STATUSES=new Set(['open','investigating','contained','closed']);

function sha256(value){
  return crypto.createHash('sha256').update(String(value||''),'utf8').digest('hex');
}
function normalizeEmail(value){return String(value||'').trim().toLowerCase();}
function requestIp(req){
  return String((req.headers&&req.headers['x-forwarded-for'])||req.socket&&req.socket.remoteAddress||'').split(',')[0].trim().slice(0,120);
}
function operatorDetails(){
  return {
    name:String(process.env.LEGAL_OPERATOR_NAME||'').trim(),
    inn:String(process.env.LEGAL_OPERATOR_INN||'').trim(),
    ogrnip:String(process.env.LEGAL_OPERATOR_OGRNIP||'').trim(),
    address:String(process.env.LEGAL_OPERATOR_ADDRESS||'').trim(),
    email:normalizeEmail(process.env.LEGAL_PRIVACY_EMAIL||process.env.MAIL_FROM||process.env.SMTP_USER||'')
  };
}
function operatorReady(details){
  return !!(details.name&&details.inn&&details.ogrnip&&details.address&&details.email);
}
function docVersion(content){
  return new Date().toISOString().slice(0,10)+'-'+sha256(content).slice(0,8);
}
function buildLegalText(type){
  const o=operatorDetails();
  const operator=o.name||'[Укажите ФИО индивидуального предпринимателя]';
  const inn=o.inn||'[ИНН]';
  const ogrnip=o.ogrnip||'[ОГРНИП]';
  const address=o.address||'[Адрес для юридически значимых сообщений]';
  const email=o.email||'[E-mail по вопросам персональных данных]';
  if(type==='privacy_policy'){
    return `ПОЛИТИКА ОБРАБОТКИ ПЕРСОНАЛЬНЫХ ДАННЫХ

Оператор: ${operator}, ИНН ${inn}, ОГРНИП ${ogrnip}.
Контакт по вопросам персональных данных: ${email}.
Адрес: ${address}.

1. Общие положения
Настоящая Политика определяет порядок обработки и защиты персональных данных при использовании сервиса «Зарплата: учёт и расчёт». Оператор обрабатывает персональные данные только для заранее определённых и законных целей и применяет принцип минимизации.

2. Роли при обработке
В отношении данных, которые человек самостоятельно предоставляет для создания и использования собственной учётной записи KORVEX, ${operator} определяет цели и состав обработки и выступает оператором персональных данных.
В отношении персональных данных работников, исполнителей и иных лиц, которые организация-клиент загружает в KORVEX для своих внутренних процессов, организация-клиент самостоятельно определяет цели обработки и является оператором, а владелец KORVEX осуществляет обработку по поручению клиента в пределах договора/поручения на обработку персональных данных.

3. Категории субъектов и данных
Пользователи учётных записей: ФИО, электронная почта, при добровольном указании телефон, организация, сведения учётной записи, история входов, IP-адрес, User-Agent и журнал значимых действий.
Лица, сведения о которых внесены организацией-клиентом: ФИО, должность, контактные и кадровые сведения, сведения об объектах, начислениях и выплатах и иные категории, прямо предусмотренные функционалом и поручением клиента. Специальные категории и биометрические персональные данные не должны загружаться без отдельной правовой и технической оценки.

4. Цели и правовые основания
Данные учётной записи обрабатываются для регистрации, предоставления функционала, аутентификации, разграничения доступа, связи по вопросам сервиса, информационной безопасности, исполнения запросов субъектов и договорных обязанностей. Основание определяется конкретной целью: согласие, договор либо иное основание, предусмотренное законодательством.
Данные, загруженные клиентом о третьих лицах, обрабатываются исключительно по документированному поручению клиента и только для целей, указанных клиентом.
Рекламные сообщения направляются только при наличии отдельного предварительного согласия.

5. Операции, сроки и уничтожение
Могут выполняться сбор, запись, систематизация, накопление, хранение, уточнение, извлечение, использование, предоставление уполномоченным пользователям, блокирование, удаление и уничтожение.
Учётная запись хранится в период её использования. После подтверждённого запроса на прекращение обработки сведения, для которых отсутствует иное законное основание, удаляются или блокируются для последующего уничтожения в применимый срок. Технические журналы безопасности хранятся в пределах установленного оператором retention-периода; резервные копии ротируются по отдельному сроку. Данные клиента после прекращения договора возвращаются/удаляются в порядке и сроки, закреплённые договором поручения, с учётом обязательных сроков хранения и legal hold.
Актуальные технические retention rules ведутся в KORVEX и подлежат утверждению ответственным лицом до production-эксплуатации.

6. Локализация, получатели и трансграничная передача
При сборе персональных данных граждан РФ первоначальная запись, систематизация, накопление, хранение, уточнение и извлечение выполняются в базах данных на территории Российской Федерации. Размещение PostgreSQL, файлов, журналов и резервных копий должно быть подтверждено настройками и документами инфраструктурных поставщиков.
Доступ предоставляется только уполномоченным пользователям и привлечённым обработчикам в объёме, необходимом для соответствующей цели. Каждый внешний обработчик/интеграция должен быть внесён в реестр subprocessors и иметь оформленное договорное основание.
Трансграничная передача не осуществляется без предварительной отдельной правовой проверки и выполнения обязательных процедур.

7. Защита
Применяются организационные и технические меры, включая аутентификацию, управление доступом, tenant-изоляцию, серверную проверку полномочий, CSRF/origin-защиту, журналирование значимых событий, резервное копирование, контроль восстановления, защиту каналов связи и управление секретами. Конкретный состав мер определяется моделью угроз, установленным уровнем защищённости ИСПДн и результатами приёмочных проверок.

8. Права субъекта
Субъект вправе направлять запросы о наличии и обработке данных, получать предусмотренные законом сведения, требовать уточнения, блокирования или уничтожения в установленных случаях, а также отзывать согласие в отношении операций, основанных на согласии. Запрос можно направить через личный кабинет либо на ${email}. До исполнения запроса оператор вправе выполнить разумную проверку личности заявителя.

9. Файлы cookie и технические идентификаторы
Сервис использует обязательный серверный cookie salary.sid для поддержания авторизованной сессии. Cookie имеет атрибуты Secure, HttpOnly и SameSite=Lax и не используется для рекламы или межсайтового профилирования. Срок серверной сессии ограничен настройками сервиса. Подключение аналитических, рекламных и иных необязательных cookie требует отдельной оценки до включения.

10. Актуальность
Актуальная версия Политики постоянно доступна в сервисе. Каждая опубликованная версия имеет дату, версию и SHA-256 контрольную сумму; публикация новой версии не изменяет доказательства ранее совершённых юридических действий.`;
  }
  if(type==='pd_consent'){
    return `СОГЛАСИЕ НА ОБРАБОТКУ ПЕРСОНАЛЬНЫХ ДАННЫХ

Я свободно, своей волей и в своём интересе отдельно даю ${operator}, ИНН ${inn}, ОГРНИП ${ogrnip}, согласие на обработку персональных данных, которые я самостоятельно предоставляю для создания и использования своей учётной записи KORVEX.

Цели: создание и ведение учётной записи, предоставление функционала сервиса, идентификация и аутентификация, связь по вопросам использования сервиса, обеспечение информационной безопасности и исполнение моих обращений.

Перечень данных: ФИО, электронная почта, при добровольном указании телефон, организация, сведения об учётной записи, IP-адрес, User-Agent, время входов и технические сведения, необходимые для подтверждения юридически значимых действий и обеспечения безопасности.

Политика обработки персональных данных опубликована отдельно по адресу /legal/privacy_policy и доступна для ознакомления независимо от дачи настоящего согласия.

Операции: сбор, запись, систематизация, накопление, хранение, уточнение, извлечение, использование, предоставление уполномоченным лицам в пределах целей, блокирование, удаление и уничтожение.

Согласие действует до достижения целей обработки или его отзыва, если иное законное основание не требует продолжения обработки. Отзыв может быть направлен через функции сервиса или на ${email}. Отзыв согласия не прекращает обработку, если у оператора имеется иное предусмотренное законом основание.`;
  }
  if(type==='terms'){
    return `ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ — БАЗОВАЯ ВЕРСИЯ

Владелец сервиса: ${operator}, ИНН ${inn}, ОГРНИП ${ogrnip}.

1. Сервис предоставляет программный функционал для учёта работников, объектов, начислений, выплат и связанных бизнес-процессов.
2. Пользователь обязан использовать сервис только в пределах предоставленных ему полномочий и не получать доступ к данным других организаций или лиц без законного основания.
3. Клиент, загружающий персональные данные третьих лиц, отвечает за наличие правового основания и поручает обработку в пределах отдельного договора/DPA, если применимо.
4. Запрещается загружать специальные категории персональных данных или биометрические данные без предварительной юридической и технической оценки соответствующего сценария.
5. Права доступа, экспорт, удаление и иные чувствительные действия могут ограничиваться политиками безопасности и журналироваться.
6. Условия тарифа, SLA, ответственности, прекращения обслуживания, возврата/экспорта и уничтожения данных должны быть определены договором или офертой владельца сервиса.

Настоящий текст является базовой технической версией и до коммерческого публичного запуска должен быть согласован с фактической договорной моделью сервиса.`;
  }
  if(type==='marketing_consent'){
    return `СОГЛАСИЕ НА РЕКЛАМНЫЕ И ИНФОРМАЦИОННЫЕ СООБЩЕНИЯ

Я отдельно и добровольно соглашаюсь получать от ${operator} рекламные и информационные сообщения по указанным мной контактам. Это согласие не является обязательным условием использования основной услуги.

Я могу в любое время отказаться от таких сообщений через доступный в сервисе механизм или по адресу ${email}. После отказа адрес может сохраняться в минимальном suppression-реестре, необходимом для соблюдения запрета повторной рассылки.`;
  }
  throw new Error('Unknown legal document type');
}

async function seedLegalDocuments(pool){
  for(const type of Object.keys(LEGAL_DOC_TYPES)){
    const content=buildLegalText(type);
    const hash=sha256(content);
    const current=await pool.query("SELECT id,content_hash FROM legal_documents WHERE doc_type=$1 AND active=TRUE ORDER BY published_at DESC,id DESC LIMIT 1",[type]);
    if(current.rows.length&&current.rows[0].content_hash===hash)continue;
    const version=docVersion(content);
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query("UPDATE legal_documents SET active=FALSE WHERE doc_type=$1 AND active=TRUE",[type]);
      await client.query(
        "INSERT INTO legal_documents(doc_type,version,title,content,content_hash,published_at,active) VALUES($1,$2,$3,$4,$5,NOW(),TRUE) ON CONFLICT(doc_type,version) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,content_hash=EXCLUDED.content_hash,published_at=NOW(),active=TRUE",
        [type,version,LEGAL_DOC_TYPES[type],content,hash]
      );
      await client.query('COMMIT');
    }catch(err){try{await client.query('ROLLBACK');}catch(e){}throw err;}
    finally{client.release();}
  }
}

async function ensureComplianceSchema(pool){
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'RU'");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS retention_profile_id INTEGER");

  for(const table of ['users','employees','objects','salary_records','employee_balances','bank_statement_payments']){
    await pool.query('ALTER TABLE '+table+' ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_'+table+'_tenant_id ON '+table+'(tenant_id)');
  }
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP");

  await pool.query("UPDATE users u SET tenant_id=o.id FROM organizations o WHERE u.tenant_id IS NULL AND trim(COALESCE(u.organization,''))<>'' AND lower(trim(u.organization))=lower(trim(o.name))");
  await pool.query("UPDATE employees e SET tenant_id=o.id FROM organizations o WHERE e.tenant_id IS NULL AND trim(COALESCE(e.organization,''))<>'' AND lower(trim(e.organization))=lower(trim(o.name))");
  await pool.query("UPDATE objects x SET tenant_id=o.id FROM organizations o WHERE x.tenant_id IS NULL AND trim(COALESCE(x.organization,''))<>'' AND lower(trim(x.organization))=lower(trim(o.name))");
  await pool.query("UPDATE salary_records s SET tenant_id=o.id FROM organizations o WHERE s.tenant_id IS NULL AND trim(COALESCE(s.organization,''))<>'' AND lower(trim(s.organization))=lower(trim(o.name))");
  await pool.query("UPDATE employee_balances b SET tenant_id=e.tenant_id FROM employees e WHERE b.tenant_id IS NULL AND b.employee_id=e.id AND e.tenant_id IS NOT NULL");
  await pool.query("UPDATE bank_statement_payments b SET tenant_id=e.tenant_id FROM employees e WHERE b.tenant_id IS NULL AND b.employee_id=e.id AND e.tenant_id IS NOT NULL");

  await pool.query(`CREATE OR REPLACE FUNCTION set_tenant_id_from_organization() RETURNS trigger AS $$
    BEGIN
      IF trim(COALESCE(NEW.organization,''))='' THEN
        NEW.tenant_id=NULL;
      ELSE
        SELECT id INTO NEW.tenant_id FROM organizations WHERE lower(trim(name))=lower(trim(NEW.organization)) ORDER BY id LIMIT 1;
      END IF;
      RETURN NEW;
    END;
  $$ LANGUAGE plpgsql`);
  for(const table of ['users','employees','objects','salary_records']){
    await pool.query('DROP TRIGGER IF EXISTS trg_'+table+'_tenant_from_org ON '+table);
    await pool.query('CREATE TRIGGER trg_'+table+'_tenant_from_org BEFORE INSERT OR UPDATE OF organization ON '+table+' FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_organization()');
  }
  await pool.query(`CREATE OR REPLACE FUNCTION set_tenant_id_from_employee() RETURNS trigger AS $$
    BEGIN
      IF NEW.employee_id IS NULL THEN
        NEW.tenant_id=NULL;
      ELSE
        SELECT tenant_id INTO NEW.tenant_id FROM employees WHERE id=NEW.employee_id;
      END IF;
      RETURN NEW;
    END;
  $$ LANGUAGE plpgsql`);
  for(const table of ['employee_balances','bank_statement_payments']){
    await pool.query('DROP TRIGGER IF EXISTS trg_'+table+'_tenant_from_employee ON '+table);
    await pool.query('CREATE TRIGGER trg_'+table+'_tenant_from_employee BEFORE INSERT OR UPDATE OF employee_id ON '+table+' FOR EACH ROW EXECUTE FUNCTION set_tenant_id_from_employee()');
  }

  await pool.query(`CREATE TABLE IF NOT EXISTS processing_purposes(
    purpose_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    legal_basis TEXT NOT NULL DEFAULT '',
    categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_rule TEXT NOT NULL DEFAULT '',
    allowed_recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS legal_documents(
    id BIGSERIAL PRIMARY KEY,
    doc_type TEXT NOT NULL,
    version TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    published_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(doc_type,version)
  )`);
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_documents_one_active ON legal_documents(doc_type) WHERE active=TRUE");
  await pool.query(`CREATE TABLE IF NOT EXISTS consents(
    consent_id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    subject_ref TEXT NOT NULL,
    purpose_id TEXT NOT NULL,
    document_type TEXT NOT NULL,
    document_version TEXT NOT NULL,
    document_hash TEXT NOT NULL,
    given_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    channel TEXT NOT NULL DEFAULT 'web',
    source_form TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT 'checkbox',
    evidence_ip TEXT NOT NULL DEFAULT '',
    evidence_user_agent TEXT NOT NULL DEFAULT '',
    withdrawn_at TIMESTAMP,
    withdrawal_channel TEXT NOT NULL DEFAULT '',
    withdrawal_reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'given',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_consents_subject ON consents(subject_ref,given_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_consents_tenant ON consents(tenant_id,given_at DESC)");
  await pool.query(`CREATE TABLE IF NOT EXISTS marketing_suppression(
    id BIGSERIAL PRIMARY KEY,
    normalized_address TEXT NOT NULL UNIQUE,
    source_consent_id BIGINT REFERENCES consents(consent_id) ON DELETE SET NULL,
    suppressed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL DEFAULT 'withdrawal'
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS data_subject_requests(
    request_id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    requester_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    subject_ref TEXT NOT NULL,
    request_type TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    identity_status TEXT NOT NULL DEFAULT 'account_authenticated',
    due_at TIMESTAMP NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    details TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    extension_reason TEXT NOT NULL DEFAULT '',
    extended_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT ''
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_dsar_tenant_due ON data_subject_requests(tenant_id,status,due_at)");
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_events(
    event_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL DEFAULT 'user',
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL DEFAULT '',
    object_id TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id,occurred_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_events(action,occurred_at DESC)");
  await pool.query(`CREATE OR REPLACE FUNCTION protect_audit_events() RETURNS trigger AS $$
    BEGIN
      IF current_setting('app.allow_audit_mutation',TRUE)='on' THEN
        RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
      END IF;
      RAISE EXCEPTION 'audit_events is append-only';
    END;
  $$ LANGUAGE plpgsql`);
  await pool.query('DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events');
  await pool.query('CREATE TRIGGER trg_audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION protect_audit_events()');
  await pool.query('DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events');
  await pool.query('CREATE TRIGGER trg_audit_events_no_delete BEFORE DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION protect_audit_events()');
  await pool.query(`CREATE TABLE IF NOT EXISTS incidents(
    incident_id BIGSERIAL PRIMARY KEY,
    severity TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP,
    tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    subject_count_estimate INTEGER,
    description TEXT NOT NULL DEFAULT '',
    timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
    notification_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    due_24h TIMESTAMP,
    due_72h TIMESTAMP,
    root_cause TEXT NOT NULL DEFAULT '',
    corrective_actions TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_incidents_status_due ON incidents(status,due_24h,due_72h)");
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_access_sessions(
    id BIGSERIAL PRIMARY KEY,
    requester_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approver_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    ticket_id TEXT NOT NULL DEFAULT '',
    starts_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ends_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    actions_link TEXT NOT NULL DEFAULT ''
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS exports(
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    requester_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    scope TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    file_ref TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    downloaded_at TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'created'
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS deletion_jobs(
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    subject_ref TEXT NOT NULL,
    legal_reason TEXT NOT NULL,
    stores_targeted JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    result TEXT NOT NULL DEFAULT '',
    evidence_ref TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS retention_rules(
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    data_category TEXT NOT NULL,
    purpose_id TEXT NOT NULL,
    duration_rule TEXT NOT NULL,
    trigger_event TEXT NOT NULL,
    action TEXT NOT NULL,
    exception_hold TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS subprocessors_integrations(
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    vendor TEXT NOT NULL,
    country TEXT NOT NULL,
    data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    purpose TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    dpa_status TEXT NOT NULL DEFAULT '',
    transfer_status TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMP,
    owner TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);

  await pool.query(`INSERT INTO processing_purposes(purpose_id,description,legal_basis,categories,retention_rule,allowed_recipients)
    VALUES
      ('account_processing','Регистрация и обслуживание учётной записи','согласие/договор/иное применимое основание','["contact","account","security"]'::jsonb,'до достижения цели и применимых сроков','["authorized_staff"]'::jsonb),
      ('service_terms','Фиксация принятия пользовательского соглашения','договор','["account"]'::jsonb,'срок договора + применимый срок доказательств','["authorized_staff"]'::jsonb),
      ('marketing','Рекламные и маркетинговые сообщения','отдельное предварительное согласие','["email","phone"]'::jsonb,'до отзыва согласия','["authorized_marketing"]'::jsonb)
    ON CONFLICT(purpose_id) DO NOTHING`);

  const retentionDefaults=[
    ['account_identity','account_processing','до прекращения аккаунта; после подтверждённого запроса — удалить/заблокировать при отсутствии иного основания','account_closed_or_valid_deletion_request','delete_or_block','v1'],
    ['security_log','account_processing',String(process.env.RETENTION_SECURITY_LOG_DAYS||'365')+' дней','event_created','delete','v1'],
    ['session_data','account_processing','до истечения сессии','session_expired','delete','v1'],
    ['email_codes','account_processing','до истечения одноразового кода','code_expired','delete','v1'],
    ['backup_copy','account_processing',String(process.env.RETENTION_BACKUP_DAYS||'30')+' дней','backup_created','rotate_delete','v1'],
    ['consent_evidence','account_processing',String(process.env.RETENTION_CONSENT_EVIDENCE_DAYS||'1095')+' дней после прекращения соответствующей обработки либо дольше при наличии обязательного основания','processing_ended','delete_after_legal_check','v1'],
    ['dsar_evidence','account_processing',String(process.env.RETENTION_DSAR_EVIDENCE_DAYS||'1095')+' дней после закрытия запроса либо дольше при наличии обязательного основания','request_closed','delete_after_legal_check','v1']
  ];
  for(const row of retentionDefaults){
    const exists=await pool.query("SELECT 1 FROM retention_rules WHERE tenant_id IS NULL AND data_category=$1 AND purpose_id=$2 AND version=$3 LIMIT 1",[row[0],row[1],row[5]]);
    if(!exists.rows.length){
      await pool.query("INSERT INTO retention_rules(tenant_id,data_category,purpose_id,duration_rule,trigger_event,action,version,active) VALUES(NULL,$1,$2,$3,$4,$5,$6,TRUE)",row);
    }
  }

  await seedLegalDocuments(pool);
}

async function getActiveLegalDocuments(queryable){
  const r=await queryable.query("SELECT id,doc_type,version,title,content,content_hash,published_at FROM legal_documents WHERE active=TRUE ORDER BY doc_type");
  const out={};
  for(const row of r.rows)out[row.doc_type]=row;
  return out;
}

async function requiredConsentStatus(queryable,userId){
  const docs=await getActiveLegalDocuments(queryable);
  const required=['terms','pd_consent'];
  const items=[];
  let ready=true;
  for(const type of required){
    const doc=docs[type];
    if(!doc){items.push({type,ready:false,missing_document:true});ready=false;continue;}
    const purpose=type==='terms'?'service_terms':'account_processing';
    const r=await queryable.query(
      `SELECT consent_id,given_at,status,withdrawn_at FROM consents
       WHERE user_id=$1 AND purpose_id=$2 AND document_type=$3
         AND document_version=$4 AND document_hash=$5
         AND status='given' AND withdrawn_at IS NULL
       ORDER BY given_at DESC,consent_id DESC LIMIT 1`,
      [userId,purpose,type,doc.version,doc.content_hash]
    );
    const accepted=!!r.rows.length;
    if(!accepted)ready=false;
    items.push({type,title:doc.title,version:doc.version,hash:doc.content_hash,url:'/legal/'+type,ready:accepted,given_at:accepted?r.rows[0].given_at:null});
  }
  return {ready,items};
}

async function recordRegistrationConsents(client,req,user,options){
  const docs=await getActiveLegalDocuments(client);
  if(!options||options.termsAccepted!==true||options.pdConsent!==true)throw new Error('Необходимо отдельно принять пользовательское соглашение и дать согласие на обработку персональных данных');
  for(const required of ['terms','pd_consent'])if(!docs[required])throw new Error('Не опубликован обязательный юридический документ: '+required);
  const evidenceIp=requestIp(req),ua=String(req.get&&req.get('user-agent')||'').slice(0,500),subject=normalizeEmail(user.email)||String(user.login||'');
  const sourceForm=String(options.sourceForm||'registration').slice(0,120);
  const records=[
    {purpose:'service_terms',type:'terms',method:'checkbox'},
    {purpose:'account_processing',type:'pd_consent',method:'checkbox'}
  ];
  if(options.marketingConsent===true&&docs.marketing_consent)records.push({purpose:'marketing',type:'marketing_consent',method:'optional_checkbox'});
  for(const item of records){
    const doc=docs[item.type];
    const existing=await client.query(
      `SELECT consent_id FROM consents
       WHERE user_id=$1 AND purpose_id=$2 AND document_type=$3 AND document_version=$4 AND document_hash=$5
         AND status='given' AND withdrawn_at IS NULL
       LIMIT 1`,
      [user.id,item.purpose,item.type,doc.version,doc.content_hash]
    );
    if(existing.rows.length)continue;
    await client.query(
      `INSERT INTO consents(tenant_id,user_id,subject_ref,purpose_id,document_type,document_version,document_hash,channel,source_form,method,evidence_ip,evidence_user_agent,status,metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,'web',$8,$9,$10,$11,'given',$12::jsonb)`,
      [user.tenant_id||null,user.id,subject,item.purpose,item.type,doc.version,doc.content_hash,sourceForm,item.method,evidenceIp,ua,JSON.stringify({document_id:doc.id})]
    );
  }
}

function addBusinessDays(start,count){
  const d=new Date(start);
  let remaining=Number(count)||0;
  while(remaining>0){
    d.setDate(d.getDate()+1);
    const day=d.getDay();
    if(day!==0&&day!==6)remaining--;
  }
  return d;
}
function htmlEscape(value){
  return String(value==null?'':value).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function legalDocumentHtml(doc){
  const lines=htmlEscape(doc.content).replace(/\r?\n/g,'<br>');
  return '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+htmlEscape(doc.title)+'</title><style>body{font-family:system-ui,-apple-system,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;line-height:1.55;color:#172033}h1{font-size:26px}.meta{color:#667085;font-size:13px;margin-bottom:24px}.doc{white-space:normal}.back{display:inline-block;margin-top:28px;color:#0f3460}</style></head><body><h1>'+htmlEscape(doc.title)+'</h1><div class="meta">Версия: '+htmlEscape(doc.version)+' · опубликовано: '+htmlEscape(new Date(doc.published_at).toLocaleString('ru-RU'))+'<br>SHA-256: '+htmlEscape(doc.content_hash)+'</div><div class="doc">'+lines+'</div><a class="back" href="/">← Вернуться в сервис</a></body></html>';
}

async function insertAudit(pool,{actorId=null,tenantId=null,action,objectType='',objectId='',result='',sourceIp='',userAgent='',correlationId='',metadata={}}){
  try{
    await pool.query(
      `INSERT INTO audit_events(actor_id,tenant_id,action,object_type,object_id,result,source_ip,user_agent,correlation_id,metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
      [actorId,tenantId,action,objectType,String(objectId||''),result,sourceIp,String(userAgent||'').slice(0,500),correlationId,JSON.stringify(metadata||{})]
    );
  }catch(err){console.error('Compliance audit error:',err.message);}
}

function correlationMiddleware(req,res,next){
  const incoming=String(req.get&&req.get('x-request-id')||'').trim();
  req.correlationId=(/^[A-Za-z0-9._:-]{8,120}$/.test(incoming)?incoming:crypto.randomUUID());
  res.setHeader('X-Correlation-ID',req.correlationId);
  next();
}
function auditMutationMiddleware(pool){
  return function(req,res,next){
    if(['GET','HEAD','OPTIONS'].includes(req.method))return next();
    const started=Date.now();
    res.on('finish',()=>{
      const u=req.session&&req.session.user;
      const tenantId=u&&u.tenant_id||null;
      insertAudit(pool,{
        actorId:u&&u.id||null,
        tenantId,
        action:'http.'+req.method.toLowerCase(),
        objectType:'api_route',
        objectId:req.path,
        result:String(res.statusCode),
        sourceIp:requestIp(req),
        userAgent:req.get&&req.get('user-agent'),
        correlationId:req.correlationId||'',
        metadata:{duration_ms:Date.now()-started}
      });
    });
    next();
  };
}

function installComplianceRoutes(app,deps){
  const {pool,requireAuth,requirePermission,refreshAccessUser,isSiteWideUser}=deps;

  app.get('/api/public/legal-documents',async(req,res)=>{
    try{
      const docs=await getActiveLegalDocuments(pool);
      const payload={};
      for(const [type,doc] of Object.entries(docs))payload[type]={type,title:doc.title,version:doc.version,hash:doc.content_hash,published_at:doc.published_at,url:'/legal/'+encodeURIComponent(type)};
      const operator=operatorDetails();
      res.setHeader('Cache-Control','no-store');
      res.json({documents:payload,operator,operator_ready:operatorReady(operator)});
    }catch(err){res.status(500).json({error:'Не удалось загрузить юридические документы'});}
  });

  app.get('/legal/:type',async(req,res)=>{
    const type=String(req.params.type||'');
    if(!LEGAL_DOC_TYPES[type])return res.status(404).send('Документ не найден');
    try{
      const r=await pool.query("SELECT * FROM legal_documents WHERE doc_type=$1 AND active=TRUE ORDER BY published_at DESC,id DESC LIMIT 1",[type]);
      if(!r.rows.length)return res.status(404).send('Документ не опубликован');
      res.setHeader('Cache-Control','no-store');
      res.type('html').send(legalDocumentHtml(r.rows[0]));
    }catch(err){res.status(500).send('Ошибка загрузки документа');}
  });

  app.get('/api/compliance/required-consents',requireAuth,async(req,res)=>{
    try{
      const operator=operatorDetails();
      const status=await requiredConsentStatus(pool,req.session.user.id);
      res.json({
        enforced:String(process.env.COMPLIANCE_ENFORCE_CURRENT_CONSENTS||'false').trim().toLowerCase()==='true',
        operator_ready:operatorReady(operator),
        ...status
      });
    }catch(err){res.status(500).json({error:'Не удалось проверить актуальность согласий'});}
  });

  app.post('/api/compliance/accept-required',requireAuth,async(req,res)=>{
    const operator=operatorDetails();
    if(!operatorReady(operator))return res.status(503).json({error:'Реквизиты оператора персональных данных ещё не настроены'});
    if(req.body.terms_accepted!==true||req.body.pd_consent!==true)return res.status(400).json({error:'Оба обязательных юридических действия должны быть подтверждены отдельно'});
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const user=(await client.query('SELECT id,login,email,tenant_id FROM users WHERE id=$1 FOR UPDATE',[req.session.user.id])).rows[0];
      if(!user){await client.query('ROLLBACK');return res.status(401).json({error:'Аккаунт не найден'});}
      await recordRegistrationConsents(client,req,user,{termsAccepted:true,pdConsent:true,marketingConsent:false,sourceForm:'existing_account_legal_gate'});
      await client.query('COMMIT');
      const status=await requiredConsentStatus(pool,user.id);
      res.json({ok:true,...status});
    }catch(err){try{await client.query('ROLLBACK');}catch(e){}res.status(500).json({error:err.message});}
    finally{client.release();}
  });

  app.get('/api/compliance/my-consents',requireAuth,async(req,res)=>{
    try{
      const r=await pool.query(`SELECT consent_id,purpose_id,document_type,document_version,document_hash,given_at,withdrawn_at,status,withdrawal_channel
        FROM consents WHERE user_id=$1 ORDER BY given_at DESC,consent_id DESC`,[req.session.user.id]);
      res.json(r.rows);
    }catch(err){res.status(500).json({error:err.message});}
  });

  app.post('/api/compliance/consents/:id/withdraw',requireAuth,async(req,res)=>{
    const id=Number(req.params.id);
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректное согласие'});
    try{
      const r=await pool.query('SELECT * FROM consents WHERE consent_id=$1 AND user_id=$2',[id,req.session.user.id]);
      if(!r.rows.length)return res.status(404).json({error:'Согласие не найдено'});
      const c=r.rows[0];
      if(c.status==='withdrawn')return res.json({ok:true});
      await pool.query("UPDATE consents SET withdrawn_at=NOW(),withdrawal_channel='account',withdrawal_reason=$1,status='withdrawn' WHERE consent_id=$2",[String(req.body.reason||'').slice(0,500),id]);
      if(c.purpose_id==='marketing'){
        const address=normalizeEmail(c.subject_ref);
        if(address)await pool.query("INSERT INTO marketing_suppression(normalized_address,source_consent_id,reason) VALUES($1,$2,'withdrawal') ON CONFLICT(normalized_address) DO UPDATE SET source_consent_id=EXCLUDED.source_consent_id,suppressed_at=NOW(),reason='withdrawal'",[address,id]);
      }
      res.json({ok:true,message:c.purpose_id==='marketing'?'Рекламное согласие отозвано':'Отзыв согласия зафиксирован. Обработка на иных законных основаниях может продолжаться.'});
    }catch(err){res.status(500).json({error:err.message});}
  });

  app.get('/api/compliance/dsar/my',requireAuth,async(req,res)=>{
    try{
      const r=await pool.query('SELECT * FROM data_subject_requests WHERE requester_user_id=$1 ORDER BY received_at DESC,request_id DESC',[req.session.user.id]);
      res.json(r.rows);
    }catch(err){res.status(500).json({error:err.message});}
  });

  app.post('/api/compliance/dsar',requireAuth,async(req,res)=>{
    const type=String(req.body.type||'').trim();
    if(!DSAR_TYPES.has(type))return res.status(400).json({error:'Некорректный тип запроса'});
    const details=String(req.body.details||'').trim().slice(0,5000);
    try{
      const actor=await refreshAccessUser(req);
      const due=addBusinessDays(new Date(),10);
      const subject=normalizeEmail(actor.email)||String(actor.login||'');
      const r=await pool.query(
        `INSERT INTO data_subject_requests(tenant_id,requester_user_id,subject_ref,request_type,due_at,details,created_by)
         VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [actor.tenant_id||null,actor.id,subject,type,due,details,actor.login]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(500).json({error:err.message});}
  });

  app.get('/api/compliance/dsar',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      let r;
      if(isSiteWideUser(actor))r=await pool.query('SELECT * FROM data_subject_requests ORDER BY received_at DESC,request_id DESC LIMIT 1000');
      else r=await pool.query('SELECT * FROM data_subject_requests WHERE tenant_id=$1 ORDER BY received_at DESC,request_id DESC LIMIT 1000',[actor.tenant_id||null]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.patch('/api/compliance/dsar/:id',requirePermission('compliance.manage'),async(req,res)=>{
    const id=Number(req.params.id),status=String(req.body.status||'').trim();
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный запрос'});
    if(status&&!DSAR_STATUSES.has(status))return res.status(400).json({error:'Некорректный статус'});
    try{
      const actor=await refreshAccessUser(req);
      const q=isSiteWideUser(actor)?await pool.query('SELECT * FROM data_subject_requests WHERE request_id=$1',[id]):await pool.query('SELECT * FROM data_subject_requests WHERE request_id=$1 AND tenant_id=$2',[id,actor.tenant_id||null]);
      if(!q.rows.length)return res.status(404).json({error:'Запрос не найден'});
      let dueAt=q.rows[0].due_at,extensionReason=q.rows[0].extension_reason||'',extendedAt=q.rows[0].extended_at;
      if(req.body.extend===true){
        extensionReason=String(req.body.extension_reason||'').trim().slice(0,2000);
        if(!extensionReason)return res.status(400).json({error:'Укажите мотивированную причину продления'});
        dueAt=addBusinessDays(new Date(dueAt),5);
        extendedAt=new Date();
      }
      const r=await pool.query(
        `UPDATE data_subject_requests SET status=COALESCE(NULLIF($1,''),status),decision=$2,due_at=$3,extension_reason=$4,extended_at=$5,
         completed_at=CASE WHEN COALESCE(NULLIF($1,''),status) IN ('completed','rejected') THEN COALESCE(completed_at,NOW()) ELSE completed_at END
         WHERE request_id=$6 RETURNING *`,
        [status,String(req.body.decision||'').slice(0,5000),dueAt,extensionReason,extendedAt,id]
      );
      res.json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.get('/api/compliance/incidents',requirePermission('incidents.manage'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      let r;
      if(isSiteWideUser(actor))r=await pool.query('SELECT * FROM incidents ORDER BY created_at DESC,incident_id DESC LIMIT 500');
      else r=await pool.query("SELECT * FROM incidents WHERE tenant_ids @> $1::jsonb ORDER BY created_at DESC,incident_id DESC LIMIT 500",[JSON.stringify([actor.tenant_id])]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/incidents',requirePermission('incidents.manage'),async(req,res)=>{
    const severity=String(req.body.severity||'').trim();
    if(!INCIDENT_SEVERITIES.has(severity))return res.status(400).json({error:'Некорректная критичность'});
    try{
      const actor=await refreshAccessUser(req);
      const detected=req.body.detected_at?new Date(req.body.detected_at):new Date();
      const confirmed=req.body.confirmed_at?new Date(req.body.confirmed_at):null;
      if(Number.isNaN(detected.getTime())||(confirmed&&Number.isNaN(confirmed.getTime())))return res.status(400).json({error:'Некорректная дата'});
      let tenantIds=Array.isArray(req.body.tenant_ids)?req.body.tenant_ids.map(Number).filter(Number.isInteger):[];
      if(!isSiteWideUser(actor))tenantIds=actor.tenant_id?[actor.tenant_id]:[];
      const due24=confirmed?new Date(confirmed.getTime()+24*60*60*1000):null;
      const due72=confirmed?new Date(confirmed.getTime()+72*60*60*1000):null;
      const r=await pool.query(
        `INSERT INTO incidents(severity,detected_at,confirmed_at,tenant_ids,data_categories,subject_count_estimate,description,due_24h,due_72h,created_by)
         VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10) RETURNING *`,
        [severity,detected,confirmed,JSON.stringify(tenantIds),JSON.stringify(Array.isArray(req.body.data_categories)?req.body.data_categories:[]),Number.isInteger(Number(req.body.subject_count_estimate))?Number(req.body.subject_count_estimate):null,String(req.body.description||'').slice(0,10000),due24,due72,actor.id]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.patch('/api/compliance/incidents/:id',requirePermission('incidents.manage'),async(req,res)=>{
    const id=Number(req.params.id),status=String(req.body.status||'').trim();
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный инцидент'});
    if(status&&!INCIDENT_STATUSES.has(status))return res.status(400).json({error:'Некорректный статус'});
    try{
      const actor=await refreshAccessUser(req);
      const check=await pool.query('SELECT * FROM incidents WHERE incident_id=$1',[id]);
      if(!check.rows.length)return res.status(404).json({error:'Инцидент не найден'});
      if(!isSiteWideUser(actor)){
        const ids=Array.isArray(check.rows[0].tenant_ids)?check.rows[0].tenant_ids:[];
        if(!ids.map(Number).includes(Number(actor.tenant_id)))return res.status(403).json({error:'Нет доступа к этому инциденту'});
      }
      const confirmed=req.body.confirmed_at?new Date(req.body.confirmed_at):(check.rows[0].confirmed_at?new Date(check.rows[0].confirmed_at):null);
      if(confirmed&&Number.isNaN(confirmed.getTime()))return res.status(400).json({error:'Некорректная дата подтверждения'});
      const due24=confirmed?new Date(confirmed.getTime()+24*60*60*1000):null,due72=confirmed?new Date(confirmed.getTime()+72*60*60*1000):null;
      const r=await pool.query(
        `UPDATE incidents SET status=COALESCE(NULLIF($1,''),status),confirmed_at=$2,due_24h=$3,due_72h=$4,
         root_cause=$5,corrective_actions=$6,notification_status=COALESCE($7::jsonb,notification_status),updated_at=NOW()
         WHERE incident_id=$8 RETURNING *`,
        [status,confirmed,due24,due72,String(req.body.root_cause||check.rows[0].root_cause||'').slice(0,10000),String(req.body.corrective_actions||check.rows[0].corrective_actions||'').slice(0,10000),req.body.notification_status?JSON.stringify(req.body.notification_status):null,id]
      );
      res.json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.get('/api/compliance/audit',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      let r;
      if(isSiteWideUser(actor))r=await pool.query('SELECT * FROM audit_events ORDER BY occurred_at DESC,event_id DESC LIMIT 1000');
      else r=await pool.query('SELECT * FROM audit_events WHERE tenant_id=$1 ORDER BY occurred_at DESC,event_id DESC LIMIT 1000',[actor.tenant_id||null]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.get('/api/compliance/legal-documents',requirePermission('legal.manage'),async(req,res)=>{
    try{res.json((await pool.query('SELECT id,doc_type,version,title,content_hash,published_at,active FROM legal_documents ORDER BY doc_type,published_at DESC,id DESC')).rows);}
    catch(err){res.status(500).json({error:err.message});}
  });

  app.post('/api/compliance/legal-documents',requirePermission('legal.manage'),async(req,res)=>{
    const type=String(req.body.doc_type||''),version=String(req.body.version||'').trim(),title=String(req.body.title||'').trim(),content=String(req.body.content||'').trim();
    if(!LEGAL_DOC_TYPES[type]||!version||!title||!content)return res.status(400).json({error:'Заполните тип, версию, заголовок и текст документа'});
    const hash=sha256(content);
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const existing=await client.query('SELECT id,content_hash FROM legal_documents WHERE doc_type=$1 AND version=$2 FOR UPDATE',[type,version]);
      if(existing.rows.length&&existing.rows[0].content_hash!==hash){
        await client.query('ROLLBACK');
        return res.status(409).json({error:'Опубликованная версия юридического документа неизменяема. Используйте новый номер версии.'});
      }
      await client.query('UPDATE legal_documents SET active=FALSE WHERE doc_type=$1',[type]);
      let r;
      if(existing.rows.length){
        r=await client.query('UPDATE legal_documents SET active=TRUE WHERE id=$1 RETURNING id,doc_type,version,title,content_hash,published_at,active',[existing.rows[0].id]);
      }else{
        r=await client.query(`INSERT INTO legal_documents(doc_type,version,title,content,content_hash,published_at,active)
          VALUES($1,$2,$3,$4,$5,NOW(),TRUE)
          RETURNING id,doc_type,version,title,content_hash,published_at,active`,[type,version,title,content,hash]);
      }
      await client.query('COMMIT');res.status(201).json(r.rows[0]);
    }catch(err){await client.query('ROLLBACK');res.status(500).json({error:err.message});}
    finally{client.release();}
  });

  app.get('/api/compliance/integrations',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const r=isSiteWideUser(actor)?await pool.query('SELECT * FROM subprocessors_integrations ORDER BY created_at DESC,id DESC'):await pool.query('SELECT * FROM subprocessors_integrations WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC',[actor.tenant_id||null]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/integrations',requirePermission('compliance.manage'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const tenantId=isSiteWideUser(actor)&&Number.isInteger(Number(req.body.tenant_id))?Number(req.body.tenant_id):actor.tenant_id||null;
      const r=await pool.query(
        `INSERT INTO subprocessors_integrations(tenant_id,vendor,country,data_categories,purpose,endpoint,dpa_status,transfer_status,approved_at,owner)
         VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [tenantId,String(req.body.vendor||'').trim(),String(req.body.country||'').trim(),JSON.stringify(Array.isArray(req.body.data_categories)?req.body.data_categories:[]),String(req.body.purpose||'').trim(),String(req.body.endpoint||'').trim(),String(req.body.dpa_status||'').trim(),String(req.body.transfer_status||'').trim(),req.body.approved_at||null,String(req.body.owner||'').trim()]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });


  app.get('/api/compliance/retention-rules',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const r=isSiteWideUser(actor)
        ?await pool.query('SELECT * FROM retention_rules ORDER BY active DESC,created_at DESC,id DESC')
        :await pool.query('SELECT * FROM retention_rules WHERE tenant_id=$1 OR tenant_id IS NULL ORDER BY tenant_id NULLS FIRST,active DESC,created_at DESC,id DESC',[actor.tenant_id||null]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/retention-rules',requirePermission('compliance.manage'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const tenantId=isSiteWideUser(actor)&&Number.isInteger(Number(req.body.tenant_id))?Number(req.body.tenant_id):actor.tenant_id||null;
      const dataCategory=String(req.body.data_category||'').trim().slice(0,200);
      const purposeId=String(req.body.purpose_id||'').trim().slice(0,120);
      const durationRule=String(req.body.duration_rule||'').trim().slice(0,500);
      const triggerEvent=String(req.body.trigger_event||'').trim().slice(0,200);
      const action=String(req.body.action||'').trim().slice(0,120);
      const exceptionHold=String(req.body.exception_hold||'').trim().slice(0,1000);
      const version=String(req.body.version||'').trim().slice(0,120);
      if(!dataCategory||!purposeId||!durationRule||!triggerEvent||!action||!version)return res.status(400).json({error:'Заполните категорию данных, цель, срок, триггер, действие и версию правила'});
      const r=await pool.query(
        `INSERT INTO retention_rules(tenant_id,data_category,purpose_id,duration_rule,trigger_event,action,exception_hold,version,active)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,TRUE) RETURNING *`,
        [tenantId,dataCategory,purposeId,durationRule,triggerEvent,action,exceptionHold,version]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.patch('/api/compliance/retention-rules/:id',requirePermission('compliance.manage'),async(req,res)=>{
    const id=Number(req.params.id);
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректное правило'});
    try{
      const actor=await refreshAccessUser(req);
      const check=isSiteWideUser(actor)
        ?await pool.query('SELECT * FROM retention_rules WHERE id=$1',[id])
        :await pool.query('SELECT * FROM retention_rules WHERE id=$1 AND tenant_id=$2',[id,actor.tenant_id||null]);
      if(!check.rows.length)return res.status(404).json({error:'Правило не найдено'});
      const active=req.body.active===undefined?check.rows[0].active:req.body.active===true;
      const exceptionHold=req.body.exception_hold===undefined?check.rows[0].exception_hold:String(req.body.exception_hold||'').trim().slice(0,1000);
      const r=await pool.query('UPDATE retention_rules SET active=$1,exception_hold=$2 WHERE id=$3 RETURNING *',[active,exceptionHold,id]);
      res.json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.get('/api/compliance/deletion-jobs',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const r=isSiteWideUser(actor)
        ?await pool.query('SELECT * FROM deletion_jobs ORDER BY created_at DESC,id DESC LIMIT 1000')
        :await pool.query('SELECT * FROM deletion_jobs WHERE tenant_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1000',[actor.tenant_id||null]);
      res.json(r.rows);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/deletion-jobs',requirePermission('compliance.manage'),async(req,res)=>{
    try{
      const actor=await refreshAccessUser(req);
      const tenantId=isSiteWideUser(actor)&&Number.isInteger(Number(req.body.tenant_id))?Number(req.body.tenant_id):actor.tenant_id||null;
      const subjectRef=String(req.body.subject_ref||'').trim().slice(0,500);
      const legalReason=String(req.body.legal_reason||'').trim().slice(0,2000);
      const stores=Array.isArray(req.body.stores_targeted)?req.body.stores_targeted.map(x=>String(x||'').trim().slice(0,120)).filter(Boolean):[];
      if(!subjectRef||!legalReason||!stores.length)return res.status(400).json({error:'Укажите субъект, правовое основание и хотя бы одно хранилище'});
      const r=await pool.query(
        `INSERT INTO deletion_jobs(tenant_id,subject_ref,legal_reason,stores_targeted,status)
         VALUES($1,$2,$3,$4::jsonb,'queued') RETURNING *`,
        [tenantId,subjectRef,legalReason,JSON.stringify(stores)]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/dsar/:id/deletion-job',requirePermission('compliance.manage'),async(req,res)=>{
    const id=Number(req.params.id);
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный запрос'});
    try{
      const actor=await refreshAccessUser(req);
      const q=isSiteWideUser(actor)
        ?await pool.query('SELECT * FROM data_subject_requests WHERE request_id=$1',[id])
        :await pool.query('SELECT * FROM data_subject_requests WHERE request_id=$1 AND tenant_id=$2',[id,actor.tenant_id||null]);
      if(!q.rows.length)return res.status(404).json({error:'Запрос не найден'});
      const dsar=q.rows[0];
      if(dsar.request_type!=='deletion')return res.status(409).json({error:'Deletion job можно создать только для запроса на уничтожение'});
      const stores=Array.isArray(req.body.stores_targeted)&&req.body.stores_targeted.length?req.body.stores_targeted:['users','employees','salary_records','files','audit-derived'];
      const reason=String(req.body.legal_reason||dsar.details||'Запрос субъекта на уничтожение персональных данных').trim().slice(0,2000);
      const existing=await pool.query("SELECT * FROM deletion_jobs WHERE tenant_id IS NOT DISTINCT FROM $1 AND subject_ref=$2 AND status IN ('queued','in_progress','blocked') ORDER BY created_at DESC LIMIT 1",[dsar.tenant_id,dsar.subject_ref]);
      if(existing.rows.length)return res.status(409).json({error:'Для этого субъекта уже есть незавершённая задача на уничтожение',deletion_job:existing.rows[0]});
      const r=await pool.query(
        `INSERT INTO deletion_jobs(tenant_id,subject_ref,legal_reason,stores_targeted,status,evidence_ref)
         VALUES($1,$2,$3,$4::jsonb,'queued',$5) RETURNING *`,
        [dsar.tenant_id,dsar.subject_ref,reason,JSON.stringify(stores),'dsar:'+id]
      );
      res.status(201).json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.patch('/api/compliance/deletion-jobs/:id',requirePermission('compliance.manage'),async(req,res)=>{
    const id=Number(req.params.id);
    const allowed=new Set(['queued','in_progress','blocked','completed','failed']);
    const status=String(req.body.status||'').trim();
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректная задача'});
    if(!allowed.has(status))return res.status(400).json({error:'Некорректный статус'});
    try{
      const actor=await refreshAccessUser(req);
      const q=isSiteWideUser(actor)
        ?await pool.query('SELECT * FROM deletion_jobs WHERE id=$1',[id])
        :await pool.query('SELECT * FROM deletion_jobs WHERE id=$1 AND tenant_id=$2',[id,actor.tenant_id||null]);
      if(!q.rows.length)return res.status(404).json({error:'Задача не найдена'});
      const result=String(req.body.result||q.rows[0].result||'').trim().slice(0,10000);
      const evidenceRef=String(req.body.evidence_ref||q.rows[0].evidence_ref||'').trim().slice(0,1000);
      if(status==='completed'&&(!result||!evidenceRef))return res.status(400).json({error:'Для завершения задачи обязательны результат и ссылка/идентификатор evidence'});
      const r=await pool.query(
        `UPDATE deletion_jobs SET status=$1,
           started_at=CASE WHEN $1='in_progress' THEN COALESCE(started_at,NOW()) ELSE started_at END,
           completed_at=CASE WHEN $1='completed' THEN COALESCE(completed_at,NOW()) WHEN $1 IN ('queued','in_progress','blocked') THEN NULL ELSE completed_at END,
           result=$2,evidence_ref=$3
         WHERE id=$4 RETURNING *`,
        [status,result,evidenceRef,id]
      );
      res.json(r.rows[0]);
    }catch(err){res.status(err.status||500).json({error:err.message});}
  });

  app.post('/api/compliance/deletion-jobs/:id/execute-account',requirePermission('compliance.manage'),async(req,res)=>{
    const id=Number(req.params.id);
    if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректная задача'});
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      const actor=await refreshAccessUser(req);
      const q=isSiteWideUser(actor)
        ?await client.query('SELECT * FROM deletion_jobs WHERE id=$1 FOR UPDATE',[id])
        :await client.query('SELECT * FROM deletion_jobs WHERE id=$1 AND tenant_id=$2 FOR UPDATE',[id,actor.tenant_id||null]);
      if(!q.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Задача не найдена'});}
      const job=q.rows[0];
      if(job.status==='completed'){await client.query('ROLLBACK');return res.status(409).json({error:'Задача уже завершена'});}
      const subject=String(job.subject_ref||'').trim();
      const params=[subject];
      let tenantSql='';
      if(job.tenant_id!=null){params.push(job.tenant_id);tenantSql=' AND tenant_id=$2';}
      const userResult=await client.query(
        "SELECT id,login,email,fio,tenant_id FROM users WHERE upper(trim(login))<>'ADMIN' AND (lower(trim(COALESCE(email,'')))=lower(trim($1)) OR lower(trim(login))=lower(trim($1)) OR lower(trim(fio))=lower(trim($1)))"+tenantSql+" ORDER BY id LIMIT 2",
        params
      );
      if(userResult.rows.length>1){
        await client.query("UPDATE deletion_jobs SET status='blocked',started_at=COALESCE(started_at,NOW()),result=$1 WHERE id=$2",['Найдено несколько аккаунтов по идентификатору; требуется ручная идентификация субъекта.',id]);
        await client.query('COMMIT');
        return res.status(409).json({error:'Найдено несколько аккаунтов; требуется ручная идентификация'});
      }
      if(!userResult.rows.length){
        await client.query("UPDATE deletion_jobs SET status='blocked',started_at=COALESCE(started_at,NOW()),result=$1 WHERE id=$2",['Аккаунт по subject_ref не найден. Кадровые/расчётные данные не удаляются автоматически без отдельного решения оператора-клиента.',id]);
        await client.query('COMMIT');
        return res.status(409).json({error:'Аккаунт не найден; задача переведена в blocked для ручной проверки'});
      }
      const user=userResult.rows[0];
      const identifiers=[
        ['email',normalizeEmail(user.email)],
        ['login',String(user.login||'').trim().toLowerCase()],
        ['fio',String(user.fio||'').trim().toLowerCase()]
      ].filter(x=>x[1]);
      for(const [type,value] of identifiers){
        await client.query(
          `INSERT INTO privacy_tombstones(identifier_hash,identifier_type,tenant_id,reason)
           VALUES($1,$2,$3,$4)
           ON CONFLICT(identifier_hash,identifier_type,tenant_id) DO UPDATE SET reason=EXCLUDED.reason`,
          [sha256(value),type,user.tenant_id||null,'deletion_job:'+id]
        );
      }
      await client.query("DELETE FROM app_sessions WHERE (sess->'user'->>'id')::text=$1",[String(user.id)]);
      await client.query('DELETE FROM email_codes WHERE user_id=$1',[user.id]);
      await client.query('DELETE FROM users WHERE id=$1',[user.id]);

      const employeeMatches=await client.query(
        "SELECT COUNT(*)::int AS n FROM employees WHERE lower(trim(fio))=lower(trim($1))"+(user.tenant_id!=null?' AND tenant_id=$2':''),
        user.tenant_id!=null?[user.fio,user.tenant_id]:[user.fio]
      );
      const retainedEmployeeRows=Number(employeeMatches.rows[0]&&employeeMatches.rows[0].n||0);
      const result='Аккаунт, активные сессии и одноразовые коды физически удалены. Consent/audit evidence сохранены в минимальном доказательственном составе без активной учётной записи. Совпадающих кадровых записей клиента: '+retainedEmployeeRows+'. Их обработка имеет отдельную роль/основание и требует решения оператора-клиента.';
      const evidence='privacy_tombstone:'+id+':'+sha256(identifiers.map(x=>x[0]+':'+x[1]).join('|')).slice(0,24);
      await client.query(
        "UPDATE deletion_jobs SET status='completed',started_at=COALESCE(started_at,NOW()),completed_at=NOW(),result=$1,evidence_ref=$2 WHERE id=$3",
        [result,evidence,id]
      );
      await client.query('COMMIT');
      res.json({ok:true,status:'completed',result,evidence_ref:evidence,retained_employee_rows:retainedEmployeeRows});
    }catch(err){
      try{await client.query('ROLLBACK');}catch(e){}
      res.status(err.status||500).json({error:err.message});
    }finally{client.release();}
  });

  app.get('/api/compliance/status',requirePermission('compliance.view'),async(req,res)=>{
    try{
      const operator=operatorDetails();
      const docs=await getActiveLegalDocuments(pool);
      const required=['privacy_policy','pd_consent','terms'];
      const tenantNullCounts={};
      for(const table of ['users','employees','objects','salary_records']){
        tenantNullCounts[table]=Number((await pool.query('SELECT COUNT(*)::int AS n FROM '+table+" WHERE tenant_id IS NULL AND trim(COALESCE(organization,''))<>''")).rows[0].n||0);
      }
      res.json({
        operator_ready:operatorReady(operator),
        operator,
        legal_documents_ready:required.every(x=>!!docs[x]),
        legal_documents:Object.fromEntries(Object.entries(docs).map(([k,v])=>[k,{version:v.version,hash:v.content_hash,published_at:v.published_at}])),
        data_region:String(process.env.DATA_REGION||'RU'),
        platform_mfa_enabled:String(process.env.PLATFORM_MFA_ENABLED||'false').toLowerCase()==='true',
        tenant_backfill_missing:tenantNullCounts,
        notes:[
          'Конкретный уровень защищённости ИСПДн и набор мер определяются отдельной моделью угроз.',
          'Проверка фактического российского размещения DB/storage/logs/backups выполняется на уровне инфраструктуры.'
        ]
      });
    }catch(err){res.status(500).json({error:err.message});}
  });
}


const COMPLIANCE_BACKUP_TABLES=[
  'processing_purposes','legal_documents','consents','marketing_suppression',
  'data_subject_requests','audit_events','incidents','admin_access_sessions',
  'exports','deletion_jobs','retention_rules','subprocessors_integrations'
];
const COMPLIANCE_DELETE_ORDER=[
  'marketing_suppression','consents','data_subject_requests','audit_events','incidents',
  'admin_access_sessions','exports','deletion_jobs','retention_rules','subprocessors_integrations',
  'legal_documents','processing_purposes'
];
const COMPLIANCE_SEQUENCE_COLUMNS={
  legal_documents:'id',consents:'consent_id',marketing_suppression:'id',
  data_subject_requests:'request_id',audit_events:'event_id',incidents:'incident_id',
  admin_access_sessions:'id',exports:'id',deletion_jobs:'id',retention_rules:'id',
  subprocessors_integrations:'id'
};

async function collectComplianceBackup(queryable){
  const data={};
  for(const table of COMPLIANCE_BACKUP_TABLES){
    data[table]=(await queryable.query('SELECT * FROM '+table+' ORDER BY 1')).rows;
  }
  return data;
}
async function restoreComplianceBackup(client,data){
  if(!data||typeof data!=='object')return;
  await client.query("SELECT set_config('app.allow_audit_mutation','on',true)");
  for(const table of COMPLIANCE_DELETE_ORDER)await client.query('DELETE FROM '+table);
  for(const table of COMPLIANCE_BACKUP_TABLES){
    const rows=Array.isArray(data[table])?data[table]:[];
    if(!rows.length)continue;
    await client.query('INSERT INTO '+table+' SELECT * FROM jsonb_populate_recordset(NULL::'+table+',$1::jsonb)',[JSON.stringify(rows)]);
  }
  for(const [table,column] of Object.entries(COMPLIANCE_SEQUENCE_COLUMNS)){
    await client.query("SELECT setval(pg_get_serial_sequence('"+table+"','"+column+"'), COALESCE((SELECT MAX("+column+") FROM "+table+"),1), (SELECT COUNT(*)>0 FROM "+table+"))");
  }
}

module.exports={
  ensureComplianceSchema,
  getActiveLegalDocuments,
  requiredConsentStatus,
  recordRegistrationConsents,
  correlationMiddleware,
  auditMutationMiddleware,
  installComplianceRoutes,
  operatorDetails,
  operatorReady,
  collectComplianceBackup,
  restoreComplianceBackup
};
