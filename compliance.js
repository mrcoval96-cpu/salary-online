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
  return !!(details.name&&details.inn&&details.ogrnip&&details.email);
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

2. Категории субъектов и данных
В зависимости от сценария могут обрабатываться данные пользователей аккаунтов, работников и иных лиц, данные которых законно внесены клиентом-оператором. Набор может включать ФИО, контактные данные, сведения об организации и учётной записи, сведения о трудовых и расчётных процессах, технические сведения о входах и действиях, а также иные данные, предусмотренные функционалом и договором.

3. Цели
Регистрация и ведение аккаунта; предоставление функционала сервиса; разграничение доступа; расчёт и учёт; информационная безопасность; исполнение запросов субъектов; выполнение договорных и законных обязанностей. Рекламные сообщения осуществляются только при наличии отдельного применимого основания.

4. Операции и сроки
Могут выполняться сбор, запись, систематизация, накопление, хранение, уточнение, извлечение, использование, предоставление уполномоченным пользователям, блокирование, удаление и уничтожение. Сроки определяются целью, договором, требованиями закона и применимыми retention rules.

5. Локализация и получатели
Основной production-контур, содержащий персональные данные граждан РФ, должен размещаться в инфраструктуре РФ. Подрядчики и субобработчики привлекаются в пределах договорных поручений и предоставленных полномочий. Трансграничная передача требует отдельной проверки и правового основания.

6. Защита
Применяются организационные и технические меры, включая аутентификацию, управление доступом, серверную проверку полномочий, журналирование значимых событий, резервное копирование, контроль восстановления, защиту каналов связи и управление секретами. Конкретный набор мер определяется моделью угроз и уровнем защищённости ИСПДн.

7. Права субъекта
Субъект вправе направлять запросы о наличии и обработке данных, требовать уточнения, блокирования или уничтожения в предусмотренных законом случаях, а также отзывать согласие в отношении операций, основанных на таком согласии. Канал обращений: ${email}.

8. Актуальность
Актуальная версия Политики публикуется в сервисе. Изменения фиксируются версией и контрольной суммой.`;
  }
  if(type==='pd_consent'){
    return `СОГЛАСИЕ НА ОБРАБОТКУ ПЕРСОНАЛЬНЫХ ДАННЫХ

Я свободно, своей волей и в своём интересе даю ${operator}, ИНН ${inn}, ОГРНИП ${ogrnip}, согласие на обработку персональных данных, которые я предоставляю при регистрации и использовании сервиса «Зарплата: учёт и расчёт».

Цели: создание и ведение учётной записи, предоставление функционала сервиса, идентификация и аутентификация, связь по вопросам использования сервиса, обеспечение безопасности и исполнение моих запросов.

Перечень данных в рамках регистрации: ФИО, телефон, электронная почта, организация, сведения об учётной записи и технические сведения, необходимые для доказательства факта регистрации и обеспечения безопасности.

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
    await pool.query('BEGIN');
    try{
      await pool.query("UPDATE legal_documents SET active=FALSE WHERE doc_type=$1 AND active=TRUE",[type]);
      await pool.query(
        "INSERT INTO legal_documents(doc_type,version,title,content,content_hash,published_at,active) VALUES($1,$2,$3,$4,$5,NOW(),TRUE) ON CONFLICT(doc_type,version) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,content_hash=EXCLUDED.content_hash,published_at=NOW(),active=TRUE",
        [type,version,LEGAL_DOC_TYPES[type],content,hash]
      );
      await pool.query('COMMIT');
    }catch(err){await pool.query('ROLLBACK');throw err;}
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

  await seedLegalDocuments(pool);
}

async function getActiveLegalDocuments(queryable){
  const r=await queryable.query("SELECT id,doc_type,version,title,content,content_hash,published_at FROM legal_documents WHERE active=TRUE ORDER BY doc_type");
  const out={};
  for(const row of r.rows)out[row.doc_type]=row;
  return out;
}

async function recordRegistrationConsents(client,req,user,options){
  const docs=await getActiveLegalDocuments(client);
  if(!options||options.termsAccepted!==true||options.pdConsent!==true)throw new Error('Необходимо отдельно принять пользовательское соглашение и дать согласие на обработку персональных данных');
  for(const required of ['terms','pd_consent'])if(!docs[required])throw new Error('Не опубликован обязательный юридический документ: '+required);
  const evidenceIp=requestIp(req),ua=String(req.get&&req.get('user-agent')||'').slice(0,500),subject=normalizeEmail(user.email)||String(user.login||'');
  const records=[
    {purpose:'service_terms',type:'terms',method:'checkbox'},
    {purpose:'account_processing',type:'pd_consent',method:'checkbox'}
  ];
  if(options.marketingConsent===true&&docs.marketing_consent)records.push({purpose:'marketing',type:'marketing_consent',method:'optional_checkbox'});
  for(const item of records){
    const doc=docs[item.type];
    await client.query(
      `INSERT INTO consents(tenant_id,user_id,subject_ref,purpose_id,document_type,document_version,document_hash,channel,source_form,method,evidence_ip,evidence_user_agent,status,metadata)
       VALUES($1,$2,$3,$4,$5,$6,$7,'web','registration',$8,$9,$10,'given',$11::jsonb)`,
      [user.tenant_id||null,user.id,subject,item.purpose,item.type,doc.version,doc.content_hash,item.method,evidenceIp,ua,JSON.stringify({document_id:doc.id})]
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
      await client.query('UPDATE legal_documents SET active=FALSE WHERE doc_type=$1',[type]);
      const r=await client.query(`INSERT INTO legal_documents(doc_type,version,title,content,content_hash,published_at,active)
        VALUES($1,$2,$3,$4,$5,NOW(),TRUE)
        ON CONFLICT(doc_type,version) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,content_hash=EXCLUDED.content_hash,published_at=NOW(),active=TRUE
        RETURNING id,doc_type,version,title,content_hash,published_at,active`,[type,version,title,content,hash]);
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

module.exports={
  ensureComplianceSchema,
  getActiveLegalDocuments,
  recordRegistrationConsents,
  correlationMiddleware,
  auditMutationMiddleware,
  installComplianceRoutes,
  operatorDetails
};
