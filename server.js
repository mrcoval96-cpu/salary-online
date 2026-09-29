const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

dotenv.config();

const app = express();
app.set('trust proxy', 1);
app.get('/health', (req, res) => res.status(200).send('OK'));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = String(process.env.SESSION_SECRET || '').trim() || crypto.randomBytes(48).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('SECURITY WARNING: SESSION_SECRET is not set. Using a random per-process secret; all sessions will be invalidated after restart. Set SESSION_SECRET in Timeweb.');
}

// Deployment retry marker.  

// Deployment retry after registry pull failure.

// Deployment trigger: refresh application after balance direction update. 
// Email verification and password recovery are enabled again.
const EMAIL_VERIFY_ENABLED = true;

// PostgreSQL pool
const fs = require('fs');
const sslConfig = {};
try {
  if (process.env.DATABASE_URL.includes('twc1.net') || process.env.DATABASE_URL.includes('timeweb')) {
    sslConfig.ssl = { rejectUnauthorized: false };
  }
} catch(e) {}


if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ...sslConfig
});
try{
  const dbUrl=new URL(process.env.DATABASE_URL);
  const hosted=!['localhost','127.0.0.1','::1'].includes(dbUrl.hostname);
  if(hosted && !sslConfig.ssl && String(process.env.DB_ALLOW_PLAINTEXT||'').toLowerCase()!=='true'){
    throw new Error('Refusing unencrypted connection to hosted PostgreSQL. Configure TLS or set DB_ALLOW_PLAINTEXT=true only if the database is on a trusted private network.');
  }
  console.log('Database transport:',sslConfig.ssl?'TLS enabled':(hosted?'plaintext explicitly allowed':'local connection'));
}catch(e){
  if(String(e.message||'').startsWith('Refusing unencrypted'))throw e;
  console.warn('Database security check:',e.message);
}


async function ensureDatabaseSchema(){
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_by TEXT");
  await pool.query("CREATE TABLE IF NOT EXISTS closed_salary_periods (month TEXT NOT NULL, year TEXT NOT NULL, organization TEXT NOT NULL DEFAULT '', closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, closed_by TEXT)");
  await pool.query("ALTER TABLE closed_salary_periods ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE closed_salary_periods DROP CONSTRAINT IF EXISTS closed_salary_periods_pkey");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_closed_salary_periods_scope ON closed_salary_periods(month,year,organization)");
  await pool.query("CREATE TABLE IF NOT EXISTS automatic_backups (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB NOT NULL)");
  await pool.query("CREATE TABLE IF NOT EXISTS security_log (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, event TEXT NOT NULL, user_login TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', success BOOLEAN NOT NULL DEFAULT FALSE, details TEXT NOT NULL DEFAULT '')");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_created_at ON security_log(created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_event ON security_log(event)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_salary_records_deleted_at ON salary_records(deleted_at)");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status TEXT NOT NULL DEFAULT 'working'");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS hr_profile JSONB NOT NULL DEFAULT '{}'::jsonb");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS photo_data TEXT NOT NULL DEFAULT ''");
  await pool.query("CREATE TABLE IF NOT EXISTS object_responsibles (object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (object_id, employee_id))");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_object_responsibles_employee ON object_responsibles(employee_id)");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS permission_overrides JSONB NOT NULL DEFAULT '{}'::jsonb");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER NOT NULL DEFAULT 0");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(email)) WHERE email IS NOT NULL AND trim(email) <> ''");
  await pool.query("CREATE TABLE IF NOT EXISTS email_codes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_email_codes_lookup ON email_codes(lower(email), purpose, created_at DESC)");
  await pool.query("CREATE TABLE IF NOT EXISTS employee_balances (id SERIAL PRIMARY KEY, employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL, employee_fio TEXT NOT NULL, balance_date DATE NOT NULL, amount NUMERIC(14,2) NOT NULL DEFAULT 0, direction TEXT NOT NULL DEFAULT 'company_to_employee', comment TEXT NOT NULL DEFAULT '', created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("ALTER TABLE employee_balances ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'company_to_employee'");
  await pool.query("UPDATE employee_balances SET direction='employee_to_company' WHERE amount < 0 AND direction <> 'employee_to_company'");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_employee_balances_employee_date ON employee_balances(lower(employee_fio), balance_date DESC, id DESC)");
  await pool.query("CREATE TABLE IF NOT EXISTS bank_statement_payments (id SERIAL PRIMARY KEY, employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL, employee_fio TEXT NOT NULL, bank TEXT NOT NULL, company_account TEXT NOT NULL DEFAULT '', transaction_date DATE NOT NULL, amount NUMERIC(14,2) NOT NULL, document_number TEXT NOT NULL DEFAULT '', recipient_account TEXT NOT NULL DEFAULT '', counterparty TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', transaction_key TEXT NOT NULL UNIQUE, source_filename TEXT NOT NULL DEFAULT '', imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, imported_by TEXT)");
  await pool.query("ALTER TABLE bank_statement_payments ADD COLUMN IF NOT EXISTS allocations JSONB NOT NULL DEFAULT '[]'::jsonb");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_employee_date ON bank_statement_payments(lower(employee_fio), transaction_date, id)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_transaction_key ON bank_statement_payments(transaction_key)");
  await pool.query("INSERT INTO object_responsibles (object_id,employee_id) SELECT o.id,e.id FROM objects o CROSS JOIN LATERAL regexp_split_to_table(COALESCE(o.responsible,''),',') AS part(name) JOIN employees e ON lower(trim(e.fio))=lower(trim(part.name)) WHERE trim(part.name)<>'' ON CONFLICT (object_id,employee_id) DO NOTHING");
}



pool.on('error', (err) => {
  console.error('PostgreSQL error:', err);
});

// Middleware
function requestIp(req){
  return String(req.ip || req.socket && req.socket.remoteAddress || '').slice(0,120);
}
async function logSecurityEvent(req,event,success,details,userLogin){
  try{
    await pool.query(
      'INSERT INTO security_log(event,user_login,ip,user_agent,success,details) VALUES($1,$2,$3,$4,$5,$6)',
      [String(event||'').slice(0,120),String(userLogin||req.session&&req.session.user&&req.session.user.login||'').slice(0,160),requestIp(req),String(req.get&&req.get('user-agent')||'').slice(0,500),!!success,String(details||'').slice(0,1500)]
    );
  }catch(e){ console.error('Security log error:',e.message); }
}
function securityHeaders(req,res,next){
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security','max-age=31536000');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  next();
}
app.use(securityHeaders);

const extraAllowedOrigins=new Set(
  String(process.env.ALLOWED_ORIGINS || process.env.APP_ORIGIN || process.env.PUBLIC_URL || '')
    .split(',').map(x=>x.trim().replace(/\/$/,'')).filter(Boolean)
);
app.use((req,res,next)=>{
  const origin=String(req.get('origin')||'').replace(/\/$/,'');
  if(!origin)return next();
  const sameOrigin=(req.protocol+'://'+req.get('host')).replace(/\/$/,'');
  if(origin!==sameOrigin && !extraAllowedOrigins.has(origin)){
    logSecurityEvent(req,'cors_blocked',false,'Blocked origin: '+origin);
    return res.status(403).json({error:'Запрос с этого источника запрещён'});
  }
  res.setHeader('Access-Control-Allow-Origin',origin);
  res.setHeader('Vary','Origin');
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,PATCH,DELETE,OPTIONS');
  if(req.method==='OPTIONS')return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  name: 'salary.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    maxAge: 8 * 60 * 60 * 1000,
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  }
}));

function createRateLimiter(options){
  const windowMs=options.windowMs,max=options.max,event=options.event;
  const store=new Map();
  return function(req,res,next){
    const now=Date.now(),key=requestIp(req)+'|'+event;
    let item=store.get(key);
    if(!item || item.resetAt<=now)item={count:0,resetAt:now+windowMs};
    item.count++;store.set(key,item);
    if(store.size>5000){
      for(const [k,v] of store){if(v.resetAt<=now)store.delete(k);}
    }
    if(item.count>max){
      const retry=Math.max(1,Math.ceil((item.resetAt-now)/1000));
      res.setHeader('Retry-After',String(retry));
      logSecurityEvent(req,'rate_limit',false,event+'; retry_after='+retry);
      return res.status(429).json({error:'Слишком много запросов. Повторите попытку позже.'});
    }
    next();
  };
}
const authRateLimit=createRateLimiter({windowMs:15*60*1000,max:12,event:'auth'});
const mutationRateLimit=createRateLimiter({windowMs:15*60*1000,max:300,event:'api_mutation'});

app.get('/api/csrf-token',(req,res)=>{
  if(!req.session.csrfToken)req.session.csrfToken=crypto.randomBytes(32).toString('hex');
  res.setHeader('Cache-Control','no-store');
  res.json({token:req.session.csrfToken});
});
app.use('/api',(req,res,next)=>{
  if(['GET','HEAD','OPTIONS'].includes(req.method))return next();
  mutationRateLimit(req,res,()=>{
    const supplied=String(req.get('x-csrf-token')||'');
    const expected=String(req.session&&req.session.csrfToken||'');
    let ok=false;
    try{
      const a=Buffer.from(supplied),b=Buffer.from(expected);
      ok=!!supplied&&!!expected&&a.length===b.length&&crypto.timingSafeEqual(a,b);
    }catch(e){}
    if(!ok){
      logSecurityEvent(req,'csrf_rejected',false,req.method+' '+req.originalUrl);
      return res.status(403).json({error:'Недействительный защитный токен. Обновите страницу.',code:'CSRF_INVALID'});
    }
    next();
  });
});

// Static files
app.use(express.static(path.join(__dirname, 'public'),{
  etag:true,
  maxAge:'1h',
  setHeaders:(res)=>res.setHeader('X-Content-Type-Options','nosniff')
}));

// === AUTH MIDDLEWARE ===
function isTechnicalAdmin(userOrLogin){
  const login=typeof userOrLogin==='string'?userOrLogin:(userOrLogin&&userOrLogin.login);
  return String(login||'').trim().toUpperCase()==='ADMIN';
}

const PERMISSION_DEFINITIONS=[
  {key:'employees.view',group:'Сотрудники',label:'Просмотр сотрудников'},
  {key:'employees.manage',group:'Сотрудники',label:'Добавление, изменение и удаление сотрудников'},
  {key:'objects.view',group:'Объекты',label:'Просмотр объектов'},
  {key:'objects.manage',group:'Объекты',label:'Создание, изменение и удаление объектов'},
  {key:'organizations.view',group:'Организации',label:'Просмотр организации'},
  {key:'organizations.manage',group:'Организации',label:'Создание, изменение и удаление организаций',siteOnly:true},
  {key:'salary.view',group:'Зарплата',label:'Просмотр зарплаты и общего сальдо'},
  {key:'salary.create',group:'Зарплата',label:'Создание начислений'},
  {key:'salary.edit',group:'Зарплата',label:'Изменение начислений и ручных выплат'},
  {key:'salary.delete',group:'Зарплата',label:'Удаление и восстановление начислений'},
  {key:'balances.manage',group:'Выплаты и остатки',label:'Ввод и изменение начальных остатков'},
  {key:'bank.view',group:'Банк',label:'Просмотр банковских выплат'},
  {key:'bank.import',group:'Банк',label:'Импорт банковской выписки'},
  {key:'bank.allocate',group:'Банк',label:'Распределение банковских выплат по месяцам'},
  {key:'bank.delete',group:'Банк',label:'Удаление банковских выплат'},
  {key:'periods.close',group:'Периоды',label:'Закрытие зарплатного периода'},
  {key:'periods.reopen',group:'Периоды',label:'Повторное открытие периода'},
  {key:'reports.export',group:'Отчёты',label:'Экспорт доступных данных'},
  {key:'users.manage',group:'Пользователи',label:'Просмотр пользователей и назначение ролей'},
  {key:'users.customize',group:'Пользователи',label:'Индивидуальная настройка прав пользователей'},
  {key:'users.delete',group:'Пользователи',label:'Удаление аккаунтов',siteOnly:true},
  {key:'logs.view',group:'Журналы',label:'Просмотр журнала действий'},
  {key:'security.view',group:'Администрирование',label:'Журнал безопасности',siteOnly:true},
  {key:'backups.manage',group:'Администрирование',label:'Резервные копии, восстановление и полная очистка',siteOnly:true}
];
const PERMISSION_KEYS=new Set(PERMISSION_DEFINITIONS.map(x=>x.key));
const SITE_ONLY_PERMISSIONS=new Set(PERMISSION_DEFINITIONS.filter(x=>x.siteOnly).map(x=>x.key));
const ROLE_PERMISSION_DEFAULTS={
  'Руководитель сайта':Object.fromEntries(PERMISSION_DEFINITIONS.map(x=>[x.key,true])),
  'Руководитель организации':{
    'employees.view':true,'employees.manage':true,'objects.view':true,'objects.manage':true,
    'organizations.view':true,'organizations.manage':false,'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':true,
    'balances.manage':true,'bank.view':true,'bank.import':true,'bank.allocate':true,'bank.delete':true,
    'periods.close':true,'periods.reopen':true,'reports.export':true,
    'users.manage':true,'users.customize':true,'users.delete':false,'logs.view':true,'security.view':false,'backups.manage':false
  },
  'Бухгалтер':{
    'employees.view':true,'employees.manage':false,'objects.view':true,'objects.manage':false,
    'organizations.view':true,'organizations.manage':false,'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':true,
    'balances.manage':true,'bank.view':true,'bank.import':true,'bank.allocate':true,'bank.delete':true,
    'periods.close':true,'periods.reopen':false,'reports.export':true,
    'users.manage':false,'users.customize':false,'users.delete':false,'logs.view':false,'security.view':false,'backups.manage':false
  },
  'Руководитель':{
    'employees.view':true,'employees.manage':true,'objects.view':true,'objects.manage':false,
    'organizations.view':true,'organizations.manage':false,'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':false,
    'balances.manage':false,'bank.view':false,'bank.import':false,'bank.allocate':false,'bank.delete':false,
    'periods.close':false,'periods.reopen':false,'reports.export':true,
    'users.manage':false,'users.customize':false,'users.delete':false,'logs.view':false,'security.view':false,'backups.manage':false
  },
  'Руководитель проекта':{
    'employees.view':true,'employees.manage':false,'objects.view':true,'objects.manage':false,
    'organizations.view':false,'organizations.manage':false,'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':false,
    'balances.manage':false,'bank.view':false,'bank.import':false,'bank.allocate':false,'bank.delete':false,
    'periods.close':false,'periods.reopen':false,'reports.export':true,
    'users.manage':false,'users.customize':false,'users.delete':false,'logs.view':false,'security.view':false,'backups.manage':false
  }
};
function normalizePermissionOverrides(value){
  if(value&&typeof value==='object'&&!Array.isArray(value))return value;
  try{const parsed=JSON.parse(value||'{}');return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?parsed:{};}catch(e){return {};}
}
function effectivePermissions(user){
  const base={};
  PERMISSION_DEFINITIONS.forEach(x=>{base[x.key]=false;});
  const defaults=ROLE_PERMISSION_DEFAULTS[String(user&&user.role||'')]||{};
  Object.keys(defaults).forEach(k=>{if(PERMISSION_KEYS.has(k))base[k]=!!defaults[k];});
  if(isTechnicalAdmin(user))PERMISSION_DEFINITIONS.forEach(x=>{base[x.key]=true;});
  const overrides=normalizePermissionOverrides(user&&user.permission_overrides);
  Object.keys(overrides).forEach(k=>{
    if(PERMISSION_KEYS.has(k)&&typeof overrides[k]==='boolean')base[k]=overrides[k];
  });
  if(!isTechnicalAdmin(user)&&String(user&&user.role||'')!=='Руководитель сайта'){
    SITE_ONLY_PERMISSIONS.forEach(k=>{base[k]=false;});
  }
  return base;
}
function buildSessionUser(user){
  const technicalAdmin=isTechnicalAdmin(user);
  return {
    id:user.id,login:user.login,fio:user.fio,phone:user.phone,role:user.role,
    organization:user.organization||'',object_name:user.object_name||'',email:user.email||'',
    email_verified:technicalAdmin?true:(EMAIL_VERIFY_ENABLED?!!user.email_verified:true),
    email_verification_enabled:technicalAdmin?false:EMAIL_VERIFY_ENABLED,
    permission_overrides:normalizePermissionOverrides(user.permission_overrides),
    permissions:effectivePermissions(user),
    last_login_at:user.last_login_at||null,
    login_count:Number(user.login_count||0)
  };
}
async function refreshAccessUser(req){
  if(req.accessUser)return req.accessUser;
  if(!req.session||!req.session.user||!req.session.user.id)return null;
  const r=await pool.query('SELECT * FROM users WHERE id=$1',[req.session.user.id]);
  if(!r.rows.length)return null;
  req.accessUser=r.rows[0];
  req.session.user=buildSessionUser(req.accessUser);
  return req.accessUser;
}
function requirePermission(key){
  return async function(req,res,next){
    if(!req.session||!req.session.user)return res.status(401).json({error:'Не авторизован'});
    try{
      const user=await refreshAccessUser(req);
      if(!user){req.session.destroy(()=>{});return res.status(401).json({error:'Аккаунт не найден'});}
      if(EMAIL_VERIFY_ENABLED&&!isTechnicalAdmin(user)&&!user.email_verified)return res.status(403).json({error:'Сначала подтвердите электронную почту',code:'EMAIL_VERIFICATION_REQUIRED'});
      const permissions=effectivePermissions(user);
      if(!permissions[key]){
        await logSecurityEvent(req,'permission_denied',false,key,user.login);
        return res.status(403).json({error:'Недостаточно прав для этого действия',permission:key});
      }
      next();
    }catch(err){res.status(500).json({error:'Ошибка проверки прав'});}
  };
}
function isSiteWideUser(user){return isTechnicalAdmin(user)||String(user&&user.role||'')==='Руководитель сайта';}
function normAccess(value){return String(value||'').trim().toLocaleLowerCase('ru-RU');}
function sameAccessValue(a,b){return normAccess(a)===normAccess(b);}
function accessOrganization(user){return String(user&&user.organization||'').trim();}
function accessObject(user){return String(user&&user.object_name||'').trim();}
function isProjectScoped(user){return String(user&&user.role||'')==='Руководитель проекта'&&!isSiteWideUser(user);}
async function ensureOrganizationAccess(user,organization){
  if(isSiteWideUser(user))return true;
  const own=accessOrganization(user);
  if(!own||!sameAccessValue(own,organization)){const err=new Error('Нет доступа к этой организации');err.status=403;throw err;}
  return true;
}
async function ensureEmployeeAccess(user,employee){
  if(isSiteWideUser(user))return true;
  let row=null;
  if(typeof employee==='number'){
    const r=await pool.query('SELECT id,fio,organization FROM employees WHERE id=$1',[employee]);row=r.rows[0];
  }else{
    const r=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) LIMIT 1',[String(employee||'')]);row=r.rows[0];
  }
  if(!row){const err=new Error('Сотрудник не найден');err.status=404;throw err;}
  await ensureOrganizationAccess(user,row.organization);
  if(isProjectScoped(user)){
    const obj=accessObject(user);
    if(!obj){const err=new Error('Для пользователя не назначен объект');err.status=403;throw err;}
    const linked=await pool.query("SELECT 1 FROM object_responsibles r JOIN objects o ON o.id=r.object_id WHERE r.employee_id=$1 AND lower(trim(o.name))=lower(trim($2)) UNION SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim($3)) AND lower(trim(COALESCE(s.object_name,'')))=lower(trim($2)) LIMIT 1",[row.id,obj,row.fio]);
    if(!linked.rows.length){const err=new Error('Нет доступа к этому сотруднику в рамках назначенного объекта');err.status=403;throw err;}
  }
  return row;
}
async function ensureObjectAccess(user,objectValue){
  if(isSiteWideUser(user))return true;
  let row=null;
  if(Number.isInteger(Number(objectValue))&&String(objectValue).trim()!==''){
    const r=await pool.query('SELECT id,name,organization FROM objects WHERE id=$1',[Number(objectValue)]);row=r.rows[0];
  }else{
    const r=await pool.query('SELECT id,name,organization FROM objects WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[String(objectValue||'')]);row=r.rows[0];
  }
  if(!row){const err=new Error('Объект не найден');err.status=404;throw err;}
  await ensureOrganizationAccess(user,row.organization);
  if(isProjectScoped(user)&&!sameAccessValue(row.name,accessObject(user))){const err=new Error('Нет доступа к этому объекту');err.status=403;throw err;}
  return row;
}
async function salaryOrganization(employeeFio,objectName){
  const object=String(objectName||'').trim();
  if(object){
    const o=await pool.query('SELECT organization FROM objects WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[object]);
    if(o.rows.length)return String(o.rows[0].organization||'').trim();
  }
  const e=await pool.query('SELECT organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) LIMIT 1',[String(employeeFio||'')]);
  return e.rows.length?String(e.rows[0].organization||'').trim():'';
}
async function ensureEmployeeOrganizationAccess(user,fio){
  const r=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) LIMIT 1',[String(fio||'')]);
  if(!r.rows.length){const err=new Error('Сотрудник не найден');err.status=404;throw err;}
  await ensureOrganizationAccess(user,r.rows[0].organization);
  return r.rows[0];
}
async function ensureSalaryAccess(user,employeeFio,objectName){
  if(isSiteWideUser(user))return true;
  await ensureEmployeeOrganizationAccess(user,employeeFio);
  const object=String(objectName||'').trim();
  if(object)await ensureObjectAccess(user,object);
  if(isProjectScoped(user)){
    if(!object||!sameAccessValue(object,accessObject(user))){const err=new Error('Нет доступа к начислению другого объекта');err.status=403;throw err;}
  }
  return true;
}
async function ensureFinancialEmployeeAccess(user,fio){
  if(isSiteWideUser(user))return true;
  const emp=await ensureEmployeeAccess(user,String(fio||''));
  return emp;
}


function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    logSecurityEvent(req,'unauthorized_api',false,req.method+' '+req.originalUrl);
    return res.status(401).json({ error: 'Не авторизован' });
  }
  if (EMAIL_VERIFY_ENABLED && !isTechnicalAdmin(req.session.user) && !req.session.user.email_verified) return res.status(403).json({ error: 'Сначала подтвердите электронную почту', code: 'EMAIL_VERIFICATION_REQUIRED' });
  next();
}

async function requireSiteManager(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  try{
    const user=await refreshAccessUser(req);
    if(!user)return res.status(401).json({error:'Аккаунт не найден'});
    if (EMAIL_VERIFY_ENABLED && !isTechnicalAdmin(user) && !user.email_verified) return res.status(403).json({ error: 'Сначала подтвердите электронную почту', code: 'EMAIL_VERIFICATION_REQUIRED' });
    if (!isSiteWideUser(user)) {
      await logSecurityEvent(req,'forbidden_admin',false,req.method+' '+req.originalUrl,user.login);
      return res.status(403).json({ error: 'Доступ только для руководителя сайта' });
    }
    next();
  }catch(err){res.status(500).json({error:'Ошибка проверки прав'});}
}

function requireUserManager(req,res,next){return requirePermission('users.manage')(req,res,next);}

// === EMAIL SECURITY ===
function normalizeEmail(value){return String(value||'').trim().toLowerCase();}
function validEmail(value){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(value));}
function codeHash(code){return crypto.createHash('sha256').update(String(code)).digest('hex');}
function createCode(){return String(crypto.randomInt(100000,1000000));}
function mailTransport(){
  if(!process.env.SMTP_USER || !process.env.SMTP_PASSWORD) throw new Error('SMTP не настроен');
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.yandex.ru',
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || 'true').toLowerCase() !== 'false',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT || 15000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT || 15000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 30000),
    tls: { servername: process.env.SMTP_HOST || 'smtp.yandex.ru' }
  });
}
async function sendSecurityCode(userId,email,purpose){
  const normalized=normalizeEmail(email);
  const recent=await pool.query("SELECT created_at FROM email_codes WHERE lower(email)=lower($1) AND purpose=$2 ORDER BY created_at DESC LIMIT 1",[normalized,purpose]);
  if(recent.rows.length && Date.now()-new Date(recent.rows[0].created_at).getTime()<60000) throw new Error('Повторный код можно запросить через 60 секунд');
  const code=createCode();
  await pool.query("DELETE FROM email_codes WHERE user_id=$1 AND purpose=$2",[userId,purpose]);
  await pool.query("INSERT INTO email_codes(user_id,email,purpose,code_hash,expires_at) VALUES($1,$2,$3,$4,NOW()+INTERVAL '10 minutes')",[userId,normalized,purpose,codeHash(code)]);
  const subject=purpose==='verify'?'Подтверждение электронной почты':'Восстановление пароля';
  await mailTransport().sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: normalized,
    subject: subject+' — Зарплата: учёт и расчёт',
    text: 'Код подтверждения: '+code+'\n\nКод действует 10 минут. Если вы не запрашивали этот код, просто проигнорируйте письмо.'
  });
}
async function verifyMailTransport(){
  if(!EMAIL_VERIFY_ENABLED)return;
  if(!process.env.SMTP_USER || !process.env.SMTP_PASSWORD){
    console.warn('SMTP diagnostic: credentials are not configured');
    return;
  }
  const started=Date.now();
  try{
    await mailTransport().verify();
    console.log('SMTP diagnostic: connection and authentication OK in '+(Date.now()-started)+' ms');
  }catch(err){
    console.error('SMTP diagnostic failed:', {
      message: err&&err.message,
      code: err&&err.code,
      command: err&&err.command,
      responseCode: err&&err.responseCode,
      syscall: err&&err.syscall,
      address: err&&err.address,
      port: err&&err.port
    });
  }
}
async function consumeCode(userId,email,purpose,code){
  const r=await pool.query("SELECT * FROM email_codes WHERE user_id=$1 AND lower(email)=lower($2) AND purpose=$3 ORDER BY created_at DESC LIMIT 1",[userId,normalizeEmail(email),purpose]);
  if(!r.rows.length) return {ok:false,error:'Запросите новый код'};
  const row=r.rows[0];
  if(new Date(row.expires_at).getTime()<Date.now()){await pool.query("DELETE FROM email_codes WHERE id=$1",[row.id]);return {ok:false,error:'Срок действия кода истёк'};}
  if(row.attempts>=5){await pool.query("DELETE FROM email_codes WHERE id=$1",[row.id]);return {ok:false,error:'Превышено число попыток. Запросите новый код'};}
  if(row.code_hash!==codeHash(code)){await pool.query("UPDATE email_codes SET attempts=attempts+1 WHERE id=$1",[row.id]);return {ok:false,error:'Неверный код'};}
  await pool.query("DELETE FROM email_codes WHERE id=$1",[row.id]);
  return {ok:true};
}

// === AUTH ROUTES ===

// Login
app.post('/api/login', authRateLimit, async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (result.rows.length === 0) {
      await logSecurityEvent(req,'login_failed',false,'Unknown login',String(login||''));
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await logSecurityEvent(req,'login_failed',false,'Invalid password',String(login||''));
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    if (!user.role) {
      return res.status(403).json({ error: 'Роль не назначена. Обратитесь к руководителю сайта.' });
    }
    const loginUpdate=await pool.query('UPDATE users SET last_login_at=NOW(), login_count=COALESCE(login_count,0)+1 WHERE id=$1 RETURNING *',[user.id]);
    const loginUser=loginUpdate.rows[0]||user;
    req.session.user=buildSessionUser(loginUser);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [user.login, 'Вход в систему']);
    await logSecurityEvent(req,'login_success',true,'Authenticated',user.login);
    res.json(req.session.user);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
});

// Logout
app.post('/api/logout', async (req, res) => {
  const login=req.session&&req.session.user?req.session.user.login:'';
  if (login) {
    try{await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [login, 'Выход из системы']);}catch(e){}
    await logSecurityEvent(req,'logout',true,'Session ended',login);
  }
  req.session.destroy(()=>res.json({ ok: true }));
});

// Check session
app.get('/api/me', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  try{
    req.accessUser=null;
    const user=await refreshAccessUser(req);
    if(!user){req.session.destroy(()=>{});return res.status(401).json({error:'Аккаунт не найден'});}
    res.json(req.session.user);
  }catch(err){res.status(500).json({error:'Ошибка сервера'});}
});

app.post('/api/email/send-verification', authRateLimit, async (req,res)=>{
  if(!req.session.user)return res.status(401).json({error:'Не авторизован'});
  if(isTechnicalAdmin(req.session.user))return res.json({ok:true,disabled:true,message:'Для технического аккаунта ADMIN подтверждение email не требуется'});
  if(!EMAIL_VERIFY_ENABLED)return res.json({ok:true,disabled:true,message:'Подтверждение электронной почты временно отключено'});
  const email=normalizeEmail(req.body.email || req.session.user.email);
  if(!validEmail(email))return res.status(400).json({error:'Введите корректный email'});
  try{
    const used=await pool.query("SELECT id FROM users WHERE lower(email)=lower($1) AND id<>$2",[email,req.session.user.id]);
    if(used.rows.length)return res.status(400).json({error:'Этот email уже используется'});
    await pool.query("UPDATE users SET email=$1,email_verified=FALSE WHERE id=$2",[email,req.session.user.id]);
    req.session.user.email=email; req.session.user.email_verified=false;
    await sendSecurityCode(req.session.user.id,email,'verify');
    res.json({ok:true,message:'Код отправлен на электронную почту'});
  }catch(e){console.error('Send verification:',e.message);res.status(400).json({error:e.message});}
});
app.post('/api/register/verify-email', authRateLimit, async (req,res)=>{
  if(!EMAIL_VERIFY_ENABLED)return res.json({ok:true,disabled:true});
  const login=String(req.body.login||'').trim(), email=normalizeEmail(req.body.email), code=String(req.body.code||'').trim();
  try{
    const r=await pool.query("SELECT id,email FROM users WHERE lower(login)=lower($1) AND lower(email)=lower($2) LIMIT 1",[login,email]);
    if(!r.rows.length)return res.status(400).json({error:'Не удалось подтвердить email'});
    const checked=await consumeCode(r.rows[0].id,email,'verify',code);
    if(!checked.ok)return res.status(400).json({error:checked.error});
    await pool.query("UPDATE users SET email_verified=TRUE WHERE id=$1",[r.rows[0].id]);
    res.json({ok:true});
  }catch(e){console.error('Registration verify:',e.message);res.status(500).json({error:'Ошибка сервера'});}
});

app.post('/api/email/verify', authRateLimit, async (req,res)=>{
  if(!req.session.user)return res.status(401).json({error:'Не авторизован'});
  if(isTechnicalAdmin(req.session.user)){req.session.user.email_verified=true;req.session.user.email_verification_enabled=false;return res.json({ok:true,disabled:true});}
  if(!EMAIL_VERIFY_ENABLED){req.session.user.email_verified=true;return res.json({ok:true,disabled:true});}
  const email=normalizeEmail(req.session.user.email);
  const checked=await consumeCode(req.session.user.id,email,'verify',String(req.body.code||'').trim());
  if(!checked.ok)return res.status(400).json({error:checked.error});
  await pool.query("UPDATE users SET email_verified=TRUE WHERE id=$1",[req.session.user.id]);
  req.session.user.email_verified=true;
  await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1,$2)',[req.session.user.login,'Подтверждена электронная почта']);
  res.json({ok:true});
});

// Register
function normalizeRegistrationFio(fio) {
  return String(fio||'').trim().replace(/\s+/g,' ').split(' ').map(word=>word.split('-').map(part=>part?part.charAt(0).toLocaleUpperCase('ru-RU')+part.slice(1).toLocaleLowerCase('ru-RU'):'').join('-')).join(' ');
}
function buildLoginFromFio(fio) {
  const parts=normalizeRegistrationFio(fio).split(' ').filter(Boolean);
  if(!parts.length)return '';
  return parts[0]+(parts.length>1?' '+parts.slice(1,3).map(x=>x.charAt(0).toUpperCase()).join(''):'');
}
function normalizePhone(phone) {
  let d=String(phone||'').replace(/\D/g,'');
  if(d.charAt(0)==='8')d='7'+d.slice(1);
  if(d.charAt(0)!=='7')d='7'+d;
  if(d.length!==11)return '';
  return '7 ('+d.slice(1,4)+') '+d.slice(4,7)+'-'+d.slice(7,9)+'-'+d.slice(9,11);
}
app.get('/api/public/organizations', async (req,res)=>{
  try{
    const result=await pool.query("SELECT id,name FROM organizations WHERE trim(name)<>'' ORDER BY name");
    res.setHeader('Cache-Control','no-store');
    res.json(result.rows);
  }catch(err){res.status(500).json({error:'Не удалось загрузить список организаций'});}
});

app.post('/api/register', authRateLimit, async (req, res) => {
  const { fio, phone, password } = req.body;
  const email=normalizeEmail(req.body.email);
  const organizationId=Number(req.body.organization_id);
  const normalizedFio=normalizeRegistrationFio(fio);
  const login=buildLoginFromFio(normalizedFio);
  const normalizedPhone=normalizePhone(phone);
  if (!normalizedFio || !phone || !login || !password || !email || !Number.isInteger(organizationId) || organizationId<=0) return res.status(400).json({ error: 'Все поля обязательны для заполнения, включая организацию' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Введите корректный email' });
  if (normalizedFio.split(' ').filter(Boolean).length < 3) return res.status(400).json({ error: 'Введите ФИО полностью: Фамилия Имя Отчество' });
  if (!normalizedPhone) return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const orgRes=await pool.query('SELECT id,name FROM organizations WHERE id=$1',[organizationId]);
    if(!orgRes.rows.length)return res.status(400).json({error:'Выбранная организация не найдена'});
    const organization=String(orgRes.rows[0].name||'').trim();
    const existing = await pool.query('SELECT id FROM users WHERE lower(login) = lower($1) OR lower(email)=lower($2)', [login,email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Логин уже занят' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (login, password, fio, phone, email, email_verified, role, organization) VALUES ($1,$2,$3,$4,$5,FALSE,$6,$7) RETURNING id',
      [login, hash, normalizedFio, normalizedPhone, email, '', organization]
    );
    const created=await pool.query('SELECT id FROM users WHERE lower(login)=lower($1)',[login]);
    if(EMAIL_VERIFY_ENABLED){
      await sendSecurityCode(created.rows[0].id,email,'verify');
      res.json({ ok: true, login, email, organization, email_verification_required:true, message: 'Регистрация создана. Код подтверждения отправлен на email. После подтверждения руководитель вашей организации сможет назначить вам роль.' });
    }else{
      res.json({ ok: true, login, email, organization, email_verification_required:false, message: 'Регистрация создана. После назначения роли руководителем вашей организации можно войти.' });
    }
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
});

// Recover password by verified email
app.post('/api/recover/request', authRateLimit, async (req,res)=>{
  if(!EMAIL_VERIFY_ENABLED)return res.status(503).json({error:'Восстановление пароля по email временно отключено. Обратитесь к руководителю сайта.'});
  const identifier=normalizeEmail(req.body.identifier);
  try{
    const r=await pool.query("SELECT id,email FROM users WHERE lower(login)=lower($1) OR lower(email)=lower($1) LIMIT 1",[identifier]);
    if(r.rows.length && r.rows[0].email){
      try{await sendSecurityCode(r.rows[0].id,r.rows[0].email,'recover');}catch(e){if(!String(e.message).includes('60 секунд'))console.error('Recover mail:',e.message);}
    }
    res.json({ok:true,message:'Если аккаунт найден и email подтверждён, код отправлен на привязанную почту.'});
  }catch(e){res.status(500).json({error:'Ошибка сервера'});}
});
app.post('/api/recover/reset', authRateLimit, async (req,res)=>{
  const identifier=normalizeEmail(req.body.identifier), code=String(req.body.code||'').trim(), password=String(req.body.password||'');
  if(password.length<8)return res.status(400).json({error:'Новый пароль должен содержать не менее 8 символов'});
  try{
    const r=await pool.query("SELECT id,login,email,email_verified FROM users WHERE lower(login)=lower($1) OR lower(email)=lower($1) LIMIT 1",[identifier]);
    if(!r.rows.length || !r.rows[0].email || !r.rows[0].email_verified)return res.status(400).json({error:'Не удалось подтвердить запрос восстановления'});
    const user=r.rows[0], checked=await consumeCode(user.id,user.email,'recover',code);
    if(!checked.ok)return res.status(400).json({error:checked.error});
    const hash=await bcrypt.hash(password,10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2",[hash,user.id]);
    await pool.query("DELETE FROM email_codes WHERE user_id=$1",[user.id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1,$2)',[user.login,'Пароль восстановлен через email']);
    res.json({ok:true});
  }catch(e){console.error('Recover reset:',e.message);res.status(500).json({error:'Ошибка сервера'});}
});

// === USERS ===
app.get('/api/permissions/catalog', requireUserManager, async (req,res)=>{
  const actor=req.accessUser||await refreshAccessUser(req);
  res.json({
    definitions:PERMISSION_DEFINITIONS,
    role_defaults:ROLE_PERMISSION_DEFAULTS,
    actor_permissions:effectivePermissions(actor)
  });
});

app.get('/api/users', requireUserManager, async (req, res) => {
  try {
    const actor=req.accessUser||await refreshAccessUser(req);
    let result;
    const fields='id, login, fio, phone, email, email_verified, role, organization, object_name, role_history, permission_overrides, last_login_at, login_count';
    if(isSiteWideUser(actor)){
      result=await pool.query('SELECT '+fields+' FROM users ORDER BY id');
    }else{
      const ownOrg=String(actor.organization||'').trim();
      if(!ownOrg)return res.json([]);
      result=await pool.query('SELECT '+fields+' FROM users WHERE lower(trim(organization))=lower(trim($1)) ORDER BY id',[ownOrg]);
    }
    res.json(result.rows.map(u=>({...u,permissions:effectivePermissions(u)})));
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.post('/api/users/role', requireUserManager, async (req, res) => {
  const userId=Number(req.body.userId);
  const requestedRole=String(req.body.role||'').trim();
  const requestedOrg=String(req.body.organization||'').trim();
  const requestedObject=String(req.body.object_name||'').trim();
  if(!Number.isInteger(userId)||userId<=0)return res.status(400).json({error:'Некорректный пользователь'});
  const allRoles=new Set(['','Руководитель сайта','Руководитель организации','Бухгалтер','Руководитель','Руководитель проекта']);
  if(!allRoles.has(requestedRole))return res.status(400).json({error:'Некорректная роль'});
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'Пользователь не найден' });
    const user = userRes.rows[0];
    const actor=req.accessUser||await refreshAccessUser(req);
    if(isTechnicalAdmin(user))return res.status(403).json({error:'Технический аккаунт ADMIN нельзя изменять'});
    let organization=requestedOrg,role=requestedRole,objectName=requestedObject;

    if(!isSiteWideUser(actor)){
      const ownOrg=String(actor.organization||'').trim();
      if(!ownOrg)return res.status(403).json({error:'У пользователя, управляющего ролями, не указана организация'});
      if(!sameAccessValue(user.organization,ownOrg)){
        await logSecurityEvent(req,'cross_org_role_change',false,'Target user ID='+userId+'; target org='+String(user.organization||''),actor.login);
        return res.status(403).json({error:'Можно управлять только пользователями своей организации'});
      }
      if(user.role==='Руководитель сайта'||role==='Руководитель сайта')return res.status(403).json({error:'Роль руководителя сайта может назначать только руководитель сайта'});
      const actorPermissions=effectivePermissions(actor);
      const proposedPermissions=effectivePermissions({...user,role:role,permission_overrides:user.permission_overrides});
      for(const key of PERMISSION_KEYS){
        if(proposedPermissions[key]&&!actorPermissions[key])return res.status(403).json({error:'Нельзя назначить роль с правами выше ваших: '+key});
      }
      organization=ownOrg;
    }

    if(role!=='Руководитель сайта'){
      if(!organization)return res.status(400).json({error:'Для этой роли должна быть указана организация'});
      const orgCheck=await pool.query('SELECT name FROM organizations WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[organization]);
      if(!orgCheck.rows.length)return res.status(400).json({error:'Организация не найдена'});
      organization=orgCheck.rows[0].name;
    }else{
      organization='';
      objectName='';
    }

    if(objectName){
      const objCheck=await pool.query("SELECT name FROM objects WHERE lower(trim(name))=lower(trim($1)) AND ($2='' OR lower(trim(organization))=lower(trim($2))) LIMIT 1",[objectName,organization]);
      if(!objCheck.rows.length)return res.status(400).json({error:'Объект не найден в выбранной организации'});
      objectName=objCheck.rows[0].name;
    }

    let history = [];
    try { history = JSON.parse(user.role_history || '[]'); } catch(e) {}
    history.push({date:new Date().toISOString(),oldRole:user.role,newRole:role,oldOrg:user.organization,newOrg:organization,by:actor.login});
    await pool.query('UPDATE users SET role=$1, organization=$2, object_name=$3, role_history=$4 WHERE id=$5',[role,organization,objectName,JSON.stringify(history),userId]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',[actor.login,'Изменение роли пользователя ID='+userId+': '+(user.role||'без роли')+' → '+(role||'без роли')+', организация '+organization]);
    await logSecurityEvent(req,'role_changed',true,'Target user ID='+userId+'; role='+(role||'none')+'; organization='+organization,actor.login);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id/access', requirePermission('users.customize'), async (req,res)=>{
  const userId=Number(req.params.id);
  const incoming=req.body&&req.body.overrides&&typeof req.body.overrides==='object'?req.body.overrides:{};
  if(!Number.isInteger(userId)||userId<=0)return res.status(400).json({error:'Некорректный пользователь'});
  try{
    const [targetRes]=await Promise.all([pool.query('SELECT * FROM users WHERE id=$1',[userId])]);
    if(!targetRes.rows.length)return res.status(404).json({error:'Пользователь не найден'});
    const target=targetRes.rows[0],actor=req.accessUser||await refreshAccessUser(req);
    if(isTechnicalAdmin(target))return res.status(403).json({error:'Права технического аккаунта ADMIN фиксированы'});
    if(!isSiteWideUser(actor)&&!sameAccessValue(target.organization,actor.organization))return res.status(403).json({error:'Можно изменять права только пользователей своей организации'});
    const actorPermissions=effectivePermissions(actor),clean={};
    for(const [key,value] of Object.entries(incoming)){
      if(!PERMISSION_KEYS.has(key))continue;
      if(value!==true&&value!==false)continue;
      if(!isSiteWideUser(actor)&&value===true&&(!actorPermissions[key]||SITE_ONLY_PERMISSIONS.has(key))){
        return res.status(403).json({error:'Нельзя выдать право, которого нет у вас: '+key});
      }
      clean[key]=value;
    }
    if(!isSiteWideUser(actor)){
      const proposedPermissions=effectivePermissions({...target,permission_overrides:clean});
      for(const key of PERMISSION_KEYS){
        if(proposedPermissions[key]&&!actorPermissions[key])return res.status(403).json({error:'Нельзя выдать или восстановить право выше ваших: '+key});
      }
    }
    await pool.query('UPDATE users SET permission_overrides=$1::jsonb WHERE id=$2',[JSON.stringify(clean),userId]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[actor.login,'Изменены индивидуальные права пользователя '+(target.login||('ID='+userId))]);
    await logSecurityEvent(req,'permissions_changed',true,'Target user ID='+userId+'; overrides='+JSON.stringify(clean),actor.login);
    res.json({ok:true,overrides:clean});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

app.put('/api/users/:id/organization', requireSiteManager, async (req,res)=>{
  const userId=Number(req.params.id),organization=String(req.body.organization||'').trim();
  if(!Number.isInteger(userId)||userId<=0)return res.status(400).json({error:'Некорректный пользователь'});
  try{
    const targetRes=await pool.query('SELECT * FROM users WHERE id=$1',[userId]);
    if(!targetRes.rows.length)return res.status(404).json({error:'Пользователь не найден'});
    const target=targetRes.rows[0];
    if(isTechnicalAdmin(target))return res.status(403).json({error:'Организация технического аккаунта ADMIN не изменяется'});
    let canonical='';
    if(organization){
      const org=await pool.query('SELECT name FROM organizations WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[organization]);
      if(!org.rows.length)return res.status(400).json({error:'Организация не найдена'});
      canonical=org.rows[0].name;
    }else if(target.role!=='Руководитель сайта'){
      return res.status(400).json({error:'Для пользователя должна быть выбрана организация'});
    }
    let objectName=String(target.object_name||'');
    if(objectName&&canonical){
      const obj=await pool.query("SELECT 1 FROM objects WHERE lower(trim(name))=lower(trim($1)) AND lower(trim(organization))=lower(trim($2)) LIMIT 1",[objectName,canonical]);
      if(!obj.rows.length)objectName='';
    }else if(!canonical)objectName='';
    await pool.query('UPDATE users SET organization=$1, object_name=$2 WHERE id=$3',[canonical,objectName,userId]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменена организация пользователя '+target.login+': '+(target.organization||'—')+' → '+(canonical||'—')]);
    res.json({ok:true});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

app.delete('/api/users/:id', requireSiteManager, async (req,res)=>{
  const userId=Number(req.params.id);
  if(!Number.isInteger(userId)||userId<=0)return res.status(400).json({error:'Некорректный пользователь'});
  try{
    const targetRes=await pool.query('SELECT * FROM users WHERE id=$1',[userId]);
    if(!targetRes.rows.length)return res.status(404).json({error:'Пользователь не найден'});
    const target=targetRes.rows[0],actor=req.accessUser||await refreshAccessUser(req);
    if(isTechnicalAdmin(target))return res.status(403).json({error:'Технический аккаунт ADMIN удалить нельзя'});
    if(Number(actor.id)===userId)return res.status(403).json({error:'Нельзя удалить собственный аккаунт'});
    if(!isSiteWideUser(actor)){
      if(!sameAccessValue(target.organization,actor.organization))return res.status(403).json({error:'Можно удалять только пользователей своей организации'});
      if(target.role==='Руководитель сайта')return res.status(403).json({error:'Руководителя сайта может удалить только руководитель сайта'});
    }
    await pool.query('DELETE FROM users WHERE id=$1',[userId]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[actor.login,'Удалён аккаунт пользователя '+target.login+' ('+(target.fio||'')+')']);
    await logSecurityEvent(req,'user_deleted',true,'Deleted user ID='+userId+'; login='+target.login,actor.login);
    res.json({ok:true});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

// === EMPLOYEES ===
app.get('/api/employees', requirePermission('employees.view'), async (req, res) => {
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT id,fio,organization,position,phone,birth_date,comments,employment_status FROM employees ORDER BY fio');
    }else if(isProjectScoped(user)){
      result=await pool.query("SELECT DISTINCT e.id,e.fio,e.organization,e.position,e.phone,e.birth_date,e.comments,e.employment_status FROM employees e WHERE lower(trim(e.organization))=lower(trim($1)) AND (EXISTS(SELECT 1 FROM object_responsibles r JOIN objects o ON o.id=r.object_id WHERE r.employee_id=e.id AND lower(trim(o.name))=lower(trim($2))) OR EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=lower(trim($2)))) ORDER BY e.fio",[accessOrganization(user),accessObject(user)]);
    }else{
      result=await pool.query('SELECT id,fio,organization,position,phone,birth_date,comments,employment_status FROM employees WHERE lower(trim(organization))=lower(trim($1)) ORDER BY fio',[accessOrganization(user)]);
    }
    res.json(result.rows);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.get('/api/employees/:id/profile', requirePermission('employees.view'), async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный сотрудник'});
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureEmployeeAccess(user,id);
    const r=await pool.query('SELECT id,fio,organization,position,phone,birth_date,comments,employment_status,hr_profile,photo_data FROM employees WHERE id=$1',[id]);
    if(!r.rows.length)return res.status(404).json({error:'Сотрудник не найден'});
    res.setHeader('Cache-Control','no-store');
    res.json(r.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

app.put('/api/employees/:id/profile', requirePermission('employees.manage'), async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный сотрудник'});
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const employee=await ensureEmployeeAccess(user,id);
    const rawProfile=req.body&&req.body.profile;
    const profile=rawProfile&&typeof rawProfile==='object'&&!Array.isArray(rawProfile)?rawProfile:{};
    const photoData=String(req.body&&req.body.photo_data||'');
    if(photoData && !/^data:image\/(jpeg|png|webp);base64,/i.test(photoData))return res.status(400).json({error:'Фото должно быть в формате JPG, PNG или WEBP'});
    if(photoData.length>1600000)return res.status(400).json({error:'Фото слишком большое. Максимальный размер после обработки — около 1 МБ'});
    const json=JSON.stringify(profile);
    if(Buffer.byteLength(json,'utf8')>200000)return res.status(400).json({error:'Анкета слишком большая'});
    const result=await pool.query('UPDATE employees SET hr_profile=$1::jsonb,photo_data=$2 WHERE id=$3 RETURNING id,fio,organization,position,phone,birth_date,comments,employment_status,hr_profile,photo_data',[json,photoData,id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Обновлена кадровая анкета сотрудника: '+employee.fio]);
    res.json(result.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

app.post('/api/employees', requirePermission('employees.manage'), async (req, res) => {
  const { fio, organization, position, phone, birth_date, comments } = req.body;
  const employment_status=req.body.employment_status==='dismissed'?'dismissed':'working';
  if (!fio) return res.status(400).json({ error: 'ФИО обязательно' });
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    const targetOrg=isSiteWideUser(user)?String(organization||'').trim():accessOrganization(user);
    if(!targetOrg)return res.status(400).json({error:'Укажите организацию'});
    await ensureOrganizationAccess(user,targetOrg);
    const result = await pool.query(
      'INSERT INTO employees (fio, organization, position, phone, birth_date, comments, employment_status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [fio, targetOrg, position||'', normalizedPhone, birth_date||'', comments||'', employment_status]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Добавлен сотрудник: ' + fio]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.put('/api/employees/:id', requirePermission('employees.manage'), async (req, res) => {
  const { id } = req.params;
  const { fio, organization, position, phone, birth_date, comments } = req.body;
  const employment_status=req.body.employment_status==='dismissed'?'dismissed':'working';
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureEmployeeAccess(user,Number(id));
    const targetOrg=isSiteWideUser(user)?String(organization||'').trim():accessOrganization(user);
    await ensureOrganizationAccess(user,targetOrg);
    const result = await pool.query(
      'UPDATE employees SET fio=$1, organization=$2, position=$3, phone=$4, birth_date=$5, comments=$6, employment_status=$7 WHERE id=$8 RETURNING *',
      [fio, targetOrg, position||'', normalizedPhone, birth_date||'', comments||'', employment_status, id]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Изменён сотрудник: ' + fio]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.delete('/api/employees/:id', requirePermission('employees.manage'), async (req, res) => {
  const { id } = req.params;
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureEmployeeAccess(user,Number(id));
    await pool.query('DELETE FROM employees WHERE id=$1', [id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Удалён сотрудник ID=' + id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.post('/api/employees/bulk-delete', requirePermission('employees.manage'), async (req, res) => {
  const ids = Array.isArray(req.body.ids)
    ? Array.from(new Set(req.body.ids.map(Number).filter(id => Number.isInteger(id) && id > 0)))
    : [];
  if (!ids.length) return res.status(400).json({ error: 'Не выбраны сотрудники для удаления' });
  const client = await pool.connect();
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    for(const id of ids)await ensureEmployeeAccess(user,id);
    await client.query('BEGIN');
    const result = await client.query('DELETE FROM employees WHERE id = ANY($1::int[]) RETURNING id, fio', [ids]);
    await client.query(
      'INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Массовое удаление сотрудников: ' + result.rows.map(r => r.fio || ('ID=' + r.id)).join(', ')]
    );
    await client.query('COMMIT');
    res.json({ ok: true, deleted: result.rows.length, employees: result.rows });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// === OBJECTS ===
async function normalizeResponsibleIds(body){
  let ids=Array.isArray(body.responsible_ids) ? body.responsible_ids : [];
  ids=Array.from(new Set(ids.map(function(v){return Number(v);}).filter(function(v){return Number.isInteger(v)&&v>0;})));
  if(!Array.isArray(body.responsible_ids) && body.responsible){
    const names=String(body.responsible).split(',').map(function(x){return x.trim();}).filter(Boolean);
    if(names.length){
      const found=await pool.query("SELECT id FROM employees WHERE lower(fio)=ANY($1::text[])",[names.map(function(n){return n.toLowerCase();})]);
      ids=found.rows.map(function(r){return Number(r.id);});
    }
  }
  if(!ids.length)return [];
  const valid=await pool.query("SELECT id FROM employees WHERE id=ANY($1::int[])",[ids]);
  return valid.rows.map(function(r){return Number(r.id);});
}
async function getObjectWithResponsibles(id){
  const result=await pool.query("SELECT o.*,COALESCE(json_agg(json_build_object('id',e.id,'fio',e.fio) ORDER BY e.fio) FILTER (WHERE e.id IS NOT NULL),'[]'::json) AS responsibles FROM objects o LEFT JOIN object_responsibles r ON r.object_id=o.id LEFT JOIN employees e ON e.id=r.employee_id WHERE o.id=$1 GROUP BY o.id",[id]);
  return result.rows[0] || null;
}
app.get('/api/objects',requirePermission('objects.view'),async(req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    const base="SELECT o.*,COALESCE(json_agg(json_build_object('id',e.id,'fio',e.fio) ORDER BY e.fio) FILTER (WHERE e.id IS NOT NULL),'[]'::json) AS responsibles FROM objects o LEFT JOIN object_responsibles r ON r.object_id=o.id LEFT JOIN employees e ON e.id=r.employee_id";
    if(isSiteWideUser(user))result=await pool.query(base+" GROUP BY o.id ORDER BY o.name");
    else if(isProjectScoped(user))result=await pool.query(base+" WHERE lower(trim(o.organization))=lower(trim($1)) AND lower(trim(o.name))=lower(trim($2)) GROUP BY o.id ORDER BY o.name",[accessOrganization(user),accessObject(user)]);
    else result=await pool.query(base+" WHERE lower(trim(o.organization))=lower(trim($1)) GROUP BY o.id ORDER BY o.name",[accessOrganization(user)]);
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
async function saveObject(id,data,res,req){
  const name=String(data.name||'').trim();
  if(!name)return res.status(400).json({error:'Наименование обязательно'});
  const responsibleIds=await normalizeResponsibleIds(data);
  const user=req.accessUser||await refreshAccessUser(req);
  const targetOrg=isSiteWideUser(user)?String(data.organization||'').trim():accessOrganization(user);
  await ensureOrganizationAccess(user,targetOrg);
  if(responsibleIds.length&&!isSiteWideUser(user)){
    const rr=await pool.query('SELECT id,organization FROM employees WHERE id=ANY($1::int[])',[responsibleIds]);
    if(rr.rows.some(function(e){return !sameAccessValue(e.organization,targetOrg);})){
      const err=new Error('Ответственными можно назначать только сотрудников своей организации');err.status=403;throw err;
    }
  }
  if(id)await ensureObjectAccess(user,Number(id));
  if(isProjectScoped(user)&&!sameAccessValue(name,accessObject(user))){const err=new Error('Руководитель проекта может изменять только назначенный объект');err.status=403;throw err;}
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let result;
    if(id){
      result=await client.query('UPDATE objects SET name=$1,address=$2,customer=$3,organization=$4,responsible=$5 WHERE id=$6 RETURNING id',[name,data.address||'',data.customer||'',targetOrg,'',id]);
      if(!result.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Объект не найден'});}
    }else{
      result=await client.query('INSERT INTO objects (name,address,customer,organization,responsible) VALUES ($1,$2,$3,$4,$5) RETURNING id',[name,data.address||'',data.customer||'',targetOrg,'']);
      id=result.rows[0].id;
    }
    await client.query('DELETE FROM object_responsibles WHERE object_id=$1',[id]);
    if(responsibleIds.length)await client.query('INSERT INTO object_responsibles (object_id,employee_id) SELECT $1,unnest($2::int[]) ON CONFLICT DO NOTHING',[id,responsibleIds]);
    const names=responsibleIds.length ? await client.query('SELECT fio FROM employees WHERE id=ANY($1::int[]) ORDER BY fio',[responsibleIds]) : {rows:[]};
    const responsibleText=names.rows.map(function(r){return r.fio;}).join(', ');
    await client.query('UPDATE objects SET responsible=$1 WHERE id=$2',[responsibleText,id]);
    await client.query('COMMIT');
    res.json(await getObjectWithResponsibles(id));
  }catch(err){
    try{await client.query('ROLLBACK');}catch(e){}
    res.status(500).json({error:err.message});
  }finally{client.release();}
}
app.post('/api/objects',requirePermission('objects.manage'),async(req,res)=>{try{await saveObject(null,req.body||{},res,req);}catch(err){res.status(err.status||500).json({error:err.message});}});
app.put('/api/objects/:id',requirePermission('objects.manage'),async(req,res)=>{try{await saveObject(req.params.id,req.body||{},res,req);}catch(err){res.status(err.status||500).json({error:err.message});}});
app.delete('/api/objects/:id',requirePermission('objects.manage'),async(req,res)=>{
  try{const user=req.accessUser||await refreshAccessUser(req);await ensureObjectAccess(user,Number(req.params.id));await pool.query('DELETE FROM objects WHERE id=$1',[req.params.id]);res.json({ok:true});}
  catch(err){res.status(err.status||500).json({error:err.message});}
});

// === ORGANIZATIONS ===
app.get('/api/organizations', requirePermission('organizations.view'), async (req, res) => {
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    const result=isSiteWideUser(user)
      ? await pool.query('SELECT * FROM organizations ORDER BY name')
      : await pool.query('SELECT * FROM organizations WHERE lower(trim(name))=lower(trim($1)) ORDER BY name',[accessOrganization(user)]);
    res.json(result.rows);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.post('/api/organizations', requirePermission('organizations.manage'), async (req, res) => {
  const { name, address, contacts } = req.body;
  if (!name) return res.status(400).json({ error: 'Наименование обязательно' });
  try {
    const result = await pool.query(
      'INSERT INTO organizations (name, address, contacts) VALUES ($1,$2,$3) RETURNING *',
      [name, address||'', contacts||'']
    );
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Добавлена организация: '+name]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.put('/api/organizations/:id', requirePermission('organizations.manage'), async (req, res) => {
  const { name, address, contacts } = req.body;
  try {
    const result = await pool.query(
      'UPDATE organizations SET name=$1, address=$2, contacts=$3 WHERE id=$4 RETURNING *',
      [name, address||'', contacts||'', req.params.id]
    );
    if(!result.rows.length)return res.status(404).json({error:'Организация не найдена'});
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменена организация: '+name]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.delete('/api/organizations/:id', requirePermission('organizations.manage'), async (req, res) => {
  try {
    await pool.query('DELETE FROM organizations WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

async function isSalaryPeriodClosed(month,year,organization){
  if(!month||!year)return false;
  const org=String(organization||'').trim();
  const r=await pool.query("SELECT 1 FROM closed_salary_periods WHERE month=$1 AND year=$2 AND (organization='' OR ($3<>'' AND lower(trim(organization))=lower(trim($3)))) LIMIT 1",[String(month),String(year),org]);
  return r.rows.length>0;
}
async function assertSalaryPeriodOpen(month,year,organization){
  if(await isSalaryPeriodClosed(month,year,organization)){
    const err=new Error('Расчётный период '+month+' '+year+' закрыт. Сначала откройте период.');err.status=409;throw err;
  }
}
function normalizePayments(value){
  if(Array.isArray(value))return value;
  try{return JSON.parse(value||'[]');}catch(e){return [];}
}
function paymentSummary(value){
  return normalizePayments(value).reduce((s,p)=>s+(parseFloat(p&&((p.amount!=null)?p.amount:p.sum))||0),0);
}
function normalizeEmployeeMatchName(value){
  return String(value||'').trim().replace(/\s+/g,' ').toLocaleLowerCase('ru-RU').replace(/ё/g,'е');
}
function normalizeBankDate(value){
  const s=String(value||'').trim();
  if(/^\d{4}-\d{2}-\d{2}$/.test(s))return s;
  const m=s.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  return m?m[3]+'-'+m[2]+'-'+m[1]:'';
}
function normalizeBankText(value){return String(value||'').trim().replace(/\s+/g,' ');}
function bankTransactionKey(tx){
  const amount=Number(tx.amount);
  const parts=[
    normalizeBankText(tx.bank).toLocaleLowerCase('ru-RU'),
    normalizeBankText(tx.company_account),
    normalizeBankDate(tx.transaction_date),
    normalizeBankText(tx.document_number),
    Number.isFinite(amount)?amount.toFixed(2):'',
    normalizeBankText(tx.recipient_account),
    normalizeBankText(tx.counterparty).toLocaleLowerCase('ru-RU').replace(/ё/g,'е')
  ];
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}
async function prepareBankStatementTransactions(transactions,user){
  const input=Array.isArray(transactions)?transactions:[];
  const [employeesResult,bankResult,salaryResult]=await Promise.all([
    pool.query('SELECT id,fio,organization FROM employees ORDER BY id'),
    pool.query('SELECT transaction_key FROM bank_statement_payments'),
    pool.query('SELECT employee_fio,object_name,payments,paid FROM salary_records WHERE deleted_at IS NULL')
  ]);
  const employeeMap=new Map();
  let allowedEmployees=employeesResult.rows;
  if(!isSiteWideUser(user)){
    allowedEmployees=allowedEmployees.filter(e=>sameAccessValue(e.organization,accessOrganization(user)));
    if(isProjectScoped(user)){
      const projectNames=new Set(salaryResult.rows.filter(r=>sameAccessValue(r.object_name,accessObject(user))).map(r=>normalizeEmployeeMatchName(r.employee_fio)));
      allowedEmployees=allowedEmployees.filter(e=>projectNames.has(normalizeEmployeeMatchName(e.fio)));
    }
  }
  allowedEmployees.forEach(e=>{const key=normalizeEmployeeMatchName(e.fio);if(key&&!employeeMap.has(key))employeeMap.set(key,e);});
  const existingBankKeys=new Set(bankResult.rows.map(r=>String(r.transaction_key||'')));
  const manualKeys=new Set(),legacyManualAmountKeys=new Set();
  salaryResult.rows.forEach(r=>{
    const fioKey=normalizeEmployeeMatchName(r.employee_fio);
    const items=normalizePayments(r.payments);
    items.forEach(p=>{
      const date=normalizeBankDate(p&&(p.date||p.payment_date));
      const amount=Number(p&&((p.amount!=null)?p.amount:p.sum));
      if(fioKey&&date&&Number.isFinite(amount))manualKeys.add(fioKey+'|'+date+'|'+amount.toFixed(2));
    });
    if(fioKey&&!items.length){
      const legacyPaid=Number(r.paid);
      if(Number.isFinite(legacyPaid)&&legacyPaid>0)legacyManualAmountKeys.add(fioKey+'|'+legacyPaid.toFixed(2));
    }
  });
  const requestKeys=new Set();
  return input.map((raw,index)=>{
    const tx={
      bank:normalizeBankText(raw&&raw.bank),
      company_account:normalizeBankText(raw&&raw.company_account),
      transaction_date:normalizeBankDate(raw&&raw.transaction_date),
      amount:Number(raw&&raw.amount),
      document_number:normalizeBankText(raw&&raw.document_number),
      recipient_account:normalizeBankText(raw&&raw.recipient_account),
      counterparty:normalizeBankText(raw&&raw.counterparty),
      purpose:normalizeBankText(raw&&raw.purpose),
      source_filename:normalizeBankText(raw&&raw.source_filename)
    };
    const fioKey=normalizeEmployeeMatchName(tx.counterparty);
    const employee=employeeMap.get(fioKey);
    const key=bankTransactionKey(tx);
    let status='ready',message='Готово к импорту';
    if(!tx.transaction_date||!Number.isFinite(tx.amount)||tx.amount<=0||!tx.counterparty){
      status='invalid';message='Некорректная строка выписки';
    }else if(!employee){
      status='employee_not_found';message='Сотрудник не найден';
    }else if(requestKeys.has(key)){
      status='duplicate_file';message='Дубликат внутри файла';
    }else if(existingBankKeys.has(key)){
      status='duplicate_import';message='Уже импортировано';
    }else if(manualKeys.has(fioKey+'|'+tx.transaction_date+'|'+tx.amount.toFixed(2))){
      status='duplicate_manual';message='Такая выплата уже внесена вручную';
    }else if(legacyManualAmountKeys.has(fioKey+'|'+tx.amount.toFixed(2))){
      status='possible_manual';message='В базе есть ручная выплата на такую сумму без даты';
    }
    requestKeys.add(key);
    return {...tx,index,employee_id:employee?employee.id:null,employee_fio:employee?employee.fio:'',transaction_key:key,status,message};
  });
}
async function createAutomaticBackup(){
  const [employees,objects,orgs,salary,responsibles,periods,balances,bankPayments]=await Promise.all([
    pool.query('SELECT * FROM employees ORDER BY id'),pool.query('SELECT * FROM objects ORDER BY id'),
    pool.query('SELECT * FROM organizations ORDER BY id'),pool.query('SELECT * FROM salary_records ORDER BY id'),
    pool.query('SELECT object_id,employee_id,created_at FROM object_responsibles ORDER BY object_id,employee_id'),
    pool.query('SELECT * FROM closed_salary_periods ORDER BY year,month'),
    pool.query('SELECT * FROM employee_balances ORDER BY id'),
    pool.query('SELECT * FROM bank_statement_payments ORDER BY id')
  ]);
  const data={format:'salary-online-auto-backup',version:2,created_at:new Date().toISOString(),employees:employees.rows,objects:objects.rows,organizations:orgs.rows,salary:salary.rows,employee_balances:balances.rows,bank_statement_payments:bankPayments.rows,object_responsibles:responsibles.rows,closed_periods:periods.rows};
  await pool.query('INSERT INTO automatic_backups(data) VALUES($1)',[JSON.stringify(data)]);
  await pool.query('DELETE FROM automatic_backups WHERE id NOT IN (SELECT id FROM automatic_backups ORDER BY created_at DESC LIMIT 7)');
}
let backupTimer=null;
function startAutomaticBackups(){
  if(backupTimer)clearInterval(backupTimer);
  setTimeout(()=>createAutomaticBackup().catch(e=>console.error('Automatic backup error:',e.message)),15000);
  backupTimer=setInterval(()=>createAutomaticBackup().catch(e=>console.error('Automatic backup error:',e.message)),24*60*60*1000);
}

// === SALARY RECORDS ===
app.get('/api/salary', requirePermission('salary.view'), async (req, res) => {
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT * FROM salary_records WHERE deleted_at IS NULL ORDER BY employee_fio, year, month');
    }else if(isProjectScoped(user)){
      result=await pool.query("SELECT * FROM salary_records WHERE deleted_at IS NULL AND lower(trim(COALESCE(object_name,'')))=lower(trim($1)) ORDER BY employee_fio,year,month",[accessObject(user)]);
    }else{
      result=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NULL AND ((trim(COALESCE(s.object_name,''))<>'' AND EXISTS(SELECT 1 FROM objects o WHERE lower(trim(o.name))=lower(trim(s.object_name)) AND lower(trim(o.organization))=lower(trim($1)))) OR (trim(COALESCE(s.object_name,''))='' AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($1))))) ORDER BY s.employee_fio,s.year,s.month",[accessOrganization(user)]);
    }
    res.json(result.rows);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

// === BANK STATEMENT PAYMENTS ===
app.get('/api/bank-payments', requirePermission('bank.view'), async (req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT * FROM bank_statement_payments ORDER BY transaction_date,id');
    }else if(isProjectScoped(user)){
      result=await pool.query("SELECT p.* FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=lower(trim($2)))) ORDER BY p.transaction_date,p.id",[accessOrganization(user),accessObject(user)]);
    }else{
      result=await pool.query("SELECT p.* FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1))) ORDER BY p.transaction_date,p.id",[accessOrganization(user)]);
    }
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.post('/api/bank-payments/preview', requirePermission('bank.import'), async (req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const items=await prepareBankStatementTransactions(req.body&&req.body.transactions,user);
    const summary=items.reduce((acc,item)=>{acc[item.status]=(acc[item.status]||0)+1;return acc;},{});
    res.json({items,summary});
  }catch(err){console.error('Bank statement preview error:',err);res.status(500).json({error:err.message});}
});
app.post('/api/bank-payments/import', requirePermission('bank.import'), async (req,res)=>{
  const client=await pool.connect();
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const items=await prepareBankStatementTransactions(req.body&&req.body.transactions,user);
    const ready=items.filter(item=>item.status==='ready');
    let imported=0;
    await client.query('BEGIN');
    for(const item of ready){
      const result=await client.query(
        'INSERT INTO bank_statement_payments(employee_id,employee_fio,bank,company_account,transaction_date,amount,document_number,recipient_account,counterparty,purpose,transaction_key,source_filename,imported_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(transaction_key) DO NOTHING RETURNING id',
        [item.employee_id,item.employee_fio,item.bank,item.company_account,item.transaction_date,item.amount,item.document_number,item.recipient_account,item.counterparty,item.purpose,item.transaction_key,item.source_filename,req.session.user.login]
      );
      if(result.rows.length)imported++;
    }
    if(imported){
      await client.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Импортировано выплат из банковской выписки: '+imported]);
    }
    await client.query('COMMIT');
    const summary=items.reduce((acc,item)=>{acc[item.status]=(acc[item.status]||0)+1;return acc;},{});
    res.json({ok:true,imported,summary});
  }catch(err){
    try{await client.query('ROLLBACK');}catch(e){}
    console.error('Bank statement import error:',err);
    res.status(500).json({error:err.message});
  }finally{client.release();}
});
app.put('/api/bank-payments/:id/allocations', requirePermission('bank.allocate'), async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный ID банковской выплаты'});
  const monthNames=new Set(['Январь','Февраль','Март','Апрель','Май','Июнь','Июль','Август','Сентябрь','Октябрь','Ноябрь','Декабрь']);
  const raw=Array.isArray(req.body&&req.body.allocations)?req.body.allocations:[];
  const allocations=[];
  for(const item of raw){
    const month=String(item&&item.month||'').trim();
    const year=String(item&&item.year||'').trim();
    const amount=Number(item&&item.amount);
    if(!monthNames.has(month) || !/^\d{4}$/.test(year) || !(amount>0)){
      return res.status(400).json({error:'Проверьте месяц, год и сумму распределения'});
    }
    allocations.push({month,year,amount:Math.round(amount*100)/100});
  }
  try{
    const current=await pool.query('SELECT * FROM bank_statement_payments WHERE id=$1',[id]);
    if(!current.rows.length)return res.status(404).json({error:'Банковская выплата не найдена'});
    const payment=current.rows[0];
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureFinancialEmployeeAccess(user,payment.employee_fio);
    const allocated=allocations.reduce((sum,x)=>sum+x.amount,0);
    if(allocated>Number(payment.amount||0)+0.005){
      return res.status(400).json({error:'Сумма распределения превышает сумму банковской выплаты'});
    }
    const result=await pool.query('UPDATE bank_statement_payments SET allocations=$1::jsonb WHERE id=$2 RETURNING *',[JSON.stringify(allocations),id]);
    await pool.query(
      'INSERT INTO action_log(user_login,action) VALUES($1,$2)',
      [req.session.user.login,'Изменено распределение банковской выплаты ID='+id+' — '+(payment.employee_fio||'')+', распределено '+allocated.toFixed(2)+' ₽ из '+Number(payment.amount||0).toFixed(2)+' ₽']
    );
    res.json(result.rows[0]);
  }catch(err){
    console.error('Bank payment allocation error:',err);
    res.status(err.status||500).json({error:err.message});
  }
});

app.delete('/api/bank-payments/:id', requirePermission('bank.delete'), async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный ID банковской выплаты'});
  try{
    const before=await pool.query('SELECT * FROM bank_statement_payments WHERE id=$1',[id]);
    if(!before.rows.length)return res.status(404).json({error:'Банковская выплата не найдена'});
    const p=before.rows[0],user=req.accessUser||await refreshAccessUser(req);
    await ensureFinancialEmployeeAccess(user,p.employee_fio);
    await pool.query('DELETE FROM bank_statement_payments WHERE id=$1',[id]);
    await pool.query(
      'INSERT INTO action_log(user_login,action) VALUES($1,$2)',
      [req.session.user.login,'Удалена банковская выплата: '+(p.employee_fio||'')+', '+String(p.transaction_date||'').slice(0,10)+', '+Number(p.amount||0).toFixed(2)+' ₽, '+(p.bank||'')]
    );
    res.json({ok:true,payment:p});
  }catch(err){
    console.error('Bank payment delete error:',err);
    res.status(err.status||500).json({error:err.message});
  }
});

// === EMPLOYEE OPENING BALANCES ===
app.get('/api/employee-balances', requirePermission('salary.view'), async (req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT * FROM employee_balances ORDER BY employee_fio,balance_date,id');
    }else if(isProjectScoped(user)&&!effectivePermissions(user)['balances.manage']){
      result={rows:[]};
    }else if(isProjectScoped(user)){
      result=await pool.query("SELECT b.* FROM employee_balances b WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=b.employee_id AND lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=lower(trim($2)))) ORDER BY b.employee_fio,b.balance_date,b.id",[accessOrganization(user),accessObject(user)]);
    }else{
      result=await pool.query("SELECT b.* FROM employee_balances b WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=b.employee_id AND lower(trim(e.organization))=lower(trim($1))) ORDER BY b.employee_fio,b.balance_date,b.id",[accessOrganization(user)]);
    }
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.post('/api/employee-balances', requirePermission('balances.manage'), async (req,res)=>{
  const employee_fio=String(req.body.employee_fio||'').trim();
  const balance_date=String(req.body.balance_date||'').slice(0,10);
  const amount=Number(req.body.amount);
  const direction=req.body.direction==='employee_to_company'?'employee_to_company':'company_to_employee';
  const signedAmount=(direction==='employee_to_company'?-1:1)*Math.abs(amount);
  const comment=String(req.body.comment||'').trim();
  if(!employee_fio)return res.status(400).json({error:'Выберите сотрудника'});
  if(!/^\d{4}-\d{2}-\d{2}$/.test(balance_date))return res.status(400).json({error:'Укажите корректную дату остатка'});
  if(!Number.isFinite(amount))return res.status(400).json({error:'Укажите сумму остатка'});
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const accessible=await ensureFinancialEmployeeAccess(user,employee_fio);
    const emp={rows:[accessible]};
    const result=await pool.query('INSERT INTO employee_balances(employee_id,employee_fio,balance_date,amount,direction,comment,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[emp.rows[0].id,emp.rows[0].fio,balance_date,signedAmount,direction,comment,req.session.user.login]);
    const directionText=direction==='employee_to_company'?'сотрудник должен компании':'компания должна сотруднику';
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Введён остаток: '+emp.rows[0].fio+', '+balance_date+', '+Math.abs(signedAmount).toFixed(2)+' ₽ ('+directionText+')']);
    res.json(result.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.put('/api/employee-balances/:id', requirePermission('balances.manage'), async (req,res)=>{
  const employee_fio=String(req.body.employee_fio||'').trim();
  const balance_date=String(req.body.balance_date||'').slice(0,10);
  const amount=Number(req.body.amount);
  const direction=req.body.direction==='employee_to_company'?'employee_to_company':'company_to_employee';
  const signedAmount=(direction==='employee_to_company'?-1:1)*Math.abs(amount);
  const comment=String(req.body.comment||'').trim();
  if(!employee_fio)return res.status(400).json({error:'Выберите сотрудника'});
  if(!/^\d{4}-\d{2}-\d{2}$/.test(balance_date))return res.status(400).json({error:'Укажите корректную дату остатка'});
  if(!Number.isFinite(amount))return res.status(400).json({error:'Укажите сумму остатка'});
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const before=await pool.query('SELECT * FROM employee_balances WHERE id=$1',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Остаток не найден'});
    await ensureFinancialEmployeeAccess(user,before.rows[0].employee_fio);
    const accessible=await ensureFinancialEmployeeAccess(user,employee_fio);
    const emp={rows:[accessible]};
    const result=await pool.query('UPDATE employee_balances SET employee_id=$1,employee_fio=$2,balance_date=$3,amount=$4,direction=$5,comment=$6,updated_at=CURRENT_TIMESTAMP WHERE id=$7 RETURNING *',[emp.rows[0].id,emp.rows[0].fio,balance_date,signedAmount,direction,comment,req.params.id]);
    if(!result.rows.length)return res.status(404).json({error:'Остаток не найден'});
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменён остаток ID='+req.params.id+' — '+emp.rows[0].fio]);
    res.json(result.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.delete('/api/employee-balances/:id', requirePermission('balances.manage'), async (req,res)=>{
  try{
    const before=await pool.query('SELECT * FROM employee_balances WHERE id=$1',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Остаток не найден'});
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureFinancialEmployeeAccess(user,before.rows[0].employee_fio);
    await pool.query('DELETE FROM employee_balances WHERE id=$1',[req.params.id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Удалён остаток ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json({ok:true});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

app.post('/api/salary', requirePermission('salary.create'), async (req, res) => {
  const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureSalaryAccess(user,employee_fio,object_name);
    const org=await salaryOrganization(employee_fio,object_name);
    await assertSalaryPeriodOpen(month,year,org);
    const duplicate=await pool.query('SELECT id FROM salary_records WHERE deleted_at IS NULL AND lower(employee_fio)=lower($1) AND lower(COALESCE(object_name,\'\'))=lower($2) AND month=$3 AND year=$4 LIMIT 1',[employee_fio||'',object_name||'',month||'',String(year||'')]);
    if(duplicate.rows.length && !req.body.allow_duplicate)return res.status(409).json({error:'За '+month+' '+year+' уже есть начисление для '+employee_fio+(object_name?' по объекту «'+object_name+'»':'')+'.',duplicate:true});
    const result = await pool.query(
      `INSERT INTO salary_records (employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [employee_fio||'', object_name||'', month||'', year||'', charge_date||null, hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
       JSON.stringify(extra_charges||[]), JSON.stringify(payments||[]), total||0, paid||0]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Добавлено начисление: ' + employee_fio + ', ' + (month||'') + ' ' + (year||'') + ', ' + Number(total||0).toFixed(2) + ' ₽; выплачено ' + Number(paid||0).toFixed(2) + ' ₽']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.put('/api/salary/:id', requirePermission('salary.edit'), async (req, res) => {
  const { id } = req.params;
  const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    const beforeRes=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NULL',[id]);
    if(!beforeRes.rows.length)return res.status(404).json({error:'Запись не найдена'});
    const before=beforeRes.rows[0];
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureSalaryAccess(user,before.employee_fio,before.object_name);
    await ensureSalaryAccess(user,employee_fio,object_name);
    const beforeOrg=await salaryOrganization(before.employee_fio,before.object_name);
    const nextOrg=await salaryOrganization(employee_fio,object_name);
    await assertSalaryPeriodOpen(before.month,before.year,beforeOrg);
    if(before.month!==month||String(before.year)!==String(year)||!sameAccessValue(beforeOrg,nextOrg))await assertSalaryPeriodOpen(month,year,nextOrg);
    const result = await pool.query(
      `UPDATE salary_records SET employee_fio=$1, object_name=$2, month=$3, year=$4, charge_date=$5, hour_rate=$6, hours=$7, per_diem_days=$8, per_diem_rate=$9, extra_charges=$10, payments=$11, total=$12, paid=$13 WHERE id=$14 AND deleted_at IS NULL RETURNING *`,
      [employee_fio||'', object_name||'', month||'', year||'', charge_date||null, hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
       JSON.stringify(extra_charges||[]), JSON.stringify(payments||[]), total||0, paid||0, id]
    );
    const oldPaid=paymentSummary(before.payments),newPaid=paymentSummary(payments);
    let action='Изменена запись зарплаты ID='+id+' — '+(employee_fio||before.employee_fio);
    if(Math.abs(newPaid-oldPaid)>0.005)action+='; выплаты: '+oldPaid.toFixed(2)+' ₽ → '+newPaid.toFixed(2)+' ₽';
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',[req.session.user.login,action]);
    res.json(result.rows[0]);
  } catch (err) { res.status(err.status||500).json({ error: err.message }); }
});

app.delete('/api/salary/:id', requirePermission('salary.delete'), async (req, res) => {
  try {
    const before=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NULL',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Запись не найдена'});
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureSalaryAccess(user,before.rows[0].employee_fio,before.rows[0].object_name);
    const org=await salaryOrganization(before.rows[0].employee_fio,before.rows[0].object_name);
    await assertSalaryPeriodOpen(before.rows[0].month,before.rows[0].year,org);
    await pool.query('UPDATE salary_records SET deleted_at=CURRENT_TIMESTAMP,deleted_by=$1 WHERE id=$2',[req.session.user.login,req.params.id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',[req.session.user.login,'Запись зарплаты отправлена в архив ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json({ ok: true });
  } catch (err) { res.status(err.status||500).json({ error: err.message }); }
});
app.get('/api/salary-archive', requirePermission('salary.delete'), async (req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);let r;
    if(isSiteWideUser(user))r=await pool.query('SELECT * FROM salary_records WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC');
    else if(isProjectScoped(user))r=await pool.query("SELECT * FROM salary_records WHERE deleted_at IS NOT NULL AND lower(trim(COALESCE(object_name,'')))=lower(trim($1)) ORDER BY deleted_at DESC",[accessObject(user)]);
    else r=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NOT NULL AND ((trim(COALESCE(s.object_name,''))<>'' AND EXISTS(SELECT 1 FROM objects o WHERE lower(trim(o.name))=lower(trim(s.object_name)) AND lower(trim(o.organization))=lower(trim($1)))) OR (trim(COALESCE(s.object_name,''))='' AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($1))))) ORDER BY s.deleted_at DESC",[accessOrganization(user)]);
    res.json(r.rows);
  }catch(e){res.status(e.status||500).json({error:e.message});}
});
app.post('/api/salary/:id/restore', requirePermission('salary.delete'), async (req,res)=>{
  try{
    const before=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NOT NULL',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Архивная запись не найдена'});
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureSalaryAccess(user,before.rows[0].employee_fio,before.rows[0].object_name);
    const org=await salaryOrganization(before.rows[0].employee_fio,before.rows[0].object_name);
    await assertSalaryPeriodOpen(before.rows[0].month,before.rows[0].year,org);
    const r=await pool.query('UPDATE salary_records SET deleted_at=NULL,deleted_by=NULL WHERE id=$1 RETURNING *',[req.params.id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Восстановлена запись зарплаты ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json(r.rows[0]);
  }catch(e){res.status(e.status||500).json({error:e.message});}
});
app.get('/api/salary-periods', requirePermission('salary.view'), async(req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const r=isSiteWideUser(user)
      ? await pool.query("SELECT * FROM closed_salary_periods WHERE organization='' ORDER BY year DESC,closed_at DESC")
      : await pool.query("SELECT * FROM closed_salary_periods WHERE organization='' OR lower(trim(organization))=lower(trim($1)) ORDER BY year DESC,closed_at DESC",[accessOrganization(user)]);
    res.json(r.rows);
  }catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/salary-periods/toggle', requireAuth, async(req,res)=>{
  const {month,year,closed}=req.body;if(!month||!year)return res.status(400).json({error:'Укажите месяц и год'});
  try{
    const user=await refreshAccessUser(req);if(!user)return res.status(401).json({error:'Не авторизован'});
    const permissions=effectivePermissions(user),needed=closed?'periods.close':'periods.reopen';
    if(!permissions[needed])return res.status(403).json({error:'Недостаточно прав для изменения периода',permission:needed});
    const organization=isSiteWideUser(user)?'':accessOrganization(user);
    if(!isSiteWideUser(user)&&!organization)return res.status(400).json({error:'У пользователя не указана организация'});
    if(closed){
      await pool.query("INSERT INTO closed_salary_periods(month,year,organization,closed_by) VALUES($1,$2,$3,$4) ON CONFLICT(month,year,organization) DO UPDATE SET closed_at=CURRENT_TIMESTAMP,closed_by=EXCLUDED.closed_by",[month,String(year),organization,user.login]);
      await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[user.login,'Закрыт расчётный период '+month+' '+year+(organization?' · '+organization:' · все организации')]);
    }else{
      await pool.query('DELETE FROM closed_salary_periods WHERE month=$1 AND year=$2 AND organization=$3',[month,String(year),organization]);
      await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[user.login,'Открыт расчётный период '+month+' '+year+(organization?' · '+organization:' · все организации')]);
    }
    res.json({ok:true});
  }catch(e){res.status(e.status||500).json({error:e.message});}
});
app.get('/api/automatic-backups', requirePermission('backups.manage'), async(req,res)=>{
  try{const r=await pool.query("SELECT id,created_at,jsonb_array_length(COALESCE(data->'salary','[]'::jsonb)) AS salary_count FROM automatic_backups ORDER BY created_at DESC LIMIT 7");res.json(r.rows);}catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/automatic-backups/create', requirePermission('backups.manage'), async(req,res)=>{
  try{await createAutomaticBackup();await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Создана резервная копия']);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}
});

// === ACTION LOG ===
app.get('/api/log', requirePermission('logs.view'), async (req, res) => {
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    const result=isSiteWideUser(user)
      ? await pool.query('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 200')
      : await pool.query("SELECT * FROM action_log WHERE user_login IN (SELECT login FROM users WHERE lower(trim(organization))=lower(trim($1))) ORDER BY created_at DESC LIMIT 200",[accessOrganization(user)]);
    res.json(result.rows);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.get('/api/security-log', requirePermission('security.view'), async (req,res)=>{
  try{
    const result=await pool.query('SELECT id,created_at,event,user_login,ip,user_agent,success,details FROM security_log ORDER BY created_at DESC LIMIT 500');
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

// === EXPORT/IMPORT ===
app.get('/api/export', requirePermission('backups.manage'), async (req, res) => {
  try {
    const users = await pool.query('SELECT id, login, fio, phone, email, email_verified, role, organization, object_name, permission_overrides, last_login_at, login_count FROM users');
    const employees = await pool.query('SELECT * FROM employees');
    const objects = await pool.query('SELECT * FROM objects');
    const orgs = await pool.query('SELECT * FROM organizations');
    const salary = await pool.query('SELECT * FROM salary_records');
    const balances = await pool.query('SELECT * FROM employee_balances');
    const bankPayments = await pool.query('SELECT * FROM bank_statement_payments');
    const objectResponsibles = await pool.query('SELECT object_id, employee_id FROM object_responsibles');
    const log = await pool.query('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 500');
    res.json({users:users.rows, employees:employees.rows, objects:objects.rows, organizations:orgs.rows, salary:salary.rows, employee_balances:balances.rows, bank_statement_payments:bankPayments.rows, object_responsibles:objectResponsibles.rows, log:log.rows});
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.post('/api/import', requirePermission('backups.manage'), async (req, res) => {
  const data = req.body;
  try {
    if (data.employees) {
      for (const emp of data.employees) {
        await pool.query(
          'INSERT INTO employees (fio, organization, position, phone, birth_date, comments, employment_status) VALUES ($1,$2,$3,$4,$5,$6,$7)',
          [emp.fio||'', emp.organization||'', emp.position||'', emp.phone||'', emp.birth_date||'', emp.comments||'', emp.employment_status==='dismissed'?'dismissed':'working']
        );
      }
    }
    if (data.objects) {
      for (const obj of data.objects) {
        await pool.query(
          'INSERT INTO objects (name, address, customer, organization, responsible) VALUES ($1,$2,$3,$4,$5)',
          [obj.name||'', obj.address||'', obj.customer||'', obj.organization||'', obj.responsible||'']
        );
      }
    }
    if (data.organizations) {
      for (const org of data.organizations) {
        await pool.query('INSERT INTO organizations (name, address, contacts) VALUES ($1,$2,$3)',
          [org.name||'', org.address||'', org.contacts||'']);
      }
    }
    if (data.salary) {
      for (const rec of data.salary) {
        await pool.query(
          `INSERT INTO salary_records (employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [rec.employee_fio||'', rec.object_name||'', rec.month||'', rec.year||'', rec.charge_date||null, rec.hour_rate||0, rec.hours||0,
           rec.per_diem_days||0, rec.per_diem_rate||0, rec.extra_charges||'[]', rec.payments||'[]', rec.total||0, rec.paid||0]
        );
      }
    }
    if(data.employee_balances){
      for(const b of data.employee_balances){
        const emp=await pool.query('SELECT id,fio FROM employees WHERE lower(fio)=lower($1) LIMIT 1',[b.employee_fio||'']);
        const direction=b.direction==='employee_to_company'||Number(b.amount)<0?'employee_to_company':'company_to_employee';
        const signedAmount=(direction==='employee_to_company'?-1:1)*Math.abs(Number(b.amount)||0);
        await pool.query('INSERT INTO employee_balances(employee_id,employee_fio,balance_date,amount,direction,comment,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)',[emp.rows[0]?emp.rows[0].id:null,b.employee_fio||'',b.balance_date||null,signedAmount,direction,b.comment||'',b.created_by||req.session.user.login]);
      }
    }
    if(data.bank_statement_payments){
      for(const p of data.bank_statement_payments){
        const emp=await pool.query('SELECT id,fio FROM employees WHERE lower(fio)=lower($1) LIMIT 1',[p.employee_fio||'']);
        const tx={bank:p.bank,company_account:p.company_account,transaction_date:p.transaction_date,amount:p.amount,document_number:p.document_number,recipient_account:p.recipient_account,counterparty:p.counterparty||p.employee_fio,purpose:p.purpose};
        await pool.query('INSERT INTO bank_statement_payments(employee_id,employee_fio,bank,company_account,transaction_date,amount,document_number,recipient_account,counterparty,purpose,transaction_key,source_filename,imported_by,allocations) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) ON CONFLICT(transaction_key) DO NOTHING',[emp.rows[0]?emp.rows[0].id:null,p.employee_fio||'',p.bank||'',p.company_account||'',p.transaction_date||null,p.amount||0,p.document_number||'',p.recipient_account||'',p.counterparty||p.employee_fio||'',p.purpose||'',p.transaction_key||bankTransactionKey(tx),p.source_filename||'',p.imported_by||req.session.user.login,JSON.stringify(Array.isArray(p.allocations)?p.allocations:[])]);
      }
    }
    res.json({ ok: true, message: 'Импорт завершён' });
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

// === FULL BACKUP / RESTORE ===
app.get('/api/backup', requirePermission('backups.manage'), async (req, res) => {
  try {
    const [users, employees, objects, orgs, salary, balances, bankPayments, objectResponsibles, log, securityLog] = await Promise.all([
      pool.query('SELECT * FROM users ORDER BY id'),
      pool.query('SELECT * FROM employees ORDER BY id'),
      pool.query('SELECT * FROM objects ORDER BY id'),
      pool.query('SELECT * FROM organizations ORDER BY id'),
      pool.query('SELECT * FROM salary_records ORDER BY id'),
      pool.query('SELECT * FROM employee_balances ORDER BY id'),
      pool.query('SELECT * FROM bank_statement_payments ORDER BY id'),
      pool.query('SELECT object_id, employee_id, created_at FROM object_responsibles ORDER BY object_id, employee_id'),
      pool.query('SELECT * FROM action_log ORDER BY id'),
      pool.query('SELECT * FROM security_log ORDER BY id')
    ]);
    res.json({
      format: 'salary-online-backup',
      version: 2,
      created_at: new Date().toISOString(),
      users: users.rows, employees: employees.rows, objects: objects.rows,
      organizations: orgs.rows, salary: salary.rows, employee_balances: balances.rows,
      bank_statement_payments: bankPayments.rows,
      object_responsibles: objectResponsibles.rows, log: log.rows, security_log: securityLog.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/restore', requirePermission('backups.manage'), async (req, res) => {
  const data=req.body||{};
  if(data.format!=='salary-online-backup' || !Array.isArray(data.users) || !Array.isArray(data.salary)){
    return res.status(400).json({error:'Файл не является резервной копией Salary Online'});
  }
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM salary_records');
    await client.query('DELETE FROM employee_balances');
    await client.query('DELETE FROM bank_statement_payments');
    await client.query('DELETE FROM object_responsibles');
    await client.query('DELETE FROM objects');
    await client.query('DELETE FROM employees');
    await client.query('DELETE FROM organizations');
    await client.query('DELETE FROM action_log');
    await client.query('DELETE FROM security_log');
    await client.query('DELETE FROM users');

    for(const u of data.users){
      await client.query('INSERT INTO users (id,login,password,fio,phone,email,email_verified,role,organization,object_name,role_history,permission_overrides,last_login_at,login_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14)',
        [u.id,u.login||'',u.password||'',u.fio||'',u.phone||'',u.email||'',!!u.email_verified,u.role||'',u.organization||'',u.object_name||'',u.role_history||'[]',JSON.stringify(normalizePermissionOverrides(u.permission_overrides)),u.last_login_at||null,Number(u.login_count||0)]);
    }
    for(const e of (data.employees||[])){
      await client.query('INSERT INTO employees (id,fio,organization,position,phone,birth_date,comments,employment_status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [e.id,e.fio||'',e.organization||'',e.position||'',e.phone||'',e.birth_date||null,e.comments||'',e.employment_status==='dismissed'?'dismissed':'working']);
    }
    for(const o of (data.objects||[])){
      await client.query('INSERT INTO objects (id,name,address,customer,organization,responsible) VALUES ($1,$2,$3,$4,$5,$6)',
        [o.id,o.name||'',o.address||'',o.customer||'',o.organization||'',o.responsible||'']);
    }
    for(const o of (data.organizations||[])){
      await client.query('INSERT INTO organizations (id,name,address,contacts) VALUES ($1,$2,$3,$4)',
        [o.id,o.name||'',o.address||'',o.contacts||'']);
    }
    for(const r of (data.object_responsibles||[])){
      await client.query('INSERT INTO object_responsibles (object_id,employee_id,created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
        [r.object_id,r.employee_id,r.created_at||new Date()]);
    }
    for(const s of data.salary){
      await client.query('INSERT INTO salary_records (id,employee_fio,object_name,month,year,charge_date,hour_rate,hours,per_diem_days,per_diem_rate,extra_charges,payments,total,paid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
        [s.id,s.employee_fio||'',s.object_name||'',s.month||'',s.year||'',s.charge_date||null,s.hour_rate||0,s.hours||0,s.per_diem_days||0,s.per_diem_rate||0,
         typeof s.extra_charges==='string'?s.extra_charges:JSON.stringify(s.extra_charges||[]),typeof s.payments==='string'?s.payments:JSON.stringify(s.payments||[]),s.total||0,s.paid||0]);
    }
    for(const b of (data.employee_balances||[])){
      const direction=b.direction==='employee_to_company'||Number(b.amount)<0?'employee_to_company':'company_to_employee';
      const signedAmount=(direction==='employee_to_company'?-1:1)*Math.abs(Number(b.amount)||0);
      await client.query('INSERT INTO employee_balances (id,employee_id,employee_fio,balance_date,amount,direction,comment,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[b.id,b.employee_id||null,b.employee_fio||'',b.balance_date||null,signedAmount,direction,b.comment||'',b.created_by||'',b.created_at||new Date(),b.updated_at||b.created_at||new Date()]);
    }
    for(const p of (data.bank_statement_payments||[])){
      const tx={bank:p.bank,company_account:p.company_account,transaction_date:p.transaction_date,amount:p.amount,document_number:p.document_number,recipient_account:p.recipient_account,counterparty:p.counterparty||p.employee_fio,purpose:p.purpose};
      await client.query('INSERT INTO bank_statement_payments (id,employee_id,employee_fio,bank,company_account,transaction_date,amount,document_number,recipient_account,counterparty,purpose,transaction_key,source_filename,imported_at,imported_by,allocations) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)',[p.id,p.employee_id||null,p.employee_fio||'',p.bank||'',p.company_account||'',p.transaction_date||null,p.amount||0,p.document_number||'',p.recipient_account||'',p.counterparty||p.employee_fio||'',p.purpose||'',p.transaction_key||bankTransactionKey(tx),p.source_filename||'',p.imported_at||new Date(),p.imported_by||'',JSON.stringify(Array.isArray(p.allocations)?p.allocations:[])]);
    }
    for(const l of (data.log||[])){
      await client.query('INSERT INTO action_log (id,user_login,action,created_at) VALUES ($1,$2,$3,$4)',
        [l.id,l.user_login||'',l.action||'',l.created_at||new Date()]);
    }
    for(const l of (data.security_log||[])){
      await client.query('INSERT INTO security_log (id,created_at,event,user_login,ip,user_agent,success,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [l.id,l.created_at||new Date(),l.event||'',l.user_login||'',l.ip||'',l.user_agent||'',!!l.success,l.details||'']);
    }
    for(const table of ['users','employees','objects','organizations','salary_records','employee_balances','bank_statement_payments','action_log','security_log']){
      await client.query("SELECT setval(pg_get_serial_sequence('"+table+"','id'), COALESCE((SELECT MAX(id) FROM "+table+"),1), (SELECT COUNT(*)>0 FROM "+table+"))");
    }
    await client.query('COMMIT');
    res.json({ok:true,message:'Резервная копия восстановлена'});
  } catch(err) {
    try{await client.query('ROLLBACK');}catch(e){}
    res.status(500).json({error:err.message});
  } finally { client.release(); }
});

// Clear all data
app.post('/api/clear', requirePermission('backups.manage'), async (req, res) => {
  try {
    await pool.query('DELETE FROM salary_records');
    await pool.query('DELETE FROM employee_balances');
    await pool.query('DELETE FROM bank_statement_payments');
    await pool.query('DELETE FROM action_log');
    await pool.query('DELETE FROM security_log');
    await pool.query('DELETE FROM employees');
    await pool.query('DELETE FROM objects');
    await pool.query('DELETE FROM organizations');
    await pool.query('DELETE FROM users WHERE login != $1', ['ADMIN']);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize ADMIN on start
async function initAdmin() {
  try {
    const result = await pool.query('SELECT id FROM users WHERE login = $1', ['ADMIN']);
    if (result.rows.length === 0) {
      const hash = await bcrypt.hash('ADMIN', 10);
      await pool.query(
        'INSERT INTO users (login, password, fio, phone, role) VALUES ($1, $2, $3, $4, $5)',
        ['ADMIN', hash, 'Администратор', '', 'Руководитель сайта']
      );
      console.log('ADMIN created');
    }
  } catch (err) {
    console.error('Init admin error:', err.message);
  }
}

app.listen(PORT, '0.0.0.0', async () => {
  console.log('Server running on port ' + PORT);
  console.log('Email verification: ' + (EMAIL_VERIFY_ENABLED ? 'enabled' : 'disabled'));
  try { await ensureDatabaseSchema(); } catch (err) { console.error('Schema initialization error:', err.message); }
  await initAdmin();
  verifyMailTransport();
  startAutomaticBackups();
});
