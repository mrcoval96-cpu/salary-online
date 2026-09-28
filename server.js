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
// Email verification is temporarily disabled until SMTP access is restored.
// Keep this hard-disabled so an old Timeweb environment variable cannot block login.
const EMAIL_VERIFY_ENABLED = false;

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
  await pool.query("CREATE TABLE IF NOT EXISTS closed_salary_periods (month TEXT NOT NULL, year TEXT NOT NULL, closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, closed_by TEXT, PRIMARY KEY(month,year))");
  await pool.query("CREATE TABLE IF NOT EXISTS automatic_backups (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB NOT NULL)");
  await pool.query("CREATE TABLE IF NOT EXISTS security_log (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, event TEXT NOT NULL, user_login TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', success BOOLEAN NOT NULL DEFAULT FALSE, details TEXT NOT NULL DEFAULT '')");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_created_at ON security_log(created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_event ON security_log(event)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_salary_records_deleted_at ON salary_records(deleted_at)");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status TEXT NOT NULL DEFAULT 'working'");
  await pool.query("CREATE TABLE IF NOT EXISTS object_responsibles (object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (object_id, employee_id))");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_object_responsibles_employee ON object_responsibles(employee_id)");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE");
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
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    logSecurityEvent(req,'unauthorized_api',false,req.method+' '+req.originalUrl);
    return res.status(401).json({ error: 'Не авторизован' });
  }
  if (EMAIL_VERIFY_ENABLED && !req.session.user.email_verified) return res.status(403).json({ error: 'Сначала подтвердите электронную почту', code: 'EMAIL_VERIFICATION_REQUIRED' });
  next();
}

function requireSiteManager(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  if (EMAIL_VERIFY_ENABLED && !req.session.user.email_verified) return res.status(403).json({ error: 'Сначала подтвердите электронную почту', code: 'EMAIL_VERIFICATION_REQUIRED' });
  if (req.session.user.role !== 'Руководитель сайта') {
    logSecurityEvent(req,'forbidden_admin',false,req.method+' '+req.originalUrl);
    return res.status(403).json({ error: 'Доступ только для руководителя сайта' });
  }
  next();
}

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
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
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
    req.session.user = {
      id: user.id,
      login: user.login,
      fio: user.fio,
      phone: user.phone,
      role: user.role,
      organization: user.organization,
      object_name: user.object_name,
      email: user.email || '',
      email_verified: EMAIL_VERIFY_ENABLED ? !!user.email_verified : true,
      email_verification_enabled: EMAIL_VERIFY_ENABLED
    };
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
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  // While email verification is disabled, also normalize old sessions created before the switch.
  if (!EMAIL_VERIFY_ENABLED) return res.json({ ...req.session.user, email_verified: true, email_verification_enabled: false });
  res.json({ ...req.session.user, email_verification_enabled: true });
});

app.post('/api/email/send-verification', authRateLimit, async (req,res)=>{
  if(!req.session.user)return res.status(401).json({error:'Не авторизован'});
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
app.post('/api/register', authRateLimit, async (req, res) => {
  const { fio, phone, password } = req.body;
  const email=normalizeEmail(req.body.email);
  const normalizedFio=normalizeRegistrationFio(fio);
  const login=buildLoginFromFio(normalizedFio);
  const normalizedPhone=normalizePhone(phone);
  if (!normalizedFio || !phone || !login || !password || !email) return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Введите корректный email' });
  if (normalizedFio.split(' ').filter(Boolean).length < 3) return res.status(400).json({ error: 'Введите ФИО полностью: Фамилия Имя Отчество' });
  if (!normalizedPhone) return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE lower(login) = lower($1) OR lower(email)=lower($2)', [login,email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Логин уже занят' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (login, password, fio, phone, email, email_verified, role) VALUES ($1,$2,$3,$4,$5,FALSE,$6) RETURNING id',
      [login, hash, normalizedFio, normalizedPhone, email, '']
    );
    const created=await pool.query('SELECT id FROM users WHERE lower(login)=lower($1)',[login]);
    if(EMAIL_VERIFY_ENABLED){
      await sendSecurityCode(created.rows[0].id,email,'verify');
      res.json({ ok: true, login, email, email_verification_required:true, message: 'Регистрация создана. Код подтверждения отправлен на email.' });
    }else{
      res.json({ ok: true, login, email, email_verification_required:false, message: 'Регистрация создана. Подтверждение email временно отключено. После назначения роли руководителем сайта можно войти.' });
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
app.get('/api/users', requireSiteManager, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, login, fio, phone, role, organization, object_name, role_history FROM users ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/role', requireSiteManager, async (req, res) => {
  const { userId, role, organization, object_name } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'Пользователь не найден' });
    const user = userRes.rows[0];
    let history = [];
    try { history = JSON.parse(user.role_history || '[]'); } catch(e) {}
    history.push({
      date: new Date().toISOString(),
      oldRole: user.role,
      newRole: role,
      oldOrg: user.organization,
      newOrg: organization,
      by: req.session.user.login
    });
    await pool.query(
      'UPDATE users SET role = $1, organization = $2, object_name = $3, role_history = $4 WHERE id = $5',
      [role, organization || '', object_name || '', JSON.stringify(history), userId]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Изменение роли пользователя ID=' + userId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === EMPLOYEES ===
app.get('/api/employees', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM employees ORDER BY fio');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/employees', requireAuth, async (req, res) => {
  const { fio, organization, position, phone, birth_date, comments } = req.body;
  const employment_status=req.body.employment_status==='dismissed'?'dismissed':'working';
  if (!fio) return res.status(400).json({ error: 'ФИО обязательно' });
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const result = await pool.query(
      'INSERT INTO employees (fio, organization, position, phone, birth_date, comments, employment_status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [fio, organization||'', position||'', normalizedPhone, birth_date||'', comments||'', employment_status]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Добавлен сотрудник: ' + fio]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/employees/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { fio, organization, position, phone, birth_date, comments } = req.body;
  const employment_status=req.body.employment_status==='dismissed'?'dismissed':'working';
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const result = await pool.query(
      'UPDATE employees SET fio=$1, organization=$2, position=$3, phone=$4, birth_date=$5, comments=$6, employment_status=$7 WHERE id=$8 RETURNING *',
      [fio, organization||'', position||'', normalizedPhone, birth_date||'', comments||'', employment_status, id]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Изменён сотрудник: ' + fio]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/employees/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM employees WHERE id=$1', [id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Удалён сотрудник ID=' + id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/employees/bulk-delete', requireAuth, async (req, res) => {
  const ids = Array.isArray(req.body.ids)
    ? Array.from(new Set(req.body.ids.map(Number).filter(id => Number.isInteger(id) && id > 0)))
    : [];
  if (!ids.length) return res.status(400).json({ error: 'Не выбраны сотрудники для удаления' });
  const client = await pool.connect();
  try {
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
app.get('/api/objects',requireAuth,async(req,res)=>{
  try{
    const result=await pool.query("SELECT o.*,COALESCE(json_agg(json_build_object('id',e.id,'fio',e.fio) ORDER BY e.fio) FILTER (WHERE e.id IS NOT NULL),'[]'::json) AS responsibles FROM objects o LEFT JOIN object_responsibles r ON r.object_id=o.id LEFT JOIN employees e ON e.id=r.employee_id GROUP BY o.id ORDER BY o.name");
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});
async function saveObject(id,data,res){
  const name=String(data.name||'').trim();
  if(!name)return res.status(400).json({error:'Наименование обязательно'});
  const responsibleIds=await normalizeResponsibleIds(data);
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let result;
    if(id){
      result=await client.query('UPDATE objects SET name=$1,address=$2,customer=$3,organization=$4,responsible=$5 WHERE id=$6 RETURNING id',[name,data.address||'',data.customer||'',data.organization||'','',id]);
      if(!result.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Объект не найден'});}
    }else{
      result=await client.query('INSERT INTO objects (name,address,customer,organization,responsible) VALUES ($1,$2,$3,$4,$5) RETURNING id',[name,data.address||'',data.customer||'',data.organization||'','']);
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
app.post('/api/objects',requireAuth,async(req,res)=>saveObject(null,req.body||{},res));
app.put('/api/objects/:id',requireAuth,async(req,res)=>saveObject(req.params.id,req.body||{},res));
app.delete('/api/objects/:id',requireAuth,async(req,res)=>{
  try{await pool.query('DELETE FROM objects WHERE id=$1',[req.params.id]);res.json({ok:true});}
  catch(err){res.status(500).json({error:err.message});}
});

// === ORGANIZATIONS ===
app.get('/api/organizations', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM organizations ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/organizations', requireAuth, async (req, res) => {
  const { name, address, contacts } = req.body;
  if (!name) return res.status(400).json({ error: 'Наименование обязательно' });
  try {
    const result = await pool.query(
      'INSERT INTO organizations (name, address, contacts) VALUES ($1,$2,$3) RETURNING *',
      [name, address||'', contacts||'']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/organizations/:id', requireAuth, async (req, res) => {
  const { name, address, contacts } = req.body;
  try {
    const result = await pool.query(
      'UPDATE organizations SET name=$1, address=$2, contacts=$3 WHERE id=$4 RETURNING *',
      [name, address||'', contacts||'', req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/organizations/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM organizations WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function isSalaryPeriodClosed(month,year){
  if(!month||!year)return false;
  const r=await pool.query('SELECT 1 FROM closed_salary_periods WHERE month=$1 AND year=$2',[String(month),String(year)]);
  return r.rows.length>0;
}
async function assertSalaryPeriodOpen(month,year){
  if(await isSalaryPeriodClosed(month,year)){
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
async function prepareBankStatementTransactions(transactions){
  const input=Array.isArray(transactions)?transactions:[];
  const [employeesResult,bankResult,salaryResult]=await Promise.all([
    pool.query('SELECT id,fio FROM employees ORDER BY id'),
    pool.query('SELECT transaction_key FROM bank_statement_payments'),
    pool.query('SELECT employee_fio,payments,paid FROM salary_records WHERE deleted_at IS NULL')
  ]);
  const employeeMap=new Map();
  employeesResult.rows.forEach(e=>{const key=normalizeEmployeeMatchName(e.fio);if(key&&!employeeMap.has(key))employeeMap.set(key,e);});
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
app.get('/api/salary', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM salary_records WHERE deleted_at IS NULL ORDER BY employee_fio, year, month');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === BANK STATEMENT PAYMENTS ===
app.get('/api/bank-payments', requireAuth, async (req,res)=>{
  try{
    const result=await pool.query('SELECT * FROM bank_statement_payments ORDER BY transaction_date, id');
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});
app.post('/api/bank-payments/preview', requireAuth, async (req,res)=>{
  try{
    const items=await prepareBankStatementTransactions(req.body&&req.body.transactions);
    const summary=items.reduce((acc,item)=>{acc[item.status]=(acc[item.status]||0)+1;return acc;},{});
    res.json({items,summary});
  }catch(err){console.error('Bank statement preview error:',err);res.status(500).json({error:err.message});}
});
app.post('/api/bank-payments/import', requireAuth, async (req,res)=>{
  const client=await pool.connect();
  try{
    const items=await prepareBankStatementTransactions(req.body&&req.body.transactions);
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
app.put('/api/bank-payments/:id/allocations', requireAuth, async (req,res)=>{
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
    res.status(500).json({error:err.message});
  }
});

app.delete('/api/bank-payments/:id', requireAuth, async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный ID банковской выплаты'});
  try{
    const result=await pool.query('DELETE FROM bank_statement_payments WHERE id=$1 RETURNING *',[id]);
    if(!result.rows.length)return res.status(404).json({error:'Банковская выплата не найдена'});
    const p=result.rows[0];
    await pool.query(
      'INSERT INTO action_log(user_login,action) VALUES($1,$2)',
      [req.session.user.login,'Удалена банковская выплата: '+(p.employee_fio||'')+', '+String(p.transaction_date||'').slice(0,10)+', '+Number(p.amount||0).toFixed(2)+' ₽, '+(p.bank||'')]
    );
    res.json({ok:true,payment:p});
  }catch(err){
    console.error('Bank payment delete error:',err);
    res.status(500).json({error:err.message});
  }
});

// === EMPLOYEE OPENING BALANCES ===
app.get('/api/employee-balances', requireAuth, async (req,res)=>{
  try{
    const result=await pool.query('SELECT * FROM employee_balances ORDER BY employee_fio, balance_date, id');
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});
app.post('/api/employee-balances', requireAuth, async (req,res)=>{
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
    const emp=await pool.query('SELECT id,fio FROM employees WHERE lower(fio)=lower($1) LIMIT 1',[employee_fio]);
    if(!emp.rows.length)return res.status(400).json({error:'Сотрудник не найден'});
    const result=await pool.query('INSERT INTO employee_balances(employee_id,employee_fio,balance_date,amount,direction,comment,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[emp.rows[0].id,emp.rows[0].fio,balance_date,signedAmount,direction,comment,req.session.user.login]);
    const directionText=direction==='employee_to_company'?'сотрудник должен компании':'компания должна сотруднику';
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Введён остаток: '+emp.rows[0].fio+', '+balance_date+', '+Math.abs(signedAmount).toFixed(2)+' ₽ ('+directionText+')']);
    res.json(result.rows[0]);
  }catch(err){res.status(500).json({error:err.message});}
});
app.put('/api/employee-balances/:id', requireAuth, async (req,res)=>{
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
    const emp=await pool.query('SELECT id,fio FROM employees WHERE lower(fio)=lower($1) LIMIT 1',[employee_fio]);
    if(!emp.rows.length)return res.status(400).json({error:'Сотрудник не найден'});
    const result=await pool.query('UPDATE employee_balances SET employee_id=$1,employee_fio=$2,balance_date=$3,amount=$4,direction=$5,comment=$6,updated_at=CURRENT_TIMESTAMP WHERE id=$7 RETURNING *',[emp.rows[0].id,emp.rows[0].fio,balance_date,signedAmount,direction,comment,req.params.id]);
    if(!result.rows.length)return res.status(404).json({error:'Остаток не найден'});
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменён остаток ID='+req.params.id+' — '+emp.rows[0].fio]);
    res.json(result.rows[0]);
  }catch(err){res.status(500).json({error:err.message});}
});
app.delete('/api/employee-balances/:id', requireAuth, async (req,res)=>{
  try{
    const before=await pool.query('SELECT * FROM employee_balances WHERE id=$1',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Остаток не найден'});
    await pool.query('DELETE FROM employee_balances WHERE id=$1',[req.params.id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Удалён остаток ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json({ok:true});
  }catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/salary', requireAuth, async (req, res) => {
  const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    await assertSalaryPeriodOpen(month,year);
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
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/salary/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { employee_fio, object_name, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    const beforeRes=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NULL',[id]);
    if(!beforeRes.rows.length)return res.status(404).json({error:'Запись не найдена'});
    const before=beforeRes.rows[0];
    await assertSalaryPeriodOpen(before.month,before.year);
    if(before.month!==month||String(before.year)!==String(year))await assertSalaryPeriodOpen(month,year);
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

app.delete('/api/salary/:id', requireAuth, async (req, res) => {
  try {
    const before=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NULL',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Запись не найдена'});
    await assertSalaryPeriodOpen(before.rows[0].month,before.rows[0].year);
    await pool.query('UPDATE salary_records SET deleted_at=CURRENT_TIMESTAMP,deleted_by=$1 WHERE id=$2',[req.session.user.login,req.params.id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',[req.session.user.login,'Запись зарплаты отправлена в архив ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json({ ok: true });
  } catch (err) { res.status(err.status||500).json({ error: err.message }); }
});
app.get('/api/salary-archive', requireAuth, async (req,res)=>{
  try{const r=await pool.query('SELECT * FROM salary_records WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC');res.json(r.rows);}catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/salary/:id/restore', requireAuth, async (req,res)=>{
  try{
    const before=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NOT NULL',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Архивная запись не найдена'});
    await assertSalaryPeriodOpen(before.rows[0].month,before.rows[0].year);
    const r=await pool.query('UPDATE salary_records SET deleted_at=NULL,deleted_by=NULL WHERE id=$1 RETURNING *',[req.params.id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Восстановлена запись зарплаты ID='+req.params.id+' — '+before.rows[0].employee_fio]);
    res.json(r.rows[0]);
  }catch(e){res.status(e.status||500).json({error:e.message});}
});
app.get('/api/salary-periods', requireAuth, async(req,res)=>{
  try{const r=await pool.query('SELECT * FROM closed_salary_periods ORDER BY year DESC,closed_at DESC');res.json(r.rows);}catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/salary-periods/toggle', requireSiteManager, async(req,res)=>{
  const {month,year,closed}=req.body;if(!month||!year)return res.status(400).json({error:'Укажите месяц и год'});
  try{
    if(closed){
      await pool.query('INSERT INTO closed_salary_periods(month,year,closed_by) VALUES($1,$2,$3) ON CONFLICT(month,year) DO UPDATE SET closed_at=CURRENT_TIMESTAMP,closed_by=EXCLUDED.closed_by',[month,String(year),req.session.user.login]);
      await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Закрыт расчётный период '+month+' '+year]);
    }else{
      await pool.query('DELETE FROM closed_salary_periods WHERE month=$1 AND year=$2',[month,String(year)]);
      await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Открыт расчётный период '+month+' '+year]);
    }
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});
app.get('/api/automatic-backups', requireSiteManager, async(req,res)=>{
  try{const r=await pool.query("SELECT id,created_at,jsonb_array_length(COALESCE(data->'salary','[]'::jsonb)) AS salary_count FROM automatic_backups ORDER BY created_at DESC LIMIT 7");res.json(r.rows);}catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/automatic-backups/create', requireSiteManager, async(req,res)=>{
  try{await createAutomaticBackup();await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Создана резервная копия']);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}
});

// === ACTION LOG ===
app.get('/api/log', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 200');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/security-log', requireSiteManager, async (req,res)=>{
  try{
    const result=await pool.query('SELECT id,created_at,event,user_login,ip,user_agent,success,details FROM security_log ORDER BY created_at DESC LIMIT 500');
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});

// === EXPORT/IMPORT ===
app.get('/api/export', requireSiteManager, async (req, res) => {
  try {
    const users = await pool.query('SELECT id, login, fio, phone, role, organization, object_name FROM users');
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
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/import', requireSiteManager, async (req, res) => {
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
    res.status(500).json({ error: err.message });
  }
});

// === FULL BACKUP / RESTORE ===
app.get('/api/backup', requireSiteManager, async (req, res) => {
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

app.post('/api/restore', requireSiteManager, async (req, res) => {
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
      await client.query('INSERT INTO users (id,login,password,fio,phone,role,organization,object_name,role_history) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [u.id,u.login||'',u.password||'',u.fio||'',u.phone||'',u.role||'',u.organization||'',u.object_name||'',u.role_history||'[]']);
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
app.post('/api/clear', requireSiteManager, async (req, res) => {
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
    res.status(500).json({ error: err.message });
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
  startAutomaticBackups();
});
