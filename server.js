const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const compliance = require('./compliance');
const PgSessionStore = require('./pg-session-store');

dotenv.config();

const app = express();
app.set('trust proxy', 1);
app.get('/health', (req, res) => res.status(200).send('OK'));
let databaseSchemaReady = false;

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = String(process.env.SESSION_SECRET || '').trim() || crypto.randomBytes(48).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('SECURITY WARNING: SESSION_SECRET is not set. Using a random per-process secret; all sessions will be invalidated after restart. Set SESSION_SECRET in Timeweb.');
}

// Deployment retry marker.   

// Deployment retry after registry pull failure.

// Deployment trigger: refresh application after balance direction update. 
const EMAIL_VERIFY_ENABLED = String(process.env.EMAIL_VERIFY_ENABLED || 'true').trim().toLowerCase() !== 'false';

// PostgreSQL pool
const fs = require('fs');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');

function databaseConnectionOptions(){
  const dbUrl=new URL(process.env.DATABASE_URL);
  const hosted=!['localhost','127.0.0.1','::1'].includes(dbUrl.hostname);
  const explicitMode=String(process.env.DB_SSL || 'auto').trim().toLowerCase();
  const allowPlaintext=String(process.env.DB_ALLOW_PLAINTEXT || '').trim().toLowerCase()==='true';
  const sslMode=String(dbUrl.searchParams.get('sslmode') || '').trim().toLowerCase();
  const urlRequestsTls=['require','verify-ca','verify-full'].includes(sslMode);
  const knownTlsHost=/timeweb|twc1\.net/i.test(dbUrl.hostname);
  const useTls=explicitMode==='true' || explicitMode==='require' || explicitMode==='verify-full' ||
    (explicitMode==='auto' && (urlRequestsTls || knownTlsHost));
  if(explicitMode==='false' || explicitMode==='disable'){
    if(hosted && !allowPlaintext)throw new Error('Refusing unencrypted connection to hosted PostgreSQL. Set DB_SSL=true, use sslmode=require, or explicitly set DB_ALLOW_PLAINTEXT=true for a trusted private network.');
    return {hosted:hosted,pool:{}};
  }
  if(useTls){
    const rejectUnauthorized=explicitMode==='verify-full' ||
      String(process.env.DB_SSL_REJECT_UNAUTHORIZED || '').trim().toLowerCase()==='true' ||
      sslMode==='verify-full';
    return {hosted:hosted,pool:{ssl:{rejectUnauthorized:rejectUnauthorized}}};
  }
  if(hosted && !allowPlaintext){
    throw new Error('Refusing unencrypted connection to hosted PostgreSQL. Set DB_SSL=true or add sslmode=require to DATABASE_URL. DB_ALLOW_PLAINTEXT=true is allowed only for a trusted private network.');
  }
  return {hosted:hosted,pool:{}};
}

const dbConnection=databaseConnectionOptions();
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ...dbConnection.pool
});
console.log('Database transport:',dbConnection.pool.ssl?'TLS enabled':(dbConnection.hosted?'plaintext explicitly allowed':'local connection'));

app.get('/ready', async (req,res)=>{
  if(!databaseSchemaReady)return res.status(503).json({ok:false});
  try{
    await pool.query('SELECT 1');
    res.status(200).json({ok:true});
  }catch(e){
    res.status(503).json({ok:false});
  }
});


async function ensureDatabaseSchema(){
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_by TEXT");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT ''");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_salary_records_organization ON salary_records(lower(trim(organization)))");
  await pool.query("CREATE TABLE IF NOT EXISTS closed_salary_periods (month TEXT NOT NULL, year TEXT NOT NULL, organization TEXT NOT NULL DEFAULT '', closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, closed_by TEXT)");
  await pool.query("ALTER TABLE closed_salary_periods ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE closed_salary_periods DROP CONSTRAINT IF EXISTS closed_salary_periods_pkey");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_closed_salary_periods_scope ON closed_salary_periods(month,year,organization)");
  await pool.query("CREATE TABLE IF NOT EXISTS automatic_backups (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB NOT NULL)");
  await pool.query("CREATE TABLE IF NOT EXISTS security_log (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, event TEXT NOT NULL, user_login TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', success BOOLEAN NOT NULL DEFAULT FALSE, details TEXT NOT NULL DEFAULT '')");
  await pool.query("CREATE TABLE IF NOT EXISTS app_sessions (sid TEXT PRIMARY KEY, sess JSONB NOT NULL, expire TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_app_sessions_expire ON app_sessions(expire)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_created_at ON security_log(created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_security_log_event ON security_log(event)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_salary_records_deleted_at ON salary_records(deleted_at)");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status TEXT NOT NULL DEFAULT 'working'");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS hr_profile JSONB NOT NULL DEFAULT '{}'::jsonb");
  await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS photo_data TEXT NOT NULL DEFAULT ''");
  await pool.query("CREATE TABLE IF NOT EXISTS object_responsibles (object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (object_id, employee_id))");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_object_responsibles_employee ON object_responsibles(employee_id)");
  await pool.query("CREATE TABLE IF NOT EXISTS object_user_responsibles (object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (object_id, user_id))");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_object_user_responsibles_user ON object_user_responsibles(user_id)");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS permission_overrides JSONB NOT NULL DEFAULT '{}'::jsonb");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER NOT NULL DEFAULT 0");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(email)) WHERE email IS NOT NULL AND trim(email) <> ''");
  await pool.query("CREATE TABLE IF NOT EXISTS email_codes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_email_codes_lookup ON email_codes(lower(email), purpose, created_at DESC)");
  await pool.query(`CREATE TABLE IF NOT EXISTS registration_invites(
    id BIGSERIAL PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_registration_invites_org ON registration_invites(organization_id,expires_at DESC)");
  await pool.query(`CREATE TABLE IF NOT EXISTS privacy_tombstones(
    id BIGSERIAL PRIMARY KEY,
    identifier_hash TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    tenant_scope TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP
  )`);
  await pool.query("ALTER TABLE privacy_tombstones ADD COLUMN IF NOT EXISTS tenant_scope TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE privacy_tombstones ADD COLUMN IF NOT EXISTS released_at TIMESTAMP");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_privacy_tombstones_unique ON privacy_tombstones(identifier_hash,identifier_type,tenant_scope)");
  await pool.query("CREATE TABLE IF NOT EXISTS employee_balances (id SERIAL PRIMARY KEY, employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL, employee_fio TEXT NOT NULL, balance_date DATE NOT NULL, amount NUMERIC(14,2) NOT NULL DEFAULT 0, direction TEXT NOT NULL DEFAULT 'company_to_employee', comment TEXT NOT NULL DEFAULT '', created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("ALTER TABLE employee_balances ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'company_to_employee'");
  await pool.query("UPDATE employee_balances SET direction='employee_to_company' WHERE amount < 0 AND direction <> 'employee_to_company'");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_employee_balances_employee_date ON employee_balances(lower(employee_fio), balance_date DESC, id DESC)");
  await pool.query("CREATE TABLE IF NOT EXISTS bank_statement_payments (id SERIAL PRIMARY KEY, employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL, employee_fio TEXT NOT NULL, bank TEXT NOT NULL, company_account TEXT NOT NULL DEFAULT '', transaction_date DATE NOT NULL, amount NUMERIC(14,2) NOT NULL, document_number TEXT NOT NULL DEFAULT '', recipient_account TEXT NOT NULL DEFAULT '', counterparty TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', transaction_key TEXT NOT NULL UNIQUE, source_filename TEXT NOT NULL DEFAULT '', imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, imported_by TEXT)");
  await pool.query("ALTER TABLE bank_statement_payments ADD COLUMN IF NOT EXISTS allocations JSONB NOT NULL DEFAULT '[]'::jsonb");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_employee_date ON bank_statement_payments(lower(employee_fio), transaction_date, id)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_bank_statement_payments_transaction_key ON bank_statement_payments(transaction_key)");
  await pool.query(`CREATE TABLE IF NOT EXISTS deals(
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    organization TEXT NOT NULL DEFAULT '',
    deal_no TEXT NOT NULL DEFAULT '',
    customer TEXT NOT NULL DEFAULT '',
    contract_description TEXT NOT NULL DEFAULT '',
    contract_amount NUMERIC(16,2) NOT NULL DEFAULT 0,
    customer_invoices JSONB NOT NULL DEFAULT '[]'::jsonb,
    customer_payments JSONB NOT NULL DEFAULT '[]'::jsonb,
    supplier_entries JSONB NOT NULL DEFAULT '[]'::jsonb,
    additional_expenses JSONB NOT NULL DEFAULT '[]'::jsonb,
    comments TEXT NOT NULL DEFAULT '',
    obligation_salary NUMERIC(16,2) NOT NULL DEFAULT 0,
    obligation_returns NUMERIC(16,2) NOT NULL DEFAULT 0,
    obligation_transit NUMERIC(16,2) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'quiet',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await pool.query("CREATE INDEX IF NOT EXISTS idx_deals_organization ON deals(lower(trim(organization)),id)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_deals_tenant ON deals(tenant_id,id)");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS inn TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS kpp TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ogrn TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS legal_address TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS postal_address TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS director_fio TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS website TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS bank_name TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS bik TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS settlement_account TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS correspondent_account TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE organizations ALTER COLUMN address TYPE TEXT");
  await pool.query("ALTER TABLE organizations ALTER COLUMN contacts TYPE TEXT");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_organizations_inn ON organizations(inn) WHERE trim(inn)<>''");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_organizations_ogrn ON organizations(ogrn) WHERE trim(ogrn)<>''");
  await pool.query("CREATE TABLE IF NOT EXISTS organization_aliases (alias TEXT PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
  await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_aliases_norm ON organization_aliases(lower(trim(alias)))");
  await pool.query("INSERT INTO object_responsibles (object_id,employee_id) SELECT o.id,e.id FROM objects o CROSS JOIN LATERAL regexp_split_to_table(COALESCE(o.responsible,''),',') AS part(name) JOIN employees e ON lower(trim(e.fio))=lower(trim(part.name)) WHERE trim(part.name)<>'' ON CONFLICT (object_id,employee_id) DO NOTHING");
  await pool.query("INSERT INTO object_user_responsibles(object_id,user_id) SELECT DISTINCT r.object_id,u.id FROM object_responsibles r JOIN objects o ON o.id=r.object_id JOIN employees e ON e.id=r.employee_id JOIN users u ON lower(trim(u.fio))=lower(trim(e.fio)) AND lower(trim(u.organization))=lower(trim(o.organization)) WHERE trim(COALESCE(o.organization,''))<>'' ON CONFLICT(object_id,user_id) DO NOTHING");
  await pool.query("INSERT INTO object_user_responsibles(object_id,user_id) SELECT DISTINCT o.id,u.id FROM objects o CROSS JOIN LATERAL regexp_split_to_table(COALESCE(o.responsible,''),',') AS part(name) JOIN users u ON lower(trim(u.fio))=lower(trim(part.name)) AND lower(trim(u.organization))=lower(trim(o.organization)) WHERE trim(part.name)<>'' AND trim(COALESCE(o.organization,''))<>'' ON CONFLICT(object_id,user_id) DO NOTHING");
  await pool.query("INSERT INTO object_user_responsibles(object_id,user_id) SELECT DISTINCT o.id,u.id FROM users u JOIN objects o ON lower(trim(o.name))=lower(trim(u.object_name)) AND lower(trim(o.organization))=lower(trim(u.organization)) WHERE u.role='Руководитель проекта' AND trim(COALESCE(u.object_name,''))<>'' ON CONFLICT(object_id,user_id) DO NOTHING");
  await repairOrganizationReferences();
}


async function repairOrganizationReferences(){
  const orgResult=await pool.query("SELECT id,name FROM organizations WHERE trim(name)<>'' ORDER BY id");
  if(!orgResult.rows.length)return;
  const canonical=new Map(orgResult.rows.map(o=>[normAccess(o.name),o]));
  const discovered=new Map();
  function rememberAlias(oldValue,newValue){
    const oldKey=normAccess(oldValue),newKey=normAccess(newValue);
    if(!oldKey||!newKey||oldKey===newKey||!canonical.has(newKey))return;
    const current=discovered.get(oldKey);
    if(current&&current!==newKey){discovered.set(oldKey,'');return;}
    if(current!=='')discovered.set(oldKey,newKey);
  }
  try{
    const histories=await pool.query("SELECT role_history FROM users WHERE role_history IS NOT NULL AND trim(role_history)<>''");
    for(const row of histories.rows){
      let history=[];try{history=Array.isArray(row.role_history)?row.role_history:JSON.parse(row.role_history||'[]');}catch(e){}
      for(const item of history)rememberAlias(item&&item.oldOrg,item&&item.newOrg);
    }
    const logs=await pool.query("SELECT action FROM action_log WHERE action LIKE 'Изменена организация пользователя %→%' ORDER BY id");
    for(const row of logs.rows){
      const m=String(row.action||'').match(/:\s*(.*?)\s*→\s*(.*?)\s*$/);
      if(m)rememberAlias(m[1],m[2]);
    }
    for(const [oldKey,newKey] of discovered){
      if(!newKey)continue;
      const oldSample=oldKey, target=canonical.get(newKey);
      await pool.query("INSERT INTO organization_aliases(alias,organization_id) VALUES($1,$2) ON CONFLICT(alias) DO UPDATE SET organization_id=EXCLUDED.organization_id",[oldSample,target.id]);
    }
  }catch(e){console.warn('Organization alias discovery:',e.message);}

  for(const table of ['users','employees','objects','salary_records']){
    await pool.query("UPDATE "+table+" t SET organization=o.name FROM organizations o WHERE trim(COALESCE(t.organization,''))<>'' AND lower(trim(t.organization))=lower(trim(o.name)) AND t.organization<>o.name");
    await pool.query("UPDATE "+table+" t SET organization=o.name FROM organization_aliases a JOIN organizations o ON o.id=a.organization_id WHERE lower(trim(COALESCE(t.organization,'')))=lower(trim(a.alias)) AND t.organization<>o.name");
  }
  await pool.query(`
    INSERT INTO closed_salary_periods(month,year,organization,closed_at,closed_by)
    SELECT p.month,p.year,o.name,p.closed_at,p.closed_by
    FROM closed_salary_periods p JOIN organizations o ON lower(trim(p.organization))=lower(trim(o.name))
    WHERE p.organization<>o.name
    ON CONFLICT(month,year,organization) DO UPDATE SET closed_at=GREATEST(closed_salary_periods.closed_at,EXCLUDED.closed_at),closed_by=EXCLUDED.closed_by
  `);
  await pool.query("DELETE FROM closed_salary_periods p USING organizations o WHERE lower(trim(p.organization))=lower(trim(o.name)) AND p.organization<>o.name");
  await pool.query(`
    INSERT INTO closed_salary_periods(month,year,organization,closed_at,closed_by)
    SELECT p.month,p.year,o.name,p.closed_at,p.closed_by
    FROM closed_salary_periods p
    JOIN organization_aliases a ON lower(trim(p.organization))=lower(trim(a.alias))
    JOIN organizations o ON o.id=a.organization_id
    WHERE p.organization<>o.name
    ON CONFLICT(month,year,organization) DO UPDATE SET closed_at=GREATEST(closed_salary_periods.closed_at,EXCLUDED.closed_at),closed_by=EXCLUDED.closed_by
  `);
  await pool.query("DELETE FROM closed_salary_periods p USING organization_aliases a,organizations o WHERE o.id=a.organization_id AND lower(trim(p.organization))=lower(trim(a.alias)) AND p.organization<>o.name");

  // Recover orphan objects from responsible employees when they all belong to one organization.
  await pool.query(`
    WITH inferred AS (
      SELECT r.object_id, MIN(e.organization) AS organization
      FROM object_responsibles r
      JOIN employees e ON e.id=r.employee_id
      JOIN organizations og ON lower(trim(og.name))=lower(trim(e.organization))
      GROUP BY r.object_id
      HAVING COUNT(DISTINCT lower(trim(e.organization)))=1
    )
    UPDATE objects o SET organization=i.organization
    FROM inferred i
    WHERE o.id=i.object_id
      AND (trim(COALESCE(o.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(o.organization))))
  `);

  // Recover orphan objects from salary records whose employees point to one organization.
  await pool.query(`
    WITH inferred AS (
      SELECT lower(trim(s.object_name)) AS object_key, MIN(e.organization) AS organization
      FROM salary_records s
      JOIN employees e ON lower(trim(e.fio))=lower(trim(s.employee_fio))
      JOIN organizations og ON lower(trim(og.name))=lower(trim(e.organization))
      WHERE trim(COALESCE(s.object_name,''))<>''
      GROUP BY lower(trim(s.object_name))
      HAVING COUNT(DISTINCT lower(trim(e.organization)))=1
    )
    UPDATE objects o SET organization=i.organization
    FROM inferred i
    WHERE lower(trim(o.name))=i.object_key
      AND (trim(COALESCE(o.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(o.organization))))
  `);

  // Legacy registered users can inherit organization from a uniquely matched employee profile.
  await pool.query(`
    WITH employee_org AS (
      SELECT lower(trim(fio)) AS fio_key, MIN(organization) AS organization
      FROM employees
      WHERE trim(COALESCE(organization,''))<>''
        AND EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(employees.organization)))
      GROUP BY lower(trim(fio))
      HAVING COUNT(DISTINCT lower(trim(organization)))=1
    )
    UPDATE users u SET organization=e.organization
    FROM employee_org e
    WHERE lower(trim(u.fio))=e.fio_key
      AND upper(trim(u.login))<>'ADMIN'
      AND u.role<>'Руководитель сайта'
      AND (trim(COALESCE(u.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(u.organization))))
  `);

  // Users with an assigned object inherit the object's organization when their old organization is orphaned.
  await pool.query(`
    WITH object_org AS (
      SELECT lower(trim(name)) AS object_key, MIN(organization) AS organization
      FROM objects
      WHERE trim(COALESCE(organization,''))<>''
        AND EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(objects.organization)))
      GROUP BY lower(trim(name))
      HAVING COUNT(DISTINCT lower(trim(organization)))=1
    )
    UPDATE users u SET organization=o.organization
    FROM object_org o
    WHERE trim(COALESCE(u.object_name,''))<>''
      AND lower(trim(u.object_name))=o.object_key
      AND (trim(COALESCE(u.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(u.organization))))
  `);

  // If the installation has one organization, orphaned legacy records can be assigned safely.
  if(orgResult.rows.length===1){
    const onlyOrg=orgResult.rows[0].name;
    await pool.query("UPDATE users u SET organization=$1 WHERE upper(trim(login))<>'ADMIN' AND role<>'Руководитель сайта' AND (trim(COALESCE(organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(u.organization))))",[onlyOrg]);
    await pool.query("UPDATE employees e SET organization=$1 WHERE trim(COALESCE(organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(e.organization)))",[onlyOrg]);
    await pool.query("UPDATE objects o SET organization=$1 WHERE trim(COALESCE(organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(o.organization)))",[onlyOrg]);
  }

  // Salary rows belong to the employee's organization; object is only an additional dimension.
  await pool.query(`
    WITH employee_org AS (
      SELECT lower(trim(fio)) AS fio_key, MIN(organization) AS organization
      FROM employees
      WHERE trim(COALESCE(organization,''))<>''
        AND EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(employees.organization)))
      GROUP BY lower(trim(fio))
      HAVING COUNT(DISTINCT lower(trim(organization)))=1
    )
    UPDATE salary_records s SET organization=e.organization
    FROM employee_org e
    WHERE lower(trim(s.employee_fio))=e.fio_key
      AND (trim(COALESCE(s.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations x WHERE lower(trim(x.name))=lower(trim(s.organization))))
  `);
  await pool.query(`
    WITH object_org AS (
      SELECT lower(trim(name)) AS object_key, MIN(organization) AS organization
      FROM objects
      WHERE trim(COALESCE(organization,''))<>''
      GROUP BY lower(trim(name))
      HAVING COUNT(DISTINCT lower(trim(organization)))=1
    )
    UPDATE salary_records s SET organization=o.organization
    FROM object_org o
    WHERE trim(COALESCE(s.object_name,''))<>''
      AND lower(trim(s.object_name))=o.object_key
      AND trim(COALESCE(s.organization,''))=''
  `);
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
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
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
  store: new PgSessionStore(pool),
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
app.use(compliance.correlationMiddleware);
app.use('/api',compliance.auditMutationMiddleware(pool));

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

// Browser libraries are served from the application package itself so user browsers do not
// contact third-party CDNs while working with personal data.
const localVendorFiles={
  '/vendor/xlsx.full.min.js':path.join(__dirname,'node_modules','xlsx','dist','xlsx.full.min.js'),
  '/vendor/html2canvas.min.js':path.join(__dirname,'node_modules','html2canvas','dist','html2canvas.min.js'),
  '/vendor/jspdf.umd.min.js':path.join(__dirname,'node_modules','jspdf','dist','jspdf.umd.min.js')
};
for(const [route,file] of Object.entries(localVendorFiles)){
  app.get(route,(req,res)=>res.sendFile(file,err=>{if(err&&!res.headersSent)res.status(404).end();}));
}

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
  {key:'accounting.view',group:'Разделы сайта',label:'Доступ к разделу «Бухгалтерия»'},
  {key:'deals.view',group:'Разделы сайта',label:'Доступ к разделу «Сделки»'},
  {key:'deals.manage',group:'Разделы сайта',label:'Создание, изменение, удаление и импорт сделок'},
  {key:'warehouse.view',group:'Разделы сайта',label:'Доступ к разделу «Склад»'},
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
  {key:'compliance.view',group:'152-ФЗ / Compliance',label:'Просмотр согласий, DSAR, аудита и реестров'},
  {key:'compliance.manage',group:'152-ФЗ / Compliance',label:'Обработка DSAR и ведение compliance-реестров'},
  {key:'incidents.manage',group:'152-ФЗ / Compliance',label:'Регистрация и расследование инцидентов'},
  {key:'legal.manage',group:'152-ФЗ / Compliance',label:'Публикация версий юридических документов',siteOnly:true},
  {key:'backups.manage',group:'Администрирование',label:'Резервные копии, восстановление и полная очистка',siteOnly:true}
];
const PERMISSION_KEYS=new Set(PERMISSION_DEFINITIONS.map(x=>x.key));
const SITE_ONLY_PERMISSIONS=new Set(PERMISSION_DEFINITIONS.filter(x=>x.siteOnly).map(x=>x.key));
const ROLE_PERMISSION_DEFAULTS={
  'Руководитель сайта':Object.fromEntries(PERMISSION_DEFINITIONS.map(x=>[x.key,true])),
  'Руководитель организации':{
    'employees.view':true,'employees.manage':true,'objects.view':true,'objects.manage':true,
    'organizations.view':true,'organizations.manage':false,'accounting.view':true,'deals.view':true,'deals.manage':true,'warehouse.view':true,
    'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':true,
    'balances.manage':true,'bank.view':true,'bank.import':true,'bank.allocate':true,'bank.delete':true,
    'periods.close':true,'periods.reopen':true,'reports.export':true,
    'users.manage':true,'users.customize':true,'users.delete':false,'logs.view':true,'security.view':false,
    'compliance.view':true,'compliance.manage':true,'incidents.manage':true,'legal.manage':false,'backups.manage':false
  },
  'Бухгалтер':{
    'employees.view':true,'employees.manage':false,'objects.view':true,'objects.manage':false,
    'organizations.view':true,'organizations.manage':false,'accounting.view':true,'deals.view':true,'deals.manage':true,'warehouse.view':false,
    'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':true,
    'balances.manage':true,'bank.view':true,'bank.import':true,'bank.allocate':true,'bank.delete':true,
    'periods.close':true,'periods.reopen':false,'reports.export':true,
    'users.manage':false,'users.customize':false,'users.delete':false,'logs.view':false,'security.view':false,'backups.manage':false
  },
  'Руководитель':{
    'employees.view':true,'employees.manage':true,'objects.view':true,'objects.manage':false,
    'organizations.view':true,'organizations.manage':false,'accounting.view':false,'deals.view':true,'deals.manage':true,'warehouse.view':true,
    'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':false,
    'balances.manage':false,'bank.view':false,'bank.import':false,'bank.allocate':false,'bank.delete':false,
    'periods.close':false,'periods.reopen':false,'reports.export':true,
    'users.manage':false,'users.customize':false,'users.delete':false,'logs.view':false,'security.view':false,'backups.manage':false
  },
  'Руководитель проекта':{
    'employees.view':true,'employees.manage':false,'objects.view':true,'objects.manage':false,
    'organizations.view':false,'organizations.manage':false,'accounting.view':false,'deals.view':true,'deals.manage':false,'warehouse.view':true,
    'salary.view':true,'salary.create':true,'salary.edit':true,'salary.delete':false,
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
    tenant_id:user.tenant_id||null,organization:user.organization||'',object_name:user.object_name||'',email:user.email||'',
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
function currentConsentEnforcementEnabled(){
  return String(process.env.COMPLIANCE_ENFORCE_CURRENT_CONSENTS||'false').trim().toLowerCase()==='true';
}
async function requireCurrentLegalConsents(user){
  if(!currentConsentEnforcementEnabled()||isTechnicalAdmin(user))return true;
  const status=await compliance.requiredConsentStatus(pool,user.id);
  if(status.ready)return true;
  const err=new Error('Необходимо отдельно принять актуальное Пользовательское соглашение и согласие на обработку персональных данных');
  err.status=403;
  err.code='LEGAL_CONSENT_REQUIRED';
  err.consent_status=status;
  throw err;
}

function requirePermission(key){
  return async function(req,res,next){
    if(!req.session||!req.session.user)return res.status(401).json({error:'Не авторизован'});
    try{
      const user=await refreshAccessUser(req);
      if(!user){req.session.destroy(()=>{});return res.status(401).json({error:'Аккаунт не найден'});}
      if(EMAIL_VERIFY_ENABLED&&!isTechnicalAdmin(user)&&!user.email_verified)return res.status(403).json({error:'Сначала подтвердите электронную почту',code:'EMAIL_VERIFICATION_REQUIRED'});
      try{await requireCurrentLegalConsents(user);}catch(legalErr){
        return res.status(legalErr.status||403).json({error:legalErr.message,code:legalErr.code||'LEGAL_CONSENT_REQUIRED',consent_status:legalErr.consent_status||null});
      }
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
async function projectObjectKeys(user){
  if(!isProjectScoped(user)||!user||!user.id)return [];
  const r=await pool.query("SELECT DISTINCT lower(trim(o.name)) AS object_key FROM object_user_responsibles ur JOIN objects o ON o.id=ur.object_id WHERE ur.user_id=$1 AND lower(trim(o.organization))=lower(trim($2))",[user.id,accessOrganization(user)]);
  return r.rows.map(function(row){return String(row.object_key||'');}).filter(Boolean);
}
async function requireProjectObjectKeys(user){
  const keys=await projectObjectKeys(user);
  if(!keys.length){const err=new Error('Для руководителя проекта не назначен объект');err.status=403;throw err;}
  return keys;
}
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
    const objectKeys=await requireProjectObjectKeys(user);
    const linked=await pool.query("SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim($1)) AND lower(trim(COALESCE(s.object_name,'')))=ANY($2::text[]) LIMIT 1",[row.fio,objectKeys]);
    if(!linked.rows.length){const err=new Error('Нет доступа к этому сотруднику в рамках назначенных объектов');err.status=403;throw err;}
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
  if(isProjectScoped(user)){
    const objectKeys=await requireProjectObjectKeys(user);
    if(!objectKeys.includes(normAccess(row.name))){const err=new Error('Нет доступа к этому объекту');err.status=403;throw err;}
  }
  return row;
}
async function salaryOrganization(employeeFio,objectName){
  const e=await pool.query("SELECT DISTINCT organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) AND trim(COALESCE(organization,''))<>''",[String(employeeFio||'')]);
  if(e.rows.length===1)return String(e.rows[0].organization||'').trim();
  const object=String(objectName||'').trim();
  if(object){
    const o=await pool.query("SELECT DISTINCT organization FROM objects WHERE lower(trim(name))=lower(trim($1)) AND trim(COALESCE(organization,''))<>''",[object]);
    if(o.rows.length===1)return String(o.rows[0].organization||'').trim();
  }
  return '';
}
async function ensureEmployeeOrganizationAccess(user,fio){
  const r=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) LIMIT 1',[String(fio||'')]);
  if(!r.rows.length){const err=new Error('Сотрудник не найден');err.status=404;throw err;}
  await ensureOrganizationAccess(user,r.rows[0].organization);
  return r.rows[0];
}
async function ensureSalaryAccess(user,employeeFio,objectName){
  const fio=String(employeeFio||'').trim(),object=String(objectName||'').trim();
  if(!fio){const err=new Error('Выберите сотрудника');err.status=400;throw err;}
  let employeesResult;
  if(isSiteWideUser(user)){
    employeesResult=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) ORDER BY id',[fio]);
  }else{
    const ownOrg=accessOrganization(user);
    employeesResult=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) AND lower(trim(organization))=lower(trim($2)) ORDER BY id',[fio,ownOrg]);
  }
  if(!employeesResult.rows.length){const err=new Error(isSiteWideUser(user)?'Сотрудник не найден':'Сотрудник не найден в вашей организации');err.status=isSiteWideUser(user)?404:403;throw err;}
  let candidates=employeesResult.rows,obj=null;
  if(object){
    let objectsResult;
    if(isSiteWideUser(user)){
      objectsResult=await pool.query('SELECT id,name,organization FROM objects WHERE lower(trim(name))=lower(trim($1)) ORDER BY id',[object]);
    }else{
      objectsResult=await pool.query('SELECT id,name,organization FROM objects WHERE lower(trim(name))=lower(trim($1)) AND lower(trim(organization))=lower(trim($2)) ORDER BY id',[object,accessOrganization(user)]);
    }
    if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      objectsResult.rows=objectsResult.rows.filter(o=>objectKeys.includes(normAccess(o.name)));
    }
    if(!objectsResult.rows.length){const err=new Error('Объект не найден в организации сотрудника');err.status=400;throw err;}
    const matches=[];
    for(const e of candidates)for(const o of objectsResult.rows)if(sameAccessValue(e.organization,o.organization))matches.push({employee:e,object:o});
    const orgKeys=Array.from(new Set(matches.map(x=>normAccess(x.employee.organization))));
    if(!matches.length){const err=new Error('Сотрудник и объект относятся к разным организациям');err.status=400;throw err;}
    if(orgKeys.length>1){const err=new Error('Невозможно однозначно определить организацию начисления. Уточните сотрудника или объект.');err.status=409;throw err;}
    candidates=matches.filter(x=>normAccess(x.employee.organization)===orgKeys[0]).map(x=>x.employee);
    obj=matches.find(x=>normAccess(x.employee.organization)===orgKeys[0]).object;
  }else if(isProjectScoped(user)){
    const err=new Error('Для руководителя проекта начисление должно быть привязано к назначенному объекту');err.status=400;throw err;
  }
  const orgKeys=Array.from(new Set(candidates.map(e=>normAccess(e.organization))));
  if(orgKeys.length>1){const err=new Error('Найдено несколько сотрудников с одинаковым ФИО в разных организациях. Выберите объект для уточнения.');err.status=409;throw err;}
  const employee=candidates[0];
  if(!isSiteWideUser(user))await ensureOrganizationAccess(user,employee.organization);
  return {employee,object:obj,organization:String(employee.organization||'').trim()};
}
async function ensureFinancialEmployeeAccess(user,fio){
  const name=String(fio||'').trim();
  if(isSiteWideUser(user)){
    const r=await pool.query('SELECT id,fio,organization FROM employees WHERE lower(trim(fio))=lower(trim($1)) ORDER BY id LIMIT 2',[name]);
    if(!r.rows.length){const err=new Error('Сотрудник не найден');err.status=404;throw err;}
    if(r.rows.length>1&&!sameAccessValue(r.rows[0].organization,r.rows[1].organization)){const err=new Error('Несколько сотрудников имеют одинаковое ФИО. Уточните организацию.');err.status=409;throw err;}
    return r.rows[0];
  }
  return ensureEmployeeAccess(user,name);
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
    try{await requireCurrentLegalConsents(user);}catch(legalErr){
      return res.status(legalErr.status||403).json({error:legalErr.message,code:legalErr.code||'LEGAL_CONSENT_REQUIRED',consent_status:legalErr.consent_status||null});
    }
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
  const subject=purpose==='verify'?'Подтверждение электронной почты':purpose==='login_mfa'?'Код второго фактора для входа':'Восстановление пароля';
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
function platformMfaEnabled(){
  return String(process.env.PLATFORM_MFA_ENABLED||'false').trim().toLowerCase()==='true';
}
function requiresPlatformMfa(user){
  return platformMfaEnabled()&&(isTechnicalAdmin(user)||String(user&&user.role||'')==='Руководитель сайта');
}
function platformMfaEmail(user){
  if(isTechnicalAdmin(user)){
    return normalizeEmail(user&&user.email||process.env.PLATFORM_ADMIN_MFA_EMAIL||'');
  }
  return normalizeEmail(user&&user.email||'');
}
function maskEmail(email){
  const value=normalizeEmail(email),parts=value.split('@');
  if(parts.length!==2)return '';
  const local=parts[0],visible=local.length<=2?local.charAt(0):local.slice(0,2);
  return visible+'***@'+parts[1];
}
async function establishAuthenticatedSession(req,user){
  const updated=await pool.query('UPDATE users SET last_login_at=NOW(), login_count=COALESCE(login_count,0)+1 WHERE id=$1 RETURNING *',[user.id]);
  const loginUser=updated.rows[0]||user;
  await new Promise((resolve,reject)=>req.session.regenerate(err=>err?reject(err):resolve()));
  req.session.user=buildSessionUser(loginUser);
  req.session.reauthenticated_at=Date.now();
  return req.session.user;
}
async function completeLogin(req,user){
  const sessionUser=await establishAuthenticatedSession(req,user);
  await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [user.login, 'Вход в систему']);
  await logSecurityEvent(req,'login_success',true,requiresPlatformMfa(user)?'Authenticated with MFA':'Authenticated',user.login);
  return sessionUser;
}

app.post('/api/login', authRateLimit, async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (result.rows.length === 0) {
      await logSecurityEvent(req,'login_failed',false,'Unknown login',String(login||''));
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    const user = result.rows[0];
    if(String(user.status||'active')!=='active'||user.deleted_at){
      await logSecurityEvent(req,'login_failed',false,'Inactive account',String(login||''));
      return res.status(403).json({error:'Учётная запись отключена'});
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await logSecurityEvent(req,'login_failed',false,'Invalid password',String(login||''));
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    if (!user.role) {
      return res.status(403).json({ error: 'Роль не назначена. Обратитесь к руководителю сайта.' });
    }
    if(requiresPlatformMfa(user)){
      const email=platformMfaEmail(user);
      if(!email){
        await logSecurityEvent(req,'mfa_blocked',false,'MFA email is not configured',user.login);
        return res.status(503).json({error:'Для административного аккаунта включена MFA, но не настроен e-mail второго фактора. Настройте email пользователя или PLATFORM_ADMIN_MFA_EMAIL.',code:'MFA_EMAIL_REQUIRED'});
      }
      await sendSecurityCode(user.id,email,'login_mfa');
      req.session.pendingMfa={user_id:user.id,email,created_at:Date.now()};
      await logSecurityEvent(req,'mfa_challenge',true,'Second factor requested',user.login);
      return res.status(202).json({mfa_required:true,masked_email:maskEmail(email)});
    }
    const sessionUser=await completeLogin(req,user);
    res.json(sessionUser);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
});

app.post('/api/login/mfa',authRateLimit,async(req,res)=>{
  const pending=req.session&&req.session.pendingMfa;
  if(!pending||!pending.user_id||Date.now()-Number(pending.created_at||0)>10*60*1000)return res.status(401).json({error:'Сессия второго фактора истекла. Введите логин и пароль заново.'});
  try{
    const r=await pool.query('SELECT * FROM users WHERE id=$1',[pending.user_id]);
    if(!r.rows.length)return res.status(401).json({error:'Аккаунт не найден'});
    const user=r.rows[0];
    const checked=await consumeCode(user.id,pending.email,'login_mfa',String(req.body.code||'').trim());
    if(!checked.ok){
      await logSecurityEvent(req,'mfa_failed',false,checked.error,user.login);
      return res.status(400).json({error:checked.error});
    }
    const sessionUser=await completeLogin(req,user);
    res.json(sessionUser);
  }catch(err){console.error('MFA login:',err.message);res.status(500).json({error:'Ошибка проверки второго фактора'});}
});

app.post('/api/login/mfa/resend',authRateLimit,async(req,res)=>{
  const pending=req.session&&req.session.pendingMfa;
  if(!pending||!pending.user_id||Date.now()-Number(pending.created_at||0)>10*60*1000)return res.status(401).json({error:'Сессия второго фактора истекла. Введите логин и пароль заново.'});
  try{
    const r=await pool.query('SELECT login FROM users WHERE id=$1',[pending.user_id]);
    if(!r.rows.length)return res.status(401).json({error:'Аккаунт не найден'});
    await sendSecurityCode(pending.user_id,pending.email,'login_mfa');
    pending.created_at=Date.now();
    res.json({ok:true,masked_email:maskEmail(pending.email)});
  }catch(err){res.status(400).json({error:err.message});}
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

function sessionHandle(sid){
  return crypto.createHash('sha256').update(String(sid||'')).digest('hex').slice(0,32);
}
app.get('/api/sessions', requireAuth, async (req,res)=>{
  try{
    const userId=String(req.session.user.id);
    const r=await pool.query(
      "SELECT sid,expire,updated_at FROM app_sessions WHERE sess #>> '{user,id}'=$1 AND expire>NOW() ORDER BY updated_at DESC",
      [userId]
    );
    res.json(r.rows.map(row=>({handle:sessionHandle(row.sid),expire:row.expire,updated_at:row.updated_at,current:row.sid===req.sessionID})));
  }catch(err){res.status(500).json({error:'Не удалось получить активные сессии'});}
});
app.delete('/api/sessions/:handle', requireAuth, async (req,res)=>{
  const handle=String(req.params.handle||'');
  if(!/^[a-f0-9]{32}$/.test(handle))return res.status(400).json({error:'Некорректная сессия'});
  try{
    const rows=(await pool.query("SELECT sid FROM app_sessions WHERE sess #>> '{user,id}'=$1",[String(req.session.user.id)])).rows;
    const target=rows.find(row=>sessionHandle(row.sid)===handle);
    if(!target)return res.status(404).json({error:'Сессия не найдена'});
    if(target.sid===req.sessionID){
      const login=req.session.user.login;
      return req.session.destroy(async err=>{
        if(err)return res.status(500).json({error:'Не удалось завершить текущую сессию'});
        try{await logSecurityEvent(req,'session_revoked',true,'Current session revoked',login);}catch(e){}
        res.json({ok:true,current:true});
      });
    }
    await pool.query('DELETE FROM app_sessions WHERE sid=$1',[target.sid]);
    await logSecurityEvent(req,'session_revoked',true,'Other session revoked: '+handle.slice(0,12),req.session.user.login);
    res.json({ok:true,current:false});
  }catch(err){res.status(500).json({error:'Не удалось завершить сессию'});}
});

const RECENT_REAUTH_MS=5*60*1000;

function requireRecentReauth(req,res,next){
  const ts=Number(req.session&&req.session.reauthenticated_at||0);
  if(!ts || Date.now()-ts>RECENT_REAUTH_MS){
    return res.status(401).json({
      error:'Для этой чувствительной операции повторно введите пароль',
      code:'REAUTH_REQUIRED'
    });
  }
  next();
}

app.post('/api/auth/reauth',requireAuth,authRateLimit,async(req,res)=>{
  const password=String(req.body&&req.body.password||'');
  if(!password)return res.status(400).json({error:'Введите пароль'});
  try{
    const r=await pool.query('SELECT id,login,password,status,deleted_at FROM users WHERE id=$1',[req.session.user.id]);
    if(!r.rows.length)return res.status(401).json({error:'Аккаунт не найден'});
    const user=r.rows[0];
    if(String(user.status||'active')!=='active'||user.deleted_at)return res.status(403).json({error:'Учётная запись отключена'});
    const ok=await bcrypt.compare(password,user.password);
    if(!ok){
      await logSecurityEvent(req,'reauth_failed',false,'Invalid password for sensitive operation',user.login);
      return res.status(401).json({error:'Неверный пароль'});
    }
    req.session.reauthenticated_at=Date.now();
    await logSecurityEvent(req,'reauth_success',true,'Sensitive operation re-authenticated',user.login);
    res.json({ok:true,valid_for_seconds:Math.floor(RECENT_REAUTH_MS/1000)});
  }catch(err){
    console.error('Reauth error:',err.message);
    res.status(500).json({error:'Не удалось повторно подтвердить пароль'});
  }
});

app.post('/api/account/change-password',requireAuth,authRateLimit,async(req,res)=>{
  const currentPassword=String(req.body.current_password||''),newPassword=String(req.body.new_password||'');
  if(newPassword.length<12)return res.status(400).json({error:'Новый пароль должен содержать не менее 12 символов'});
  if(newPassword===currentPassword)return res.status(400).json({error:'Новый пароль должен отличаться от текущего'});
  try{
    const r=await pool.query('SELECT id,login,password FROM users WHERE id=$1',[req.session.user.id]);
    if(!r.rows.length)return res.status(401).json({error:'Аккаунт не найден'});
    const ok=await bcrypt.compare(currentPassword,r.rows[0].password);
    if(!ok){
      await logSecurityEvent(req,'password_change_failed',false,'Invalid current password',r.rows[0].login);
      return res.status(401).json({error:'Текущий пароль указан неверно'});
    }
    const hash=await bcrypt.hash(newPassword,12);
    await pool.query('UPDATE users SET password=$1 WHERE id=$2',[hash,r.rows[0].id]);
    const other=(await pool.query("SELECT sid FROM app_sessions WHERE sess #>> '{user,id}'=$1",[String(r.rows[0].id)])).rows;
    for(const row of other){if(row.sid!==req.sessionID)await pool.query('DELETE FROM app_sessions WHERE sid=$1',[row.sid]);}
    req.session.reauthenticated_at=Date.now();
    await logSecurityEvent(req,'password_changed',true,'Password changed; other sessions revoked',r.rows[0].login);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[r.rows[0].login,'Изменён пароль; другие активные сессии завершены']);
    res.json({ok:true,message:'Пароль изменён. Другие активные сессии завершены.'});
  }catch(err){res.status(500).json({error:'Не удалось изменить пароль'});}
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
    await pool.query("UPDATE users SET email_verified=TRUE,email_verified_at=NOW() WHERE id=$1",[r.rows[0].id]);
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
  await pool.query("UPDATE users SET email_verified=TRUE,email_verified_at=NOW() WHERE id=$1",[req.session.user.id]);
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
function invitationTokenHash(value){
  return crypto.createHash('sha256').update(String(value||'').trim(),'utf8').digest('hex');
}
app.get('/api/public/invitation/:token', async (req,res)=>{
  try{
    const token=String(req.params.token||'').trim();
    if(token.length<20)return res.status(404).json({error:'Приглашение не найдено'});
    const r=await pool.query(
      `SELECT i.id,i.expires_at,i.max_uses,i.uses,o.id AS organization_id,o.name AS organization
       FROM registration_invites i
       JOIN organizations o ON o.id=i.organization_id
       WHERE i.token_hash=$1 AND i.revoked_at IS NULL AND i.expires_at>NOW()
         AND i.uses<i.max_uses AND o.status='active'
       LIMIT 1`,
      [invitationTokenHash(token)]
    );
    if(!r.rows.length)return res.status(404).json({error:'Приглашение недействительно, истекло или уже использовано'});
    res.setHeader('Cache-Control','no-store');
    res.json({ok:true,organization_id:r.rows[0].organization_id,organization:r.rows[0].organization,expires_at:r.rows[0].expires_at});
  }catch(err){res.status(500).json({error:'Не удалось проверить приглашение'});}
});

app.post('/api/register', authRateLimit, async (req, res) => {
  const enforceLegalReady=String(process.env.COMPLIANCE_ENFORCE_LEGAL_READY||'true').trim().toLowerCase()!=='false';
  if(enforceLegalReady&&!compliance.operatorReady(compliance.operatorDetails())){
    return res.status(503).json({error:'Регистрация временно недоступна: администратор должен заполнить реквизиты оператора персональных данных.',code:'LEGAL_CONFIGURATION_REQUIRED'});
  }
  const { fio, phone, password } = req.body;
  const email=normalizeEmail(req.body.email);
  const inviteToken=String(req.body.invite_token||'').trim();
  const legacyOrganizationId=Number(req.body.organization_id);
  const inviteRequired=String(process.env.REGISTRATION_INVITE_REQUIRED||'true').trim().toLowerCase()!=='false';
  const normalizedFio=normalizeRegistrationFio(fio);
  const login=buildLoginFromFio(normalizedFio);
  const normalizedPhone=phone?normalizePhone(phone):'';
  const termsAccepted=req.body.terms_accepted===true;
  const pdConsent=req.body.pd_consent===true;
  const marketingConsent=req.body.marketing_consent===true;
  if (!normalizedFio || !login || !password || !email) return res.status(400).json({ error: 'Заполните обязательные поля регистрации' });
  if(inviteRequired&&!inviteToken)return res.status(400).json({error:'Для регистрации требуется действующее приглашение организации'});
  if (!termsAccepted || !pdConsent) return res.status(400).json({ error: 'Пользовательское соглашение и согласие на обработку персональных данных принимаются отдельными обязательными действиями' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Введите корректный email' });
  if (normalizedFio.split(' ').filter(Boolean).length < 2) return res.status(400).json({ error: 'Введите фамилию и имя' });
  if (phone&&!normalizedPhone) return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  if (String(password).length < 12) return res.status(400).json({ error: 'Пароль должен содержать не менее 12 символов' });

  const client=await pool.connect();
  let createdUser=null,organization='',organizationId=null,inviteRow=null;
  try {
    await client.query('BEGIN');
    if(inviteToken){
      const inviteRes=await client.query(
        `SELECT i.*,o.name AS organization_name,o.status AS organization_status
         FROM registration_invites i JOIN organizations o ON o.id=i.organization_id
         WHERE i.token_hash=$1 FOR UPDATE`,
        [invitationTokenHash(inviteToken)]
      );
      inviteRow=inviteRes.rows[0]||null;
      if(!inviteRow||inviteRow.revoked_at||new Date(inviteRow.expires_at)<=new Date()||Number(inviteRow.uses)>=Number(inviteRow.max_uses)||inviteRow.organization_status!=='active'){
        await client.query('ROLLBACK');
        return res.status(400).json({error:'Приглашение недействительно, истекло или уже использовано'});
      }
      organizationId=Number(inviteRow.organization_id);
      organization=String(inviteRow.organization_name||'').trim();
    }else{
      if(inviteRequired){await client.query('ROLLBACK');return res.status(400).json({error:'Для регистрации требуется приглашение'});}
      const orgRes=await client.query("SELECT id,name FROM organizations WHERE id=$1 AND status='active'",[legacyOrganizationId]);
      if(!orgRes.rows.length){await client.query('ROLLBACK');return res.status(400).json({error:'Выбранная организация не найдена или недоступна'});}
      organizationId=Number(orgRes.rows[0].id);
      organization=String(orgRes.rows[0].name||'').trim();
    }
    const reRegistrationIdentifiers=[
      ['email',email],
      ['login',String(login||'').trim().toLowerCase()],
      ['fio',String(normalizedFio||'').trim().toLowerCase()]
    ].filter(x=>x[1]);
    for(const [type,value] of reRegistrationIdentifiers){
      const hash=crypto.createHash('sha256').update(value,'utf8').digest('hex');
      await client.query(
        "UPDATE privacy_tombstones SET released_at=NOW(),reason=reason||CASE WHEN reason='' THEN '' ELSE '; ' END||'new registration authorized' WHERE identifier_hash=$1 AND identifier_type=$2 AND (tenant_scope=$3 OR tenant_scope='')",
        [hash,type,String(organizationId)]
      );
    }
    const existing = await client.query('SELECT id FROM users WHERE lower(login) = lower($1) OR lower(email)=lower($2)', [login,email]);
    if (existing.rows.length > 0) {await client.query('ROLLBACK');return res.status(400).json({ error: 'Логин или электронная почта уже используются' });}
    const hash = await bcrypt.hash(password, 10);
    const inserted=await client.query(
      'INSERT INTO users (login,password,fio,phone,email,email_verified,role,organization,tenant_id,status) VALUES ($1,$2,$3,$4,$5,FALSE,$6,$7,$8,$9) RETURNING id,login,email,tenant_id',
      [login, hash, normalizedFio, normalizedPhone, email, '', organization, organizationId, 'active']
    );
    createdUser=inserted.rows[0];
    await compliance.recordRegistrationConsents(client,req,createdUser,{termsAccepted,pdConsent,marketingConsent});
    if(inviteRow)await client.query('UPDATE registration_invites SET uses=uses+1,last_used_at=NOW() WHERE id=$1',[inviteRow.id]);
    await client.query('COMMIT');
  } catch (err) {
    try{await client.query('ROLLBACK');}catch(e){}
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  } finally {
    client.release();
  }

  try{
    if(EMAIL_VERIFY_ENABLED){
      await sendSecurityCode(createdUser.id,email,'verify');
      return res.json({ ok: true, login, email, organization, email_verification_required:true, message: 'Регистрация создана, юридические действия зафиксированы. Код подтверждения отправлен на email. После подтверждения руководитель вашей организации сможет назначить вам роль.' });
    }
    res.json({ ok: true, login, email, organization, email_verification_required:false, message: 'Регистрация создана, юридические действия зафиксированы. После назначения роли руководителем вашей организации можно войти.' });
  }catch(err){
    console.error('Registration verification mail:',err.message);
    res.status(503).json({error:'Аккаунт создан, но письмо с кодом подтверждения не отправлено. Обратитесь к администратору для повторной отправки кода.',registration_created:true,login,email});
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
  if(password.length<12)return res.status(400).json({error:'Новый пароль должен содержать не менее 12 символов'});
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

app.get('/api/registration-invites', requireUserManager, async (req,res)=>{
  try{
    const actor=req.accessUser||await refreshAccessUser(req);
    const params=[];
    let where='';
    if(!isSiteWideUser(actor)){params.push(actor.tenant_id||0);where='WHERE i.organization_id=$1';}
    const r=await pool.query(
      `SELECT i.id,i.organization_id,o.name AS organization,i.created_at,i.expires_at,i.max_uses,i.uses,i.revoked_at,i.last_used_at
       FROM registration_invites i JOIN organizations o ON o.id=i.organization_id
       ${where} ORDER BY i.created_at DESC LIMIT 200`,
      params
    );
    res.json(r.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.post('/api/registration-invites', requireUserManager, async (req,res)=>{
  try{
    const actor=req.accessUser||await refreshAccessUser(req);
    let organizationId=isSiteWideUser(actor)?Number(req.body.organization_id):Number(actor.tenant_id);
    if(!Number.isInteger(organizationId)||organizationId<=0)return res.status(400).json({error:'Не выбрана организация'});
    if(!isSiteWideUser(actor)&&organizationId!==Number(actor.tenant_id))return res.status(403).json({error:'Можно создавать приглашения только для своей организации'});
    const org=await pool.query("SELECT id,name FROM organizations WHERE id=$1 AND status='active'",[organizationId]);
    if(!org.rows.length)return res.status(404).json({error:'Организация не найдена или неактивна'});
    const validDays=Math.min(30,Math.max(1,Number(req.body.valid_days)||7));
    const maxUses=Math.min(20,Math.max(1,Number(req.body.max_uses)||1));
    const token=crypto.randomBytes(32).toString('base64url');
    const r=await pool.query(
      `INSERT INTO registration_invites(token_hash,organization_id,created_by,expires_at,max_uses)
       VALUES($1,$2,$3,NOW()+($4::text||' days')::interval,$5)
       RETURNING id,organization_id,created_at,expires_at,max_uses,uses`,
      [invitationTokenHash(token),organizationId,actor.id,String(validDays),maxUses]
    );
    await logSecurityEvent(req,'registration_invite_created',true,'invite='+r.rows[0].id+'; org='+organizationId+'; max_uses='+maxUses,actor.login);
    res.status(201).json({...r.rows[0],organization:org.rows[0].name,token});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.delete('/api/registration-invites/:id', requireUserManager, async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректное приглашение'});
  try{
    const actor=req.accessUser||await refreshAccessUser(req);
    const q=isSiteWideUser(actor)
      ?await pool.query('SELECT * FROM registration_invites WHERE id=$1',[id])
      :await pool.query('SELECT * FROM registration_invites WHERE id=$1 AND organization_id=$2',[id,actor.tenant_id||0]);
    if(!q.rows.length)return res.status(404).json({error:'Приглашение не найдено'});
    await pool.query('UPDATE registration_invites SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=$1',[id]);
    await logSecurityEvent(req,'registration_invite_revoked',true,'invite='+id,actor.login);
    res.json({ok:true});
  }catch(err){res.status(err.status||500).json({error:err.message});}
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
    if(role==='Руководитель проекта'&&objectName){
      await pool.query("INSERT INTO object_user_responsibles(object_id,user_id) SELECT o.id,$1 FROM objects o WHERE lower(trim(o.name))=lower(trim($2)) AND lower(trim(o.organization))=lower(trim($3)) ON CONFLICT(object_id,user_id) DO NOTHING",[userId,objectName,organization]);
    }
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
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query("SELECT DISTINCT e.id,e.fio,e.organization,e.position,e.phone,e.birth_date,e.comments,e.employment_status FROM employees e WHERE lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=ANY($2::text[])) ORDER BY e.fio",[accessOrganization(user),objectKeys]);
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
    if(isProjectScoped(user)){
      await logSecurityEvent(req,'hr_profile_denied',false,'Employee ID='+id,user.login);
      return res.status(403).json({error:'Кадровые анкеты недоступны руководителю проекта'});
    }
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
    if(isProjectScoped(user)){
      await logSecurityEvent(req,'hr_profile_denied',false,'Employee ID='+id,user.login);
      return res.status(403).json({error:'Кадровые анкеты недоступны руководителю проекта'});
    }
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
app.get('/api/object-responsible-users', requirePermission('objects.manage'), async (req,res)=>{
  try{
    const actor=req.accessUser||await refreshAccessUser(req);
    const fields='id,fio,role,organization';
    const result=isSiteWideUser(actor)
      ? await pool.query("SELECT "+fields+" FROM users WHERE upper(trim(login))<>'ADMIN' AND trim(COALESCE(organization,''))<>'' ORDER BY organization,fio")
      : await pool.query("SELECT "+fields+" FROM users WHERE upper(trim(login))<>'ADMIN' AND lower(trim(organization))=lower(trim($1)) ORDER BY fio",[accessOrganization(actor)]);
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
async function normalizeResponsibleIds(body,targetOrg){
  let ids=Array.isArray(body.responsible_ids) ? body.responsible_ids : [];
  ids=Array.from(new Set(ids.map(function(v){return Number(v);}).filter(function(v){return Number.isInteger(v)&&v>0;})));
  if(!Array.isArray(body.responsible_ids) && body.responsible){
    const names=String(body.responsible).split(',').map(function(x){return x.trim();}).filter(Boolean);
    if(names.length){
      const found=await pool.query("SELECT id FROM users WHERE lower(trim(organization))=lower(trim($1)) AND lower(trim(fio))=ANY($2::text[])",[targetOrg,names.map(function(n){return n.toLocaleLowerCase('ru-RU');})]);
      ids=found.rows.map(function(r){return Number(r.id);});
    }
  }
  if(!ids.length)return [];
  const valid=await pool.query("SELECT id FROM users WHERE id=ANY($1::int[]) AND lower(trim(organization))=lower(trim($2))",[ids,targetOrg]);
  if(valid.rows.length!==ids.length){
    const err=new Error('Ответственным можно назначить только зарегистрированного пользователя организации объекта');err.status=400;throw err;
  }
  return valid.rows.map(function(r){return Number(r.id);});
}
async function getObjectWithResponsibles(id){
  const result=await pool.query("SELECT o.*,COALESCE(json_agg(json_build_object('id',u.id,'fio',u.fio,'role',u.role) ORDER BY u.fio) FILTER (WHERE u.id IS NOT NULL),'[]'::json) AS responsibles FROM objects o LEFT JOIN object_user_responsibles r ON r.object_id=o.id LEFT JOIN users u ON u.id=r.user_id WHERE o.id=$1 GROUP BY o.id",[id]);
  return result.rows[0] || null;
}
app.get('/api/objects',requirePermission('objects.view'),async(req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    const base="SELECT o.*,COALESCE(json_agg(json_build_object('id',u.id,'fio',u.fio,'role',u.role) ORDER BY u.fio) FILTER (WHERE u.id IS NOT NULL),'[]'::json) AS responsibles FROM objects o LEFT JOIN object_user_responsibles r ON r.object_id=o.id LEFT JOIN users u ON u.id=r.user_id";
    if(isSiteWideUser(user))result=await pool.query(base+" GROUP BY o.id ORDER BY o.name");
    else if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query(base+" WHERE lower(trim(o.organization))=lower(trim($1)) AND lower(trim(o.name))=ANY($2::text[]) GROUP BY o.id ORDER BY o.name",[accessOrganization(user),objectKeys]);
    }
    else result=await pool.query(base+" WHERE lower(trim(o.organization))=lower(trim($1)) GROUP BY o.id ORDER BY o.name",[accessOrganization(user)]);
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
async function saveObject(id,data,res,req){
  const name=String(data.name||'').trim();
  if(!name)return res.status(400).json({error:'Наименование обязательно'});
  const user=req.accessUser||await refreshAccessUser(req);
  const requestedOrg=isSiteWideUser(user)?String(data.organization||'').trim():accessOrganization(user);
  if(!requestedOrg)return res.status(400).json({error:'Выберите организацию объекта'});
  const orgResult=await pool.query('SELECT id,name FROM organizations WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[requestedOrg]);
  if(!orgResult.rows.length)return res.status(400).json({error:'Выбранная организация не найдена'});
  const targetOrg=String(orgResult.rows[0].name||'').trim();
  await ensureOrganizationAccess(user,targetOrg);
  const responsibleIds=await normalizeResponsibleIds(data,targetOrg);
  if(id)await ensureObjectAccess(user,Number(id));
  if(isProjectScoped(user)){
    const objectKeys=await requireProjectObjectKeys(user);
    if(!objectKeys.includes(normAccess(name))){const err=new Error('Руководитель проекта может изменять только назначенный объект');err.status=403;throw err;}
  }
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
    await client.query('DELETE FROM object_user_responsibles WHERE object_id=$1',[id]);
    if(responsibleIds.length)await client.query('INSERT INTO object_user_responsibles (object_id,user_id) SELECT $1,unnest($2::int[]) ON CONFLICT DO NOTHING',[id,responsibleIds]);
    const names=responsibleIds.length ? await client.query('SELECT fio FROM users WHERE id=ANY($1::int[]) ORDER BY fio',[responsibleIds]) : {rows:[]};
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
function organizationPayload(body){
  const src=body&&typeof body==='object'?body:{};
  const digits=function(value){return String(value||'').replace(/\D/g,'');};
  return {
    name:String(src.name||'').trim(),
    full_name:String(src.full_name||'').trim(),
    inn:digits(src.inn),
    kpp:digits(src.kpp),
    ogrn:digits(src.ogrn),
    legal_address:String(src.legal_address||'').trim(),
    address:String(src.address||'').trim(),
    postal_address:String(src.postal_address||'').trim(),
    director_fio:String(src.director_fio||'').trim(),
    phone:String(src.phone||'').trim(),
    email:normalizeEmail(src.email),
    website:String(src.website||'').trim(),
    bank_name:String(src.bank_name||'').trim(),
    bik:digits(src.bik),
    settlement_account:digits(src.settlement_account),
    correspondent_account:digits(src.correspondent_account),
    contacts:String(src.contacts||'').trim()
  };
}
function validateOrganizationPayload(data,requireExtended){
  if(!data.name)return 'Наименование обязательно';
  if(requireExtended&&!data.full_name)return 'Полное наименование обязательно';
  if(requireExtended&&!data.inn)return 'ИНН обязателен';
  if(data.inn&&!/^(?:\d{10}|\d{12})$/.test(data.inn))return 'ИНН должен содержать 10 или 12 цифр';
  if(data.kpp&&!/^\d{9}$/.test(data.kpp))return 'КПП должен содержать 9 цифр';
  if(requireExtended&&!data.ogrn)return 'ОГРН обязателен';
  if(data.ogrn&&!/^(?:\d{13}|\d{15})$/.test(data.ogrn))return 'ОГРН/ОГРНИП должен содержать 13 или 15 цифр';
  if(requireExtended&&!data.legal_address)return 'Юридический адрес обязателен';
  if(data.email&&!validEmail(data.email))return 'Некорректный e-mail организации';
  if(data.bik&&!/^\d{9}$/.test(data.bik))return 'БИК должен содержать 9 цифр';
  if(data.settlement_account&&!/^\d{20}$/.test(data.settlement_account))return 'Расчётный счёт должен содержать 20 цифр';
  if(data.correspondent_account&&!/^\d{20}$/.test(data.correspondent_account))return 'Корреспондентский счёт должен содержать 20 цифр';
  return '';
}
const ORGANIZATION_COLUMNS='name,full_name,inn,kpp,ogrn,legal_address,address,postal_address,director_fio,phone,email,website,bank_name,bik,settlement_account,correspondent_account,contacts';

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

app.post('/api/organizations', requireSiteManager, async (req, res) => {
  const data=organizationPayload(req.body);
  const validation=validateOrganizationPayload(data,true);
  if(validation)return res.status(400).json({error:validation});
  try {
    const duplicate=await pool.query("SELECT id,name FROM organizations WHERE lower(trim(name))=lower(trim($1)) OR (trim($2)<>'' AND inn=$2) OR (trim($3)<>'' AND ogrn=$3) LIMIT 1",[data.name,data.inn,data.ogrn]);
    if(duplicate.rows.length)return res.status(409).json({error:'Организация с таким наименованием, ИНН или ОГРН уже существует'});
    const values=ORGANIZATION_COLUMNS.split(',').map(function(key){return data[key]||'';});
    const result=await pool.query(
      'INSERT INTO organizations ('+ORGANIZATION_COLUMNS+') VALUES ('+values.map(function(_,i){return '$'+(i+1);}).join(',')+') RETURNING *',
      values
    );
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Добавлена организация: '+data.name+(data.inn?' · ИНН '+data.inn:'')]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.status||500).json({ error: err.message });
  }
});

app.put('/api/organizations/:id', requireSiteManager, async (req, res) => {
  const data=organizationPayload(req.body);
  const validation=validateOrganizationPayload(data,false);
  if(validation)return res.status(400).json({error:validation});
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const before=await client.query('SELECT * FROM organizations WHERE id=$1 FOR UPDATE',[req.params.id]);
    if(!before.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Организация не найдена'});}
    const oldName=String(before.rows[0].name||'').trim();
    const duplicate=await client.query("SELECT id FROM organizations WHERE id<>$1 AND (lower(trim(name))=lower(trim($2)) OR (trim($3)<>'' AND inn=$3) OR (trim($4)<>'' AND ogrn=$4)) LIMIT 1",[req.params.id,data.name,data.inn,data.ogrn]);
    if(duplicate.rows.length){await client.query('ROLLBACK');return res.status(409).json({error:'Другая организация уже использует это наименование, ИНН или ОГРН'});}
    const columns=ORGANIZATION_COLUMNS.split(',');
    const values=columns.map(function(key){return data[key]||'';});
    const assignments=columns.map(function(key,i){return key+'=$'+(i+1);}).join(',');
    values.push(req.params.id);
    const result=await client.query('UPDATE organizations SET '+assignments+' WHERE id=$'+values.length+' RETURNING *',values);
    if(oldName&&oldName!==data.name){
      await client.query('INSERT INTO organization_aliases(alias,organization_id) VALUES($1,$2) ON CONFLICT(alias) DO UPDATE SET organization_id=EXCLUDED.organization_id',[normAccess(oldName),req.params.id]);
    }
    for(const table of ['users','employees','objects','salary_records']){
      await client.query("UPDATE "+table+" SET organization=$1 WHERE lower(trim(COALESCE(organization,'')))=lower(trim($2))",[data.name,oldName]);
    }
    if(oldName!==data.name){
      await client.query("INSERT INTO closed_salary_periods(month,year,organization,closed_at,closed_by) SELECT month,year,$1,closed_at,closed_by FROM closed_salary_periods WHERE lower(trim(organization))=lower(trim($2)) ON CONFLICT(month,year,organization) DO UPDATE SET closed_at=GREATEST(closed_salary_periods.closed_at,EXCLUDED.closed_at),closed_by=EXCLUDED.closed_by",[data.name,oldName]);
      await client.query("DELETE FROM closed_salary_periods WHERE lower(trim(organization))=lower(trim($1))",[oldName]);
    }
    await client.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменена организация: '+oldName+' → '+data.name]);
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (err) {
    try{await client.query('ROLLBACK');}catch(e){}
    res.status(err.status||500).json({ error: err.message });
  } finally { client.release(); }
});

app.delete('/api/organizations/:id', requireSiteManager, async (req, res) => {
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
function assertManualPaymentAllocations(value){
  const payments=normalizePayments(value);
  const allowedMonths=new Set(['Январь','Февраль','Март','Апрель','Май','Июнь','Июль','Август','Сентябрь','Октябрь','Ноябрь','Декабрь']);
  payments.forEach((p,paymentIndex)=>{
    const paymentAmount=Number(p&&((p.amount!=null)?p.amount:p.sum));
    if(!Number.isFinite(paymentAmount)||paymentAmount<0){
      const err=new Error('Некорректная сумма ручной выплаты #'+(paymentIndex+1));err.status=400;throw err;
    }
    const allocations=Array.isArray(p&&p.allocations)?p.allocations:[];
    let allocated=0;
    allocations.forEach((a,index)=>{
      const month=String(a&&a.month||'').trim();
      const year=String(a&&a.year||'').trim();
      const amount=Number(a&&a.amount);
      const handedBy=String(a&&a.handed_by||'').trim();
      const handedAt=String(a&&a.handed_at||'').slice(0,10);
      if(!allowedMonths.has(month)||!/^(20\d{2}|2100)$/.test(year)||!(amount>0)||!handedBy||handedBy.length>255||!/^(20\d{2}|2100)-\d{2}-\d{2}$/.test(handedAt)){
        const err=new Error('Некорректные данные распределения ручной выплаты #'+(paymentIndex+1)+', строка '+(index+1));err.status=400;throw err;
      }
      const d=new Date(handedAt+'T00:00:00Z');
      if(Number.isNaN(d.getTime())||d.toISOString().slice(0,10)!==handedAt){
        const err=new Error('Некорректная дата передачи денег в распределении ручной выплаты');err.status=400;throw err;
      }
      allocated+=amount;
    });
    if(allocated>paymentAmount+0.005){
      const err=new Error('Распределённая сумма ручной выплаты превышает сумму самой выплаты');err.status=400;throw err;
    }
  });
  return payments;
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
      const objectKeys=await requireProjectObjectKeys(user);
      const projectNames=new Set(salaryResult.rows.filter(r=>objectKeys.includes(normAccess(r.object_name))).map(r=>normalizeEmployeeMatchName(r.employee_fio)));
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
  const [users,employees,objects,orgs,salary,deals,responsibles,userResponsibles,periods,balances,bankPayments,aliases,log,securityLog,complianceData]=await Promise.all([
    pool.query('SELECT * FROM users ORDER BY id'),
    pool.query('SELECT * FROM employees ORDER BY id'),
    pool.query('SELECT * FROM objects ORDER BY id'),
    pool.query('SELECT * FROM organizations ORDER BY id'),
    pool.query('SELECT * FROM salary_records ORDER BY id'),
    pool.query('SELECT * FROM deals ORDER BY id'),
    pool.query('SELECT object_id,employee_id,created_at FROM object_responsibles ORDER BY object_id,employee_id'),
    pool.query('SELECT object_id,user_id,created_at FROM object_user_responsibles ORDER BY object_id,user_id'),
    pool.query('SELECT * FROM closed_salary_periods ORDER BY year,month'),
    pool.query('SELECT * FROM employee_balances ORDER BY id'),
    pool.query('SELECT * FROM bank_statement_payments ORDER BY id'),
    pool.query('SELECT * FROM organization_aliases ORDER BY alias'),
    pool.query('SELECT * FROM action_log ORDER BY id'),
    pool.query('SELECT * FROM security_log ORDER BY id'),
    compliance.collectComplianceBackup(pool)
  ]);
  const data={
    format:'salary-online-auto-backup',
    version:4,
    created_at:new Date().toISOString(),
    users:users.rows,
    employees:employees.rows,
    objects:objects.rows,
    organizations:orgs.rows,
    salary:salary.rows,
    deals:deals.rows,
    employee_balances:balances.rows,
    bank_statement_payments:bankPayments.rows,
    object_responsibles:responsibles.rows,
    object_user_responsibles:userResponsibles.rows,
    closed_periods:periods.rows,
    organization_aliases:aliases.rows,
    log:log.rows,
    security_log:securityLog.rows,
    compliance:complianceData
  };
  await pool.query('INSERT INTO automatic_backups(data) VALUES($1)',[JSON.stringify(data)]);
  await pool.query('DELETE FROM automatic_backups WHERE id NOT IN (SELECT id FROM automatic_backups ORDER BY created_at DESC LIMIT 7)');
}
let backupTimer=null;
function startAutomaticBackups(){
  if(backupTimer)clearInterval(backupTimer);
  setTimeout(()=>createAutomaticBackup().catch(e=>console.error('Automatic backup error:',e.message)),15000);
  backupTimer=setInterval(()=>createAutomaticBackup().catch(e=>console.error('Automatic backup error:',e.message)),24*60*60*1000);
}

// === DEALS ===
const DEAL_STATUSES=new Set(['quiet','current','attention','urgent','completed']);
function dealText(value,max){
  const s=String(value==null?'':value).trim();
  return max?s.slice(0,max):s;
}
function dealNumber(value){
  const n=Number(value);
  return Number.isFinite(n)?Math.round(n*100)/100:0;
}
function cleanDealList(value,type){
  const rows=Array.isArray(value)?value.slice(0,1000):[];
  if(type==='customer'){
    return rows.map(x=>({date:dealText(x&&x.date,10),number:dealText(x&&x.number,120),amount:dealNumber(x&&x.amount)}))
      .filter(x=>x.date||x.number||Math.abs(x.amount)>0.0001);
  }
  if(type==='supplier'){
    return rows.map(x=>({
      planned_cost:dealNumber(x&&x.planned_cost),supplier:dealText(x&&x.supplier,500),subject:dealText(x&&x.subject,1000),
      invoice_date:dealText(x&&x.invoice_date,10),invoice_number:dealText(x&&x.invoice_number,180),invoice_amount:dealNumber(x&&x.invoice_amount),
      payment_date:dealText(x&&x.payment_date,10),payment_number:dealText(x&&x.payment_number,180),payment_amount:dealNumber(x&&x.payment_amount)
    })).filter(x=>x.supplier||x.subject||x.invoice_date||x.invoice_number||x.payment_date||x.payment_number||Math.abs(x.planned_cost)+Math.abs(x.invoice_amount)+Math.abs(x.payment_amount)>0.0001);
  }
  return rows.map(x=>({supplier:dealText(x&&x.supplier,500),subject:dealText(x&&x.subject,1000),date:dealText(x&&x.date,10),amount:dealNumber(x&&x.amount)}))
    .filter(x=>x.supplier||x.subject||x.date||Math.abs(x.amount)>0.0001);
}
function cleanDealPayload(body){
  const input=body||{},status=dealText(input.status,30);
  return {
    deal_no:dealText(input.deal_no,80),
    customer:dealText(input.customer,500),
    contract_description:dealText(input.contract_description,4000),
    contract_amount:dealNumber(input.contract_amount),
    customer_invoices:cleanDealList(input.customer_invoices,'customer'),
    customer_payments:cleanDealList(input.customer_payments,'customer'),
    supplier_entries:cleanDealList(input.supplier_entries,'supplier'),
    additional_expenses:cleanDealList(input.additional_expenses,'extra'),
    comments:dealText(input.comments,8000),
    obligation_salary:dealNumber(input.obligation_salary),
    obligation_returns:dealNumber(input.obligation_returns),
    obligation_transit:dealNumber(input.obligation_transit),
    status:DEAL_STATUSES.has(status)?status:'quiet'
  };
}
async function dealTargetScope(user,requestedOrganization){
  const organization=isSiteWideUser(user)?dealText(requestedOrganization,500):accessOrganization(user);
  if(!organization){const err=new Error('Для сделки необходимо выбрать организацию');err.status=400;throw err;}
  const org=await pool.query('SELECT id,name FROM organizations WHERE lower(trim(name))=lower(trim($1)) LIMIT 1',[organization]);
  if(!org.rows.length){const err=new Error('Организация сделки не найдена');err.status=400;throw err;}
  return {organization:org.rows[0].name,tenant_id:org.rows[0].id};
}
app.get('/api/deals',requirePermission('deals.view'),async(req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const result=isSiteWideUser(user)
      ?await pool.query('SELECT * FROM deals ORDER BY id DESC')
      :await pool.query('SELECT * FROM deals WHERE lower(trim(organization))=lower(trim($1)) ORDER BY id DESC',[accessOrganization(user)]);
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.post('/api/deals',requirePermission('deals.manage'),async(req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req),data=cleanDealPayload(req.body),scope=await dealTargetScope(user,req.body&&req.body.organization);
    const result=await pool.query(`INSERT INTO deals
      (tenant_id,organization,deal_no,customer,contract_description,contract_amount,customer_invoices,customer_payments,supplier_entries,additional_expenses,comments,obligation_salary,obligation_returns,obligation_transit,status,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [scope.tenant_id,scope.organization,data.deal_no,data.customer,data.contract_description,data.contract_amount,JSON.stringify(data.customer_invoices),JSON.stringify(data.customer_payments),JSON.stringify(data.supplier_entries),JSON.stringify(data.additional_expenses),data.comments,data.obligation_salary,data.obligation_returns,data.obligation_transit,data.status,req.session.user.login]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Создана сделка '+(data.deal_no||('#'+result.rows[0].id))+' — '+data.customer]);
    res.json(result.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.put('/api/deals/:id',requirePermission('deals.manage'),async(req,res)=>{
  try{
    const id=Number(req.params.id);if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный ID сделки'});
    const user=req.accessUser||await refreshAccessUser(req);
    const before=await pool.query('SELECT * FROM deals WHERE id=$1',[id]);if(!before.rows.length)return res.status(404).json({error:'Сделка не найдена'});
    if(!isSiteWideUser(user)&&!sameAccessValue(before.rows[0].organization,accessOrganization(user)))return res.status(403).json({error:'Нет доступа к этой сделке'});
    const data=cleanDealPayload(req.body),scope=await dealTargetScope(user,req.body&&req.body.organization);
    const result=await pool.query(`UPDATE deals SET tenant_id=$1,organization=$2,deal_no=$3,customer=$4,contract_description=$5,contract_amount=$6,
      customer_invoices=$7::jsonb,customer_payments=$8::jsonb,supplier_entries=$9::jsonb,additional_expenses=$10::jsonb,comments=$11,
      obligation_salary=$12,obligation_returns=$13,obligation_transit=$14,status=$15,updated_at=CURRENT_TIMESTAMP WHERE id=$16 RETURNING *`,
      [scope.tenant_id,scope.organization,data.deal_no,data.customer,data.contract_description,data.contract_amount,JSON.stringify(data.customer_invoices),JSON.stringify(data.customer_payments),JSON.stringify(data.supplier_entries),JSON.stringify(data.additional_expenses),data.comments,data.obligation_salary,data.obligation_returns,data.obligation_transit,data.status,id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Изменена сделка '+(data.deal_no||('#'+id))+' — '+data.customer]);
    res.json(result.rows[0]);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.delete('/api/deals/:id',requirePermission('deals.manage'),async(req,res)=>{
  try{
    const id=Number(req.params.id);if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Некорректный ID сделки'});
    const user=req.accessUser||await refreshAccessUser(req);
    const before=await pool.query('SELECT * FROM deals WHERE id=$1',[id]);if(!before.rows.length)return res.status(404).json({error:'Сделка не найдена'});
    if(!isSiteWideUser(user)&&!sameAccessValue(before.rows[0].organization,accessOrganization(user)))return res.status(403).json({error:'Нет доступа к этой сделке'});
    await pool.query('DELETE FROM deals WHERE id=$1',[id]);
    await pool.query('INSERT INTO action_log(user_login,action) VALUES($1,$2)',[req.session.user.login,'Удалена сделка '+(before.rows[0].deal_no||('#'+id))+' — '+before.rows[0].customer]);
    res.json({ok:true});
  }catch(err){res.status(err.status||500).json({error:err.message});}
});

// === SALARY RECORDS ===
app.get('/api/salary', requirePermission('salary.view'), async (req, res) => {
  try {
    const user=req.accessUser||await refreshAccessUser(req);
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT * FROM salary_records WHERE deleted_at IS NULL ORDER BY employee_fio, year, month');
    }else if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NULL AND lower(trim(COALESCE(s.object_name,'')))=ANY($1::text[]) AND (lower(trim(COALESCE(s.organization,'')))=lower(trim($2)) OR ((trim(COALESCE(s.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations og WHERE lower(trim(og.name))=lower(trim(s.organization)))) AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($2))))) ORDER BY s.employee_fio,s.year,s.month",[objectKeys,accessOrganization(user)]);
    }else{
      result=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NULL AND (lower(trim(COALESCE(s.organization,'')))=lower(trim($1)) OR ((trim(COALESCE(s.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations og WHERE lower(trim(og.name))=lower(trim(s.organization)))) AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($1))))) ORDER BY s.employee_fio,s.year,s.month",[accessOrganization(user)]);
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
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query("SELECT p.* FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=ANY($2::text[]))) ORDER BY p.transaction_date,p.id",[accessOrganization(user),objectKeys]);
    }else{
      result=await pool.query("SELECT p.* FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1))) ORDER BY p.transaction_date,p.id",[accessOrganization(user)]);
    }
    res.json(result.rows);
  }catch(err){res.status(err.status||500).json({error:err.message});}
});
app.get('/api/financial-payments', requirePermission('salary.view'), async (req,res)=>{
  try{
    const user=req.accessUser||await refreshAccessUser(req);
    const fields='p.id,p.employee_id,p.employee_fio,p.transaction_date,p.amount,p.bank,p.purpose,p.document_number,p.allocations';
    let result;
    if(isSiteWideUser(user)){
      result=await pool.query('SELECT '+fields+' FROM bank_statement_payments p ORDER BY p.transaction_date,p.id');
    }else if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query("SELECT "+fields+" FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=ANY($2::text[]))) ORDER BY p.transaction_date,p.id",[accessOrganization(user),objectKeys]);
    }else{
      result=await pool.query("SELECT "+fields+" FROM bank_statement_payments p WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=p.employee_id AND lower(trim(e.organization))=lower(trim($1))) ORDER BY p.transaction_date,p.id",[accessOrganization(user)]);
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
    }else if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      result=await pool.query("SELECT b.* FROM employee_balances b WHERE EXISTS(SELECT 1 FROM employees e WHERE e.id=b.employee_id AND lower(trim(e.organization))=lower(trim($1)) AND EXISTS(SELECT 1 FROM salary_records s WHERE lower(trim(s.employee_fio))=lower(trim(e.fio)) AND lower(trim(COALESCE(s.object_name,'')))=ANY($2::text[]))) ORDER BY b.employee_fio,b.balance_date,b.id",[accessOrganization(user),objectKeys]);
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
    const scope=await ensureSalaryAccess(user,employee_fio,object_name);
    const org=scope.organization;
    await assertSalaryPeriodOpen(month,year,org);
    assertManualPaymentAllocations(payments);
    const duplicate=await pool.query("SELECT id FROM salary_records WHERE deleted_at IS NULL AND lower(employee_fio)=lower($1) AND lower(COALESCE(object_name,''))=lower($2) AND month=$3 AND year=$4 AND (trim(COALESCE(organization,''))='' OR lower(trim(organization))=lower(trim($5))) LIMIT 1",[employee_fio||'',object_name||'',month||'',String(year||''),org]);
    if(duplicate.rows.length && !req.body.allow_duplicate)return res.status(409).json({error:'За '+month+' '+year+' уже есть начисление для '+employee_fio+(object_name?' по объекту «'+object_name+'»':'')+'.',duplicate:true});
    const result = await pool.query(
      `INSERT INTO salary_records (employee_fio, object_name, organization, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [employee_fio||'', object_name||'', org, month||'', year||'', charge_date||null, hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
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
    const nextScope=await ensureSalaryAccess(user,employee_fio,object_name);
    const beforeOrg=String(before.organization||'').trim()||await salaryOrganization(before.employee_fio,before.object_name);
    const nextOrg=nextScope.organization;
    await assertSalaryPeriodOpen(before.month,before.year,beforeOrg);
    if(before.month!==month||String(before.year)!==String(year)||!sameAccessValue(beforeOrg,nextOrg))await assertSalaryPeriodOpen(month,year,nextOrg);
    assertManualPaymentAllocations(payments);
    const result = await pool.query(
      `UPDATE salary_records SET employee_fio=$1, object_name=$2, organization=$3, month=$4, year=$5, charge_date=$6, hour_rate=$7, hours=$8, per_diem_days=$9, per_diem_rate=$10, extra_charges=$11, payments=$12, total=$13, paid=$14 WHERE id=$15 AND deleted_at IS NULL RETURNING *`,
      [employee_fio||'', object_name||'', nextOrg, month||'', year||'', charge_date||null, hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
       JSON.stringify(extra_charges||[]), JSON.stringify(payments||[]), total||0, paid||0, id]
    );
    const oldPaid=paymentSummary(before.payments),newPaid=paymentSummary(payments);
    let action='Изменена запись зарплаты ID='+id+' — '+(employee_fio||before.employee_fio);
    if(Math.abs(newPaid-oldPaid)>0.005)action+='; выплаты: '+oldPaid.toFixed(2)+' ₽ → '+newPaid.toFixed(2)+' ₽';
    if(JSON.stringify(normalizePayments(before.payments))!==JSON.stringify(normalizePayments(payments)))action+='; обновлены реквизиты/распределение ручных выплат';
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
    const org=String(before.rows[0].organization||'').trim()||await salaryOrganization(before.rows[0].employee_fio,before.rows[0].object_name);
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
    else if(isProjectScoped(user)){
      const objectKeys=await requireProjectObjectKeys(user);
      r=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NOT NULL AND lower(trim(COALESCE(s.object_name,'')))=ANY($1::text[]) AND (lower(trim(COALESCE(s.organization,'')))=lower(trim($2)) OR ((trim(COALESCE(s.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations og WHERE lower(trim(og.name))=lower(trim(s.organization)))) AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($2))))) ORDER BY s.deleted_at DESC",[objectKeys,accessOrganization(user)]);
    }
    else r=await pool.query("SELECT s.* FROM salary_records s WHERE s.deleted_at IS NOT NULL AND (lower(trim(COALESCE(s.organization,'')))=lower(trim($1)) OR ((trim(COALESCE(s.organization,''))='' OR NOT EXISTS(SELECT 1 FROM organizations og WHERE lower(trim(og.name))=lower(trim(s.organization)))) AND EXISTS(SELECT 1 FROM employees e WHERE lower(trim(e.fio))=lower(trim(s.employee_fio)) AND lower(trim(e.organization))=lower(trim($1))))) ORDER BY s.deleted_at DESC",[accessOrganization(user)]);
    res.json(r.rows);
  }catch(e){res.status(e.status||500).json({error:e.message});}
});
app.post('/api/salary/:id/restore', requirePermission('salary.delete'), async (req,res)=>{
  try{
    const before=await pool.query('SELECT * FROM salary_records WHERE id=$1 AND deleted_at IS NOT NULL',[req.params.id]);
    if(!before.rows.length)return res.status(404).json({error:'Архивная запись не найдена'});
    const user=req.accessUser||await refreshAccessUser(req);
    await ensureSalaryAccess(user,before.rows[0].employee_fio,before.rows[0].object_name);
    const org=String(before.rows[0].organization||'').trim()||await salaryOrganization(before.rows[0].employee_fio,before.rows[0].object_name);
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

compliance.installComplianceRoutes(app,{
  pool,
  requireAuth,
  requirePermission,
  refreshAccessUser,
  isSiteWideUser
});

// === EXPORT/IMPORT ===
app.get('/api/export', requirePermission('backups.manage'), requireRecentReauth, async (req, res) => {
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

app.post('/api/import', requirePermission('backups.manage'), requireRecentReauth, async (req, res) => {
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
        await pool.query('INSERT INTO organizations (name,full_name,inn,kpp,ogrn,legal_address,address,postal_address,director_fio,phone,email,website,bank_name,bik,settlement_account,correspondent_account,contacts) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)',
          [org.name||'',org.full_name||'',org.inn||'',org.kpp||'',org.ogrn||'',org.legal_address||'',org.address||'',org.postal_address||'',org.director_fio||'',org.phone||'',org.email||'',org.website||'',org.bank_name||'',org.bik||'',org.settlement_account||'',org.correspondent_account||'',org.contacts||'']);
      }
    }
    if (data.salary) {
      for (const rec of data.salary) {
        await pool.query(
          `INSERT INTO salary_records (employee_fio, object_name, organization, month, year, charge_date, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [rec.employee_fio||'', rec.object_name||'', rec.organization||await salaryOrganization(rec.employee_fio,rec.object_name), rec.month||'', rec.year||'', rec.charge_date||null, rec.hour_rate||0, rec.hours||0,
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
app.get('/api/backup', requirePermission('backups.manage'), requireRecentReauth, async (req, res) => {
  try {
    const [users,employees,objects,orgs,salary,deals,balances,bankPayments,objectResponsibles,objectUserResponsibles,closedPeriods,aliases,log,securityLog,complianceData] = await Promise.all([
      pool.query('SELECT * FROM users ORDER BY id'),
      pool.query('SELECT * FROM employees ORDER BY id'),
      pool.query('SELECT * FROM objects ORDER BY id'),
      pool.query('SELECT * FROM organizations ORDER BY id'),
      pool.query('SELECT * FROM salary_records ORDER BY id'),
      pool.query('SELECT * FROM deals ORDER BY id'),
      pool.query('SELECT * FROM employee_balances ORDER BY id'),
      pool.query('SELECT * FROM bank_statement_payments ORDER BY id'),
      pool.query('SELECT object_id, employee_id, created_at FROM object_responsibles ORDER BY object_id, employee_id'),
      pool.query('SELECT object_id, user_id, created_at FROM object_user_responsibles ORDER BY object_id, user_id'),
      pool.query('SELECT * FROM closed_salary_periods ORDER BY year,month,organization'),
      pool.query('SELECT * FROM organization_aliases ORDER BY alias'),
      pool.query('SELECT * FROM action_log ORDER BY id'),
      pool.query('SELECT * FROM security_log ORDER BY id'),
      compliance.collectComplianceBackup(pool)
    ]);
    res.setHeader('Cache-Control','no-store');
    res.json({
      format:'salary-online-backup',
      version:4,
      created_at:new Date().toISOString(),
      users:users.rows,
      employees:employees.rows,
      objects:objects.rows,
      organizations:orgs.rows,
      salary:salary.rows,
      deals:deals.rows,
      employee_balances:balances.rows,
      bank_statement_payments:bankPayments.rows,
      object_responsibles:objectResponsibles.rows,
      object_user_responsibles:objectUserResponsibles.rows,
      closed_periods:closedPeriods.rows,
      organization_aliases:aliases.rows,
      log:log.rows,
      security_log:securityLog.rows,
      compliance:complianceData
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/restore', requirePermission('backups.manage'), requireRecentReauth, async (req, res) => {
  const data=req.body||{};
  if(data.format!=='salary-online-backup' || !Array.isArray(data.users) || !Array.isArray(data.salary)){
    return res.status(400).json({error:'Файл не является резервной копией Salary Online'});
  }
  const client=await pool.connect();
  const hasCompliance=data.version>=4&&data.compliance&&typeof data.compliance==='object';
  try {
    await client.query('BEGIN');
    if(hasCompliance)await compliance.restoreComplianceBackup(client,{});

    await client.query('DELETE FROM salary_records');
    await client.query('DELETE FROM deals');
    await client.query('DELETE FROM employee_balances');
    await client.query('DELETE FROM bank_statement_payments');
    await client.query('DELETE FROM object_user_responsibles');
    await client.query('DELETE FROM object_responsibles');
    await client.query('DELETE FROM organization_aliases');
    await client.query('DELETE FROM closed_salary_periods');
    await client.query('DELETE FROM objects');
    await client.query('DELETE FROM employees');
    await client.query('DELETE FROM action_log');
    await client.query('DELETE FROM security_log');
    await client.query('DELETE FROM users');
    await client.query('DELETE FROM organizations');

    for(const o of (data.organizations||[])){
      await client.query(`INSERT INTO organizations
        (id,name,full_name,inn,kpp,ogrn,legal_address,address,postal_address,director_fio,phone,email,website,bank_name,bik,settlement_account,correspondent_account,contacts,created_at,status,data_region,closed_at,retention_profile_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
        [o.id,o.name||'',o.full_name||'',o.inn||'',o.kpp||'',o.ogrn||'',o.legal_address||'',o.address||'',o.postal_address||'',o.director_fio||'',o.phone||'',o.email||'',o.website||'',o.bank_name||'',o.bik||'',o.settlement_account||'',o.correspondent_account||'',o.contacts||'',o.created_at||new Date(),o.status||'active',o.data_region||'RU',o.closed_at||null,o.retention_profile_id||null]);
    }

    for(const u of data.users){
      await client.query(`INSERT INTO users
        (id,login,password,fio,phone,email,email_verified,role,organization,object_name,role_history,permission_overrides,last_login_at,login_count,created_at,tenant_id,status,deleted_at,email_verified_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19)`,
        [u.id,u.login||'',u.password||'',u.fio||'',u.phone||'',u.email||'',!!u.email_verified,u.role||'',u.organization||'',u.object_name||'',u.role_history||'[]',JSON.stringify(normalizePermissionOverrides(u.permission_overrides)),u.last_login_at||null,Number(u.login_count||0),u.created_at||new Date(),u.tenant_id||null,u.status||'active',u.deleted_at||null,u.email_verified_at||null]);
    }

    for(const e of (data.employees||[])){
      await client.query(`INSERT INTO employees
        (id,fio,organization,position,phone,birth_date,comments,employment_status,hr_profile,photo_data,created_at,tenant_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)`,
        [e.id,e.fio||'',e.organization||'',e.position||'',e.phone||'',e.birth_date||'',e.comments||'',e.employment_status==='dismissed'?'dismissed':'working',JSON.stringify(e.hr_profile&&typeof e.hr_profile==='object'?e.hr_profile:{}),e.photo_data||'',e.created_at||new Date(),e.tenant_id||null]);
    }

    for(const o of (data.objects||[])){
      await client.query('INSERT INTO objects (id,name,address,customer,organization,responsible,created_at,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [o.id,o.name||'',o.address||'',o.customer||'',o.organization||'',o.responsible||'',o.created_at||new Date(),o.tenant_id||null]);
    }

    for(const d of (data.deals||[])){
      await client.query(`INSERT INTO deals
        (id,tenant_id,organization,deal_no,customer,contract_description,contract_amount,customer_invoices,customer_payments,supplier_entries,additional_expenses,comments,obligation_salary,obligation_returns,obligation_transit,status,created_by,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,$19)`,
        [d.id,d.tenant_id||null,d.organization||'',d.deal_no||'',d.customer||'',d.contract_description||'',d.contract_amount||0,
         JSON.stringify(Array.isArray(d.customer_invoices)?d.customer_invoices:[]),JSON.stringify(Array.isArray(d.customer_payments)?d.customer_payments:[]),
         JSON.stringify(Array.isArray(d.supplier_entries)?d.supplier_entries:[]),JSON.stringify(Array.isArray(d.additional_expenses)?d.additional_expenses:[]),
         d.comments||'',d.obligation_salary||0,d.obligation_returns||0,d.obligation_transit||0,DEAL_STATUSES.has(d.status)?d.status:'quiet',
         d.created_by||'',d.created_at||new Date(),d.updated_at||d.created_at||new Date()]);
    }

    for(const a of (data.organization_aliases||[])){
      await client.query('INSERT INTO organization_aliases(alias,organization_id,created_at) VALUES($1,$2,$3) ON CONFLICT(alias) DO UPDATE SET organization_id=EXCLUDED.organization_id',[a.alias,a.organization_id,a.created_at||new Date()]);
    }

    for(const r of (data.object_responsibles||[])){
      await client.query('INSERT INTO object_responsibles (object_id,employee_id,created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[r.object_id,r.employee_id,r.created_at||new Date()]);
    }
    for(const r of (data.object_user_responsibles||[])){
      await client.query('INSERT INTO object_user_responsibles (object_id,user_id,created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[r.object_id,r.user_id,r.created_at||new Date()]);
    }
    if(!Array.isArray(data.object_user_responsibles)){
      await client.query("INSERT INTO object_user_responsibles(object_id,user_id) SELECT DISTINCT r.object_id,u.id FROM object_responsibles r JOIN objects o ON o.id=r.object_id JOIN employees e ON e.id=r.employee_id JOIN users u ON lower(trim(u.fio))=lower(trim(e.fio)) AND lower(trim(u.organization))=lower(trim(o.organization)) ON CONFLICT(object_id,user_id) DO NOTHING");
    }

    for(const row of data.salary){
      await client.query(`INSERT INTO salary_records
        (id,employee_fio,object_name,organization,month,year,charge_date,hour_rate,hours,per_diem_days,per_diem_rate,extra_charges,payments,total,paid,deleted_at,deleted_by,created_at,tenant_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
        [row.id,row.employee_fio||'',row.object_name||'',row.organization||'',row.month||'',row.year||'',row.charge_date||null,row.hour_rate||0,row.hours||0,row.per_diem_days||0,row.per_diem_rate||0,
         typeof row.extra_charges==='string'?row.extra_charges:JSON.stringify(row.extra_charges||[]),typeof row.payments==='string'?row.payments:JSON.stringify(row.payments||[]),row.total||0,row.paid||0,row.deleted_at||null,row.deleted_by||null,row.created_at||new Date(),row.tenant_id||null]);
    }

    for(const b of (data.employee_balances||[])){
      const direction=b.direction==='employee_to_company'||Number(b.amount)<0?'employee_to_company':'company_to_employee';
      const signedAmount=(direction==='employee_to_company'?-1:1)*Math.abs(Number(b.amount)||0);
      await client.query('INSERT INTO employee_balances (id,employee_id,employee_fio,balance_date,amount,direction,comment,created_by,created_at,updated_at,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [b.id,b.employee_id||null,b.employee_fio||'',b.balance_date||null,signedAmount,direction,b.comment||'',b.created_by||'',b.created_at||new Date(),b.updated_at||b.created_at||new Date(),b.tenant_id||null]);
    }

    for(const p of (data.bank_statement_payments||[])){
      const tx={bank:p.bank,company_account:p.company_account,transaction_date:p.transaction_date,amount:p.amount,document_number:p.document_number,recipient_account:p.recipient_account,counterparty:p.counterparty||p.employee_fio,purpose:p.purpose};
      await client.query(`INSERT INTO bank_statement_payments
        (id,employee_id,employee_fio,bank,company_account,transaction_date,amount,document_number,recipient_account,counterparty,purpose,transaction_key,source_filename,imported_at,imported_by,allocations,tenant_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17)`,
        [p.id,p.employee_id||null,p.employee_fio||'',p.bank||'',p.company_account||'',p.transaction_date||null,p.amount||0,p.document_number||'',p.recipient_account||'',p.counterparty||p.employee_fio||'',p.purpose||'',p.transaction_key||bankTransactionKey(tx),p.source_filename||'',p.imported_at||new Date(),p.imported_by||'',JSON.stringify(Array.isArray(p.allocations)?p.allocations:[]),p.tenant_id||null]);
    }

    for(const p of (data.closed_periods||[])){
      await client.query('INSERT INTO closed_salary_periods(month,year,organization,closed_at,closed_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT(month,year,organization) DO UPDATE SET closed_at=EXCLUDED.closed_at,closed_by=EXCLUDED.closed_by',
        [p.month||'',p.year||'',p.organization||'',p.closed_at||new Date(),p.closed_by||'']);
    }

    for(const l of (data.log||[])){
      await client.query('INSERT INTO action_log (id,user_login,action,created_at) VALUES ($1,$2,$3,$4)',[l.id,l.user_login||'',l.action||'',l.created_at||new Date()]);
    }
    for(const l of (data.security_log||[])){
      await client.query('INSERT INTO security_log (id,created_at,event,user_login,ip,user_agent,success,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',[l.id,l.created_at||new Date(),l.event||'',l.user_login||'',l.ip||'',l.user_agent||'',!!l.success,l.details||'']);
    }

    if(hasCompliance)await compliance.restoreComplianceBackup(client,data.compliance);
    await enforcePrivacyTombstones(client);

    for(const table of ['users','employees','objects','organizations','salary_records','deals','employee_balances','bank_statement_payments','action_log','security_log']){
      await client.query("SELECT setval(pg_get_serial_sequence('"+table+"','id'), COALESCE((SELECT MAX(id) FROM "+table+"),1), (SELECT COUNT(*)>0 FROM "+table+"))");
    }
    await client.query('COMMIT');
    await compliance.ensureComplianceSchema(pool);
    res.json({ok:true,message:hasCompliance?'Резервная копия версии 4 восстановлена вместе с compliance evidence':'Восстановлена legacy-копия без compliance evidence. Проверьте согласия, DSAR и аудит вручную.',compliance_restored:!!hasCompliance});
  } catch(err) {
    try{await client.query('ROLLBACK');}catch(e){}
    res.status(500).json({error:err.message});
  } finally { client.release(); }
});

// Clear all data
app.post('/api/clear', requirePermission('backups.manage'), requireRecentReauth, async (req, res) => {
  try {
    await pool.query('DELETE FROM salary_records');
    await pool.query('DELETE FROM deals');
    await pool.query('DELETE FROM employee_balances');
    await pool.query('DELETE FROM bank_statement_payments');
    await pool.query('DELETE FROM object_user_responsibles');
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
  const result = await pool.query('SELECT id,password,email FROM users WHERE login = $1', ['ADMIN']);
  if (result.rows.length === 0) {
    const initialPassword=String(process.env.INITIAL_ADMIN_PASSWORD||'');
    if(initialPassword.length<12)throw new Error('ADMIN account is absent. Set INITIAL_ADMIN_PASSWORD with at least 12 characters for one-time bootstrap.');
    const hash = await bcrypt.hash(initialPassword, 12);
    await pool.query(
      'INSERT INTO users (login,password,fio,phone,role,status) VALUES ($1,$2,$3,$4,$5,$6)',
      ['ADMIN', hash, 'Администратор', '', 'Руководитель сайта','active']
    );
    console.log('ADMIN created from INITIAL_ADMIN_PASSWORD. Remove INITIAL_ADMIN_PASSWORD from environment after first successful login.');
  }else{
    try{
      if(await bcrypt.compare('ADMIN',result.rows[0].password))console.warn('SECURITY WARNING: ADMIN still uses the legacy default password. Change it immediately.');
    }catch(e){}
  }
}

async function enforcePrivacyTombstones(queryable){
  try{
    const tombstones=(await queryable.query("SELECT identifier_hash,identifier_type,tenant_scope,created_at,released_at FROM privacy_tombstones")).rows;
    if(!tombstones.length)return 0;
    const users=(await queryable.query("SELECT id,login,email,fio,tenant_id,created_at FROM users WHERE upper(trim(login))<>'ADMIN'")).rows;
    let removed=0;
    for(const user of users){
      const scope=String(user.tenant_id||'');
      const candidates=[
        ['email',normalizeEmail(user.email)],
        ['login',String(user.login||'').trim().toLowerCase()],
        ['fio',String(user.fio||'').trim().toLowerCase()]
      ].filter(x=>x[1]);
      const matched=tombstones.some(t=>{
        if(String(t.tenant_scope||'')&&String(t.tenant_scope)!==scope)return false;
        if(t.released_at&&user.created_at&&new Date(user.created_at)>=new Date(t.released_at))return false;
        const candidate=candidates.find(x=>x[0]===String(t.identifier_type||''));
        if(!candidate)return false;
        const hash=crypto.createHash('sha256').update(candidate[1],'utf8').digest('hex');
        return hash===String(t.identifier_hash||'');
      });
      if(!matched)continue;
      await queryable.query('DELETE FROM email_codes WHERE user_id=$1',[user.id]);
      await queryable.query("DELETE FROM app_sessions WHERE (sess->'user'->>'id')::text=$1",[String(user.id)]);
      await queryable.query('DELETE FROM users WHERE id=$1',[user.id]);
      removed++;
    }
    if(removed)console.warn('Privacy tombstones removed resurrected accounts:',removed);
    return removed;
  }catch(err){console.error('Privacy tombstone enforcement failed:',err.message);return 0;}
}

async function runRetentionCleanup(){
  const securityDays=Math.min(3650,Math.max(30,Number(process.env.RETENTION_SECURITY_LOG_DAYS)||365));
  const backupDays=Math.min(3650,Math.max(1,Number(process.env.RETENTION_BACKUP_DAYS)||30));
  try{
    await pool.query('DELETE FROM email_codes WHERE expires_at<NOW()');
    await pool.query('DELETE FROM app_sessions WHERE expire<NOW()');
    await pool.query("DELETE FROM registration_invites WHERE (expires_at<NOW()-INTERVAL '30 days' OR revoked_at<NOW()-INTERVAL '30 days')");
    await pool.query("DELETE FROM security_log WHERE created_at<NOW()-($1::text||' days')::interval",[String(securityDays)]);
    await pool.query("DELETE FROM automatic_backups WHERE created_at<NOW()-($1::text||' days')::interval",[String(backupDays)]);
  }catch(err){console.error('Retention cleanup failed:',err.message);}
}

async function startServer(){
  try{
    await ensureDatabaseSchema();
    await enforcePrivacyTombstones(pool);
    await compliance.ensureComplianceSchema(pool);
    await initAdmin();
    databaseSchemaReady=true;
  }catch(err){
    databaseSchemaReady=false;
    console.error('Startup initialization failed:',err.message);
    process.exitCode=1;
    try{await pool.end();}catch(e){}
    return;
  }
  app.listen(PORT,'0.0.0.0',()=>{
    console.log('Server running on port '+PORT);
    console.log('Email verification: '+(EMAIL_VERIFY_ENABLED?'enabled':'disabled'));
    console.log('Platform MFA: '+(platformMfaEnabled()?'enabled':'disabled'));
    verifyMailTransport();
    startAutomaticBackups();
    runRetentionCleanup();
    setInterval(runRetentionCleanup,24*60*60*1000).unref();
  });
}
startServer();
