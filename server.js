const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');

dotenv.config();

const app = express();
app.get('/health', (req, res) => res.status(200).send('OK'));

const PORT = process.env.PORT || 3000;

// PostgreSQL pool
const fs = require('fs');
const sslConfig = {};
try {
  if (process.env.DATABASE_URL.includes('twc1.net') || process.env.DATABASE_URL.includes('timeweb')) {
    sslConfig.ssl = { rejectUnauthorized: false };
  }
} catch(e) {}


const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ...sslConfig
});


async function ensureDatabaseSchema(){
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS charge_date DATE");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP");
  await pool.query("ALTER TABLE salary_records ADD COLUMN IF NOT EXISTS deleted_by TEXT");
  await pool.query("CREATE TABLE IF NOT EXISTS closed_salary_periods (month TEXT NOT NULL, year TEXT NOT NULL, closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, closed_by TEXT, PRIMARY KEY(month,year))");
  await pool.query("CREATE TABLE IF NOT EXISTS automatic_backups (id SERIAL PRIMARY KEY, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, data JSONB NOT NULL)");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_salary_records_deleted_at ON salary_records(deleted_at)");
  await pool.query("CREATE TABLE IF NOT EXISTS object_responsibles (object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (object_id, employee_id))");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_object_responsibles_employee ON object_responsibles(employee_id)");
  await pool.query("INSERT INTO object_responsibles (object_id,employee_id) SELECT o.id,e.id FROM objects o CROSS JOIN LATERAL regexp_split_to_table(COALESCE(o.responsible,''),',') AS part(name) JOIN employees e ON lower(trim(e.fio))=lower(trim(part.name)) WHERE trim(part.name)<>'' ON CONFLICT (object_id,employee_id) DO NOTHING");
}



pool.on('error', (err) => {
  console.error('PostgreSQL error:', err);
});

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true }
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// === AUTH MIDDLEWARE ===
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  next();
}

function requireSiteManager(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  if (req.session.user.role !== 'Руководитель сайта') {
    return res.status(403).json({ error: 'Доступ только для руководителя сайта' });
  }
  next();
}

// === AUTH ROUTES ===

// Login
app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
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
      object_name: user.object_name
    };
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [user.login, 'Вход в систему']);
    res.json(req.session.user);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  if (req.session.user) {
    pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [req.session.user.login, 'Выход из системы']);
  }
  req.session.destroy();
  res.json({ ok: true });
});

// Check session
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  res.json(req.session.user);
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
app.post('/api/register', async (req, res) => {
  const { fio, phone, password } = req.body;
  const normalizedFio=normalizeRegistrationFio(fio);
  const login=buildLoginFromFio(normalizedFio);
  const normalizedPhone=normalizePhone(phone);
  if (!normalizedFio || !phone || !login || !password) return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
  if (normalizedFio.split(' ').filter(Boolean).length < 3) return res.status(400).json({ error: 'Введите ФИО полностью: Фамилия Имя Отчество' });
  if (!normalizedPhone) return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE lower(login) = lower($1)', [login]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Логин уже занят' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (login, password, fio, phone, role) VALUES ($1, $2, $3, $4, $5)',
      [login, hash, normalizedFio, normalizedPhone, '']
    );
    res.json({ ok: true, message: 'Регистрация успешна. Обратитесь к руководителю сайта для назначения роли.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
});

// Recover password
app.post('/api/recover', async (req, res) => {
  const { login, phone } = req.body;
  const normalizedPhone=normalizePhone(phone);
  if(!normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1 AND phone = $2', [login, normalizedPhone]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    const user = result.rows[0];
    const newPass = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPass, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, user.id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)', [login, 'Восстановление пароля']);
    res.json({ ok: true, newPassword: newPass });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера: ' + err.message });
  }
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
  if (!fio) return res.status(400).json({ error: 'ФИО обязательно' });
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const result = await pool.query(
      'INSERT INTO employees (fio, organization, position, phone, birth_date, comments) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [fio, organization||'', position||'', normalizedPhone, birth_date||'', comments||'']
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
  const normalizedPhone=phone ? normalizePhone(phone) : '';
  if(phone && !normalizedPhone)return res.status(400).json({ error: 'Некорректный номер телефона. Формат: 7 (900) 900-90-90' });
  try {
    const result = await pool.query(
      'UPDATE employees SET fio=$1, organization=$2, position=$3, phone=$4, birth_date=$5, comments=$6 WHERE id=$7 RETURNING *',
      [fio, organization||'', position||'', normalizedPhone, birth_date||'', comments||'', id]
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
async function createAutomaticBackup(){
  const [employees,objects,orgs,salary,responsibles,periods]=await Promise.all([
    pool.query('SELECT * FROM employees ORDER BY id'),pool.query('SELECT * FROM objects ORDER BY id'),
    pool.query('SELECT * FROM organizations ORDER BY id'),pool.query('SELECT * FROM salary_records ORDER BY id'),
    pool.query('SELECT object_id,employee_id,created_at FROM object_responsibles ORDER BY object_id,employee_id'),
    pool.query('SELECT * FROM closed_salary_periods ORDER BY year,month')
  ]);
  const data={format:'salary-online-auto-backup',version:1,created_at:new Date().toISOString(),employees:employees.rows,objects:objects.rows,organizations:orgs.rows,salary:salary.rows,object_responsibles:responsibles.rows,closed_periods:periods.rows};
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

// === EXPORT/IMPORT ===
app.get('/api/export', requireSiteManager, async (req, res) => {
  try {
    const users = await pool.query('SELECT id, login, fio, phone, role, organization, object_name FROM users');
    const employees = await pool.query('SELECT * FROM employees');
    const objects = await pool.query('SELECT * FROM objects');
    const orgs = await pool.query('SELECT * FROM organizations');
    const salary = await pool.query('SELECT * FROM salary_records');
    const objectResponsibles = await pool.query('SELECT object_id, employee_id FROM object_responsibles');
    const log = await pool.query('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 500');
    res.json({users:users.rows, employees:employees.rows, objects:objects.rows, organizations:orgs.rows, salary:salary.rows, object_responsibles:objectResponsibles.rows, log:log.rows});
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
          'INSERT INTO employees (fio, organization, position, phone, birth_date, comments) VALUES ($1,$2,$3,$4,$5,$6)',
          [emp.fio||'', emp.organization||'', emp.position||'', emp.phone||'', emp.birth_date||'', emp.comments||'']
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
    res.json({ ok: true, message: 'Импорт завершён' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === FULL BACKUP / RESTORE ===
app.get('/api/backup', requireSiteManager, async (req, res) => {
  try {
    const [users, employees, objects, orgs, salary, objectResponsibles, log] = await Promise.all([
      pool.query('SELECT * FROM users ORDER BY id'),
      pool.query('SELECT * FROM employees ORDER BY id'),
      pool.query('SELECT * FROM objects ORDER BY id'),
      pool.query('SELECT * FROM organizations ORDER BY id'),
      pool.query('SELECT * FROM salary_records ORDER BY id'),
      pool.query('SELECT object_id, employee_id, created_at FROM object_responsibles ORDER BY object_id, employee_id'),
      pool.query('SELECT * FROM action_log ORDER BY id')
    ]);
    res.json({
      format: 'salary-online-backup',
      version: 1,
      created_at: new Date().toISOString(),
      users: users.rows, employees: employees.rows, objects: objects.rows,
      organizations: orgs.rows, salary: salary.rows,
      object_responsibles: objectResponsibles.rows, log: log.rows
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
    await client.query('DELETE FROM object_responsibles');
    await client.query('DELETE FROM objects');
    await client.query('DELETE FROM employees');
    await client.query('DELETE FROM organizations');
    await client.query('DELETE FROM action_log');
    await client.query('DELETE FROM users');

    for(const u of data.users){
      await client.query('INSERT INTO users (id,login,password,fio,phone,role,organization,object_name,role_history) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [u.id,u.login||'',u.password||'',u.fio||'',u.phone||'',u.role||'',u.organization||'',u.object_name||'',u.role_history||'[]']);
    }
    for(const e of (data.employees||[])){
      await client.query('INSERT INTO employees (id,fio,organization,position,phone,birth_date,comments) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [e.id,e.fio||'',e.organization||'',e.position||'',e.phone||'',e.birth_date||null,e.comments||'']);
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
    for(const l of (data.log||[])){
      await client.query('INSERT INTO action_log (id,user_login,action,created_at) VALUES ($1,$2,$3,$4)',
        [l.id,l.user_login||'',l.action||'',l.created_at||new Date()]);
    }
    for(const table of ['users','employees','objects','organizations','salary_records','action_log']){
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
    await pool.query('DELETE FROM action_log');
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
  try { await ensureDatabaseSchema(); } catch (err) { console.error('Schema initialization error:', err.message); }
  await initAdmin();
  startAutomaticBackups();
});
