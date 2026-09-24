const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');

dotenv.config();

const app = express();
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
app.post('/api/register', async (req, res) => {
  const { fio, phone, login, password } = req.body;
  if (!login || !password || !fio) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }
  try {
    const existing = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Логин уже занят' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (login, password, fio, phone, role) VALUES ($1, $2, $3, $4, $5)',
      [login, hash, fio, phone || '', '']
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
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1 AND phone = $2', [login, phone]);
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
  try {
    const result = await pool.query(
      'INSERT INTO employees (fio, organization, position, phone, birth_date, comments) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [fio, organization||'', position||'', phone||'', birth_date||'', comments||'']
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
  try {
    const result = await pool.query(
      'UPDATE employees SET fio=$1, organization=$2, position=$3, phone=$4, birth_date=$5, comments=$6 WHERE id=$7 RETURNING *',
      [fio, organization||'', position||'', phone||'', birth_date||'', comments||'', id]
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
app.get('/api/objects', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM objects ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/objects', requireAuth, async (req, res) => {
  const { name, address, customer, organization, responsible } = req.body;
  if (!name) return res.status(400).json({ error: 'Наименование обязательно' });
  try {
    const result = await pool.query(
      'INSERT INTO objects (name, address, customer, organization, responsible) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [name, address||'', customer||'', organization||'', responsible||'']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/objects/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, address, customer, organization, responsible } = req.body;
  try {
    const result = await pool.query(
      'UPDATE objects SET name=$1, address=$2, customer=$3, organization=$4, responsible=$5 WHERE id=$6 RETURNING *',
      [name, address||'', customer||'', organization||'', responsible||'', id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/objects/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM objects WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

// === SALARY RECORDS ===
app.get('/api/salary', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM salary_records ORDER BY employee_fio, year, month');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/salary', requireAuth, async (req, res) => {
  const { employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO salary_records (employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [employee_fio||'', object_name||'', month||'', year||'', hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
       JSON.stringify(extra_charges||[]), JSON.stringify(payments||[]), total||0, paid||0]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Добавлена запись зарплаты: ' + employee_fio]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/salary/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid } = req.body;
  try {
    const result = await pool.query(
      `UPDATE salary_records SET employee_fio=$1, object_name=$2, month=$3, year=$4, hour_rate=$5, hours=$6,
       per_diem_days=$7, per_diem_rate=$8, extra_charges=$9, payments=$10, total=$11, paid=$12 WHERE id=$13 RETURNING *`,
      [employee_fio||'', object_name||'', month||'', year||'', hour_rate||0, hours||0, per_diem_days||0, per_diem_rate||0,
       JSON.stringify(extra_charges||[]), JSON.stringify(payments||[]), total||0, paid||0, id]
    );
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Изменена запись зарплаты ID=' + id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/salary/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM salary_records WHERE id=$1', [req.params.id]);
    await pool.query('INSERT INTO action_log (user_login, action) VALUES ($1, $2)',
      [req.session.user.login, 'Удалена запись зарплаты ID=' + req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    const log = await pool.query('SELECT * FROM action_log ORDER BY created_at DESC LIMIT 500');
    res.json({
      users: users.rows, employees: employees.rows, objects: objects.rows,
      organizations: orgs.rows, salary: salary.rows, log: log.rows
    });
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
          `INSERT INTO salary_records (employee_fio, object_name, month, year, hour_rate, hours, per_diem_days, per_diem_rate, extra_charges, payments, total, paid)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [rec.employee_fio||'', rec.object_name||'', rec.month||'', rec.year||'', rec.hour_rate||0, rec.hours||0,
           rec.per_diem_days||0, rec.per_diem_rate||0, rec.extra_charges||'[]', rec.payments||'[]', rec.total||0, rec.paid||0]
        );
      }
    }
    res.json({ ok: true, message: 'Импорт завершён' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  await initAdmin();
});
