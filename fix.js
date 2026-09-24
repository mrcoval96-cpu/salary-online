require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function fix() {
  const hash = await bcrypt.hash('ADMIN', 10);
  await pool.query('UPDATE users SET password = $1 WHERE login = $2', [hash, 'ADMIN']);
  const res = await pool.query('SELECT login, password FROM users WHERE login = $1', ['ADMIN']);
  const valid = bcrypt.compareSync('ADMIN', res.rows[0].password);
  console.log('Hash updated, compare result:', valid);
  await pool.end();
}
fix().catch(e => console.error('Error:', e.message));

