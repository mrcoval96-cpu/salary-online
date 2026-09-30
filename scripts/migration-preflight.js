'use strict';

require('dotenv').config();
const pg = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('BLOCKER: DATABASE_URL is required');
  process.exit(2);
}

function connectionOptions(){
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
    if(hosted && !allowPlaintext)throw new Error('Hosted PostgreSQL requires TLS unless DB_ALLOW_PLAINTEXT=true is explicitly set for a trusted private network.');
    return {hosted,pool:{}};
  }
  if(useTls){
    const rejectUnauthorized=explicitMode==='verify-full' ||
      String(process.env.DB_SSL_REJECT_UNAUTHORIZED || '').trim().toLowerCase()==='true' ||
      sslMode==='verify-full';
    return {hosted,pool:{ssl:{rejectUnauthorized}}};
  }
  if(hosted && !allowPlaintext){
    throw new Error('Hosted PostgreSQL requires TLS. Set DB_SSL=true or add sslmode=require to DATABASE_URL.');
  }
  return {hosted,pool:{}};
}

const criticalTables=[
  'users','employees','objects','organizations','salary_records','action_log',
  'object_responsibles','object_user_responsibles','closed_salary_periods',
  'automatic_backups','security_log','email_codes','employee_balances',
  'bank_statement_payments','organization_aliases'
];

const requiredColumns={
  users:['id','login','password','fio','role','organization','email','email_verified','permission_overrides','last_login_at','login_count'],
  employees:['id','fio','organization','employment_status','hr_profile','photo_data'],
  objects:['id','name','organization'],
  organizations:['id','name','full_name','inn','ogrn','legal_address','address','contacts'],
  salary_records:['id','employee_fio','object_name','organization','month','year','charge_date','deleted_at','deleted_by'],
  object_user_responsibles:['object_id','user_id'],
  employee_balances:['id','employee_fio','balance_date','amount','direction'],
  bank_statement_payments:['id','employee_fio','transaction_date','amount','transaction_key','allocations']
};

async function scalar(client,sql,params=[]){
  const r=await client.query(sql,params);
  return Number(r.rows[0]&&Object.values(r.rows[0])[0]||0);
}

async function main(){
  const cfg=connectionOptions();
  const dbUrl=new URL(process.env.DATABASE_URL);
  const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,...cfg.pool});
  const client=await pool.connect();
  const blockers=[];
  const warnings=[];
  const counts={};
  try{
    await client.query('BEGIN TRANSACTION READ ONLY');

    const version=(await client.query('SHOW server_version')).rows[0].server_version;
    console.log('=== Migration preflight (READ ONLY) ===');
    console.log('Database host:',dbUrl.hostname);
    console.log('Database name:',dbUrl.pathname.replace(/^\//,'')||'(default)');
    console.log('PostgreSQL:',version);
    console.log('Transport:',cfg.pool.ssl?'TLS':'local/trusted plaintext');

    const tablesResult=await client.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
    );
    const existing=new Set(tablesResult.rows.map(r=>r.table_name));
    for(const table of criticalTables){
      if(!existing.has(table))blockers.push('Missing table: '+table);
    }

    for(const [table,columns] of Object.entries(requiredColumns)){
      if(!existing.has(table))continue;
      const r=await client.query(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1",
        [table]
      );
      const present=new Set(r.rows.map(x=>x.column_name));
      for(const column of columns){
        if(!present.has(column))blockers.push('Missing column: '+table+'.'+column);
      }
    }

    for(const table of criticalTables){
      if(existing.has(table))counts[table]=await scalar(client,'SELECT COUNT(*) FROM "'+table+'"');
    }

    if(existing.has('organizations')){
      const dupNames=await scalar(client,`
        SELECT COUNT(*) FROM (
          SELECT lower(trim(name)) k FROM organizations
          WHERE trim(COALESCE(name,''))<>'' GROUP BY lower(trim(name)) HAVING COUNT(*)>1
        ) x
      `);
      if(dupNames)blockers.push('Duplicate organization names after normalization: '+dupNames);

      const dupInn=await scalar(client,`
        SELECT COUNT(*) FROM (
          SELECT inn FROM organizations WHERE trim(COALESCE(inn,''))<>'' GROUP BY inn HAVING COUNT(*)>1
        ) x
      `);
      if(dupInn)warnings.push('Duplicate organization INN values: '+dupInn);

      const dupOgrn=await scalar(client,`
        SELECT COUNT(*) FROM (
          SELECT ogrn FROM organizations WHERE trim(COALESCE(ogrn,''))<>'' GROUP BY ogrn HAVING COUNT(*)>1
        ) x
      `);
      if(dupOgrn)warnings.push('Duplicate organization OGRN values: '+dupOgrn);
    }

    for(const table of ['users','employees','objects','salary_records']){
      if(!existing.has(table)||!existing.has('organizations'))continue;
      const n=await scalar(client,`
        SELECT COUNT(*) FROM "${table}" t
        WHERE trim(COALESCE(t.organization,''))<>''
          AND NOT EXISTS (
            SELECT 1 FROM organizations o
            WHERE lower(trim(o.name))=lower(trim(t.organization))
          )
      `);
      if(n)blockers.push('Orphan organization references in '+table+': '+n);
    }

    if(existing.has('salary_records')&&existing.has('employees')){
      const emptyOrg=await scalar(client,
        "SELECT COUNT(*) FROM salary_records WHERE deleted_at IS NULL AND trim(COALESCE(organization,''))=''"
      );
      if(emptyOrg)blockers.push('Active salary records without organization: '+emptyOrg);

      const missingEmployees=await scalar(client,`
        SELECT COUNT(*) FROM salary_records s
        WHERE s.deleted_at IS NULL
          AND trim(COALESCE(s.employee_fio,''))<>''
          AND NOT EXISTS (
            SELECT 1 FROM employees e
            WHERE lower(trim(e.fio))=lower(trim(s.employee_fio))
              AND lower(trim(COALESCE(e.organization,'')))=lower(trim(COALESCE(s.organization,'')))
          )
      `);
      if(missingEmployees)warnings.push('Salary records without matching employee in the same organization: '+missingEmployees);
    }

    if(existing.has('salary_records')&&existing.has('objects')){
      const missingObjects=await scalar(client,`
        SELECT COUNT(*) FROM salary_records s
        WHERE s.deleted_at IS NULL
          AND trim(COALESCE(s.object_name,''))<>''
          AND NOT EXISTS (
            SELECT 1 FROM objects o
            WHERE lower(trim(o.name))=lower(trim(s.object_name))
              AND lower(trim(COALESCE(o.organization,'')))=lower(trim(COALESCE(s.organization,'')))
          )
      `);
      if(missingObjects)warnings.push('Salary records without matching object in the same organization: '+missingObjects);
    }

    if(existing.has('object_user_responsibles')&&existing.has('users')&&existing.has('objects')){
      const mismatched=await scalar(client,`
        SELECT COUNT(*) FROM object_user_responsibles r
        JOIN users u ON u.id=r.user_id
        JOIN objects o ON o.id=r.object_id
        WHERE lower(trim(COALESCE(u.organization,'')))<>lower(trim(COALESCE(o.organization,'')))
      `);
      if(mismatched)blockers.push('Object responsibles linked across different organizations: '+mismatched);

      const projectWithoutObjects=await scalar(client,`
        SELECT COUNT(*) FROM users u
        WHERE u.role='Руководитель проекта'
          AND upper(trim(u.login))<>'ADMIN'
          AND NOT EXISTS (SELECT 1 FROM object_user_responsibles r WHERE r.user_id=u.id)
      `);
      if(projectWithoutObjects)warnings.push('Project managers without assigned objects: '+projectWithoutObjects);
    }

    console.log('\nRecord counts:');
    Object.keys(counts).sort().forEach(k=>console.log('  '+k+': '+counts[k]));

    console.log('\nWarnings:');
    if(!warnings.length)console.log('  none');
    warnings.forEach(x=>console.log('  - '+x));

    console.log('\nBlockers:');
    if(!blockers.length)console.log('  none');
    blockers.forEach(x=>console.log('  - '+x));

    await client.query('ROLLBACK');

    if(blockers.length){
      console.error('\nRESULT: NOT READY FOR MIGRATION');
      process.exitCode=2;
    }else{
      console.log('\nRESULT: READY FOR BACKUP/RESTORE TEST');
    }
  }catch(err){
    try{await client.query('ROLLBACK');}catch(e){}
    console.error('BLOCKER: preflight failed:',err.message);
    process.exitCode=2;
  }finally{
    client.release();
    await pool.end();
  }
}

main().catch(err=>{
  console.error('BLOCKER:',err.message);
  process.exit(2);
});
