'use strict';

require('dotenv').config();
const pg=require('pg');
const bcrypt=require('bcryptjs');
const fs=require('fs');
const path=require('path');

if(!process.env.DATABASE_URL){
  console.error('BLOCKER: DATABASE_URL is required');
  process.exit(2);
}

const criticalTables=[
  'users','employees','objects','organizations','salary_records','action_log',
  'object_responsibles','object_user_responsibles','closed_salary_periods',
  'automatic_backups','security_log','email_codes','employee_balances',
  'bank_statement_payments','organization_aliases','processing_purposes','legal_documents',
  'consents','marketing_suppression','data_subject_requests','audit_events','incidents',
  'admin_access_sessions','exports','deletion_jobs','retention_rules','subprocessors_integrations','app_sessions'
];

const requiredColumns={
  users:['id','login','password','fio','role','organization','tenant_id','status','email','email_verified','permission_overrides','last_login_at','login_count'],
  employees:['id','fio','organization','tenant_id','employment_status','hr_profile','photo_data'],
  objects:['id','name','organization','tenant_id'],
  organizations:['id','name','full_name','inn','ogrn','legal_address','address','contacts'],
  salary_records:['id','employee_fio','object_name','organization','tenant_id','month','year','charge_date','extra_charges','payments','deleted_at','deleted_by'],
  object_user_responsibles:['object_id','user_id'],
  employee_balances:['id','employee_fio','balance_date','amount','direction'],
  bank_statement_payments:['id','employee_fio','tenant_id','transaction_date','amount','transaction_key','allocations'],
  consents:['consent_id','tenant_id','user_id','purpose_id','document_version','document_hash','given_at','withdrawn_at','status'],
  data_subject_requests:['request_id','tenant_id','request_type','received_at','due_at','status'],
  audit_events:['event_id','occurred_at','actor_id','tenant_id','action','correlation_id'],
  incidents:['incident_id','severity','detected_at','confirmed_at','due_24h','due_72h','status'],
  app_sessions:['sid','sess','expire','updated_at']
};

function sslOptions(urlString){
  const u=new URL(urlString);
  const sslmode=(u.searchParams.get('sslmode')||'').toLowerCase();
  const explicit=String(process.env.DB_SSL||'auto').toLowerCase();
  const allowPlain=String(process.env.DB_ALLOW_PLAINTEXT||'').toLowerCase()==='true';
  const hosted=!['localhost','127.0.0.1','::1'].includes(u.hostname);
  const tls=sslmode==='require'||sslmode==='verify-ca'||sslmode==='verify-full'||
    explicit==='true'||explicit==='require'||explicit==='verify-full'||/timeweb|twc1\.net/i.test(u.hostname);
  if(hosted&&!tls&&!allowPlain)throw new Error('Hosted PostgreSQL requires TLS. Set DB_SSL=true or sslmode=require.');
  return tls?{ssl:{rejectUnauthorized:sslmode==='verify-full'||explicit==='verify-full'||String(process.env.DB_SSL_REJECT_UNAUTHORIZED||'').toLowerCase()==='true'}}:{};
}
async function scalar(client,sql,params=[]){
  const r=await client.query(sql,params);
  return Number(r.rows[0]&&Object.values(r.rows[0])[0]||0);
}
async function validateJsonText(client){
  const issues=[];
  let lastId=0;
  while(true){
    const r=await client.query(
      'SELECT id,extra_charges,payments FROM salary_records WHERE id>$1 ORDER BY id LIMIT 500',
      [lastId]
    );
    if(!r.rows.length)break;
    for(const row of r.rows){
      lastId=row.id;
      for(const field of ['extra_charges','payments']){
        const value=row[field];
        if(value===null||String(value).trim()==='')continue;
        try{JSON.parse(String(value));}
        catch(e){issues.push('salary_records.id='+row.id+' invalid '+field+' JSON');}
      }
    }
    if(r.rows.length<500)break;
  }
  return issues;
}

async function main(){
  const url=new URL(process.env.DATABASE_URL);
  const client=new pg.Client({connectionString:process.env.DATABASE_URL,...sslOptions(process.env.DATABASE_URL)});
  const blockers=[];
  const warnings=[];
  const counts={};
  await client.connect();
  try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');

    const version=(await client.query('SHOW server_version')).rows[0].server_version;
    console.log('=== Security Stage 1 preflight (READ ONLY) ===');
    console.log('Database host:',url.hostname);
    console.log('Database name:',decodeURIComponent(url.pathname.replace(/^\//,'')));
    console.log('PostgreSQL:',version);

    const tablesResult=await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'");
    const existing=new Set(tablesResult.rows.map(r=>r.table_name));

    for(const table of criticalTables){
      if(!existing.has(table))blockers.push('Missing table: '+table);
    }

    for(const [table,cols] of Object.entries(requiredColumns)){
      if(!existing.has(table))continue;
      const r=await client.query(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1",
        [table]
      );
      const present=new Set(r.rows.map(x=>x.column_name));
      for(const col of cols){
        if(!present.has(col))blockers.push('Missing column: '+table+'.'+col);
      }
    }

    for(const table of criticalTables){
      if(existing.has(table))counts[table]=await scalar(client,'SELECT COUNT(*) FROM "'+table+'"');
    }

    for(const table of ['users','employees','objects','salary_records']){
      if(!existing.has(table))continue;
      const n=await scalar(client,`SELECT COUNT(*) FROM "${table}" WHERE trim(COALESCE(organization,''))<>'' AND tenant_id IS NULL`);
      if(n)blockers.push('Tenant IDs missing after organization backfill in '+table+': '+n);
    }

    // P0 configuration and transport controls.
    const hosted=!['localhost','127.0.0.1','::1'].includes(url.hostname);
    if(hosted){
      const sslResult=await client.query("SELECT COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),FALSE) AS ssl");
      if(!sslResult.rows[0].ssl)blockers.push('Hosted PostgreSQL connection is not using TLS');
    }
    if(String(process.env.DATA_REGION||'').trim().toUpperCase()!=='RU')blockers.push('DATA_REGION must be explicitly set to RU for the Russian production contour');
    for(const key of ['LEGAL_OPERATOR_NAME','LEGAL_OPERATOR_INN','LEGAL_OPERATOR_OGRNIP','LEGAL_PRIVACY_EMAIL']){
      if(!String(process.env[key]||'').trim())blockers.push('Missing legal operator setting: '+key);
    }
    if(String(process.env.PLATFORM_MFA_ENABLED||'false').trim().toLowerCase()!=='true')blockers.push('Platform administrator MFA is not enabled (PLATFORM_MFA_ENABLED=true required for P0)');
    if(String(process.env.SESSION_SECRET||'').length<32)blockers.push('SESSION_SECRET must be configured with at least 32 characters');

    if(existing.has('users')){
      const admin=await client.query("SELECT password,email FROM users WHERE upper(trim(login))='ADMIN' LIMIT 1");
      if(admin.rows.length){
        try{if(await bcrypt.compare('ADMIN',admin.rows[0].password))blockers.push('Technical ADMIN still uses the legacy default password ADMIN');}catch(e){}
        if(String(process.env.PLATFORM_MFA_ENABLED||'false').trim().toLowerCase()==='true' && !String(admin.rows[0].email||process.env.PLATFORM_ADMIN_MFA_EMAIL||'').trim()){
          blockers.push('Platform MFA is enabled but ADMIN has no MFA email');
        }
      }
    }

    if(existing.has('legal_documents')){
      for(const type of ['privacy_policy','pd_consent','terms']){
        const n=await scalar(client,"SELECT COUNT(*) FROM legal_documents WHERE doc_type=$1 AND active=TRUE",[type]);
        if(n!==1)blockers.push('Exactly one active legal document is required for '+type+'; found '+n);
      }
    }
    if(existing.has('consents')&&existing.has('legal_documents')){
      const orphanConsent=await scalar(client,`
        SELECT COUNT(*) FROM consents c
        WHERE NOT EXISTS(
          SELECT 1 FROM legal_documents d
          WHERE d.doc_type=c.document_type
            AND d.version=c.document_version
            AND d.content_hash=c.document_hash
        )
      `);
      if(orphanConsent)blockers.push('Consent evidence references missing or changed legal document versions: '+orphanConsent);
    }

    for(const table of ['users','employees','objects','salary_records']){
      if(!existing.has(table)||!existing.has('organizations'))continue;
      const n=await scalar(client,`
        SELECT COUNT(*) FROM "${table}" t
        JOIN organizations o ON o.id=t.tenant_id
        WHERE t.tenant_id IS NOT NULL
          AND trim(COALESCE(t.organization,''))<>''
          AND lower(trim(t.organization))<>lower(trim(o.name))
      `);
      if(n)blockers.push('Tenant mismatch in '+table+': '+n);
    }
    for(const table of ['employee_balances','bank_statement_payments']){
      if(!existing.has(table)||!existing.has('employees'))continue;
      const n=await scalar(client,`
        SELECT COUNT(*) FROM "${table}" t
        JOIN employees e ON e.id=t.employee_id
        WHERE t.employee_id IS NOT NULL
          AND COALESCE(t.tenant_id,-1)<>COALESCE(e.tenant_id,-1)
      `);
      if(n)blockers.push('Employee tenant mismatch in '+table+': '+n);
    }

    if(existing.has('audit_events')){
      const triggerCount=await scalar(client,"SELECT COUNT(*) FROM pg_trigger WHERE tgrelid='audit_events'::regclass AND NOT tgisinternal AND tgname IN ('trg_audit_events_no_update','trg_audit_events_no_delete')");
      if(triggerCount!==2)blockers.push('Append-only audit protection triggers are missing');
    }

    // Static browser egress inventory: no hidden external resources should go unnoticed.
    try{
      const html=fs.readFileSync(path.join(__dirname,'..','public','index.html'),'utf8');
      const external=[...html.matchAll(/<(?:script|link)[^>]+(?:src|href)=["'](https?:\/\/[^"']+)/gi)].map(m=>m[1]);
      if(external.length)warnings.push('External browser assets require documented data-egress review: '+[...new Set(external)].join(', '));
    }catch(e){warnings.push('Could not inspect public/index.html for external browser assets');}

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

    if(existing.has('employees')){
      const dupEmployees=await scalar(client,`
        SELECT COUNT(*) FROM (
          SELECT lower(trim(fio)) fio_key,lower(trim(COALESCE(organization,''))) org_key
          FROM employees
          WHERE trim(COALESCE(fio,''))<>''
          GROUP BY lower(trim(fio)),lower(trim(COALESCE(organization,'')))
          HAVING COUNT(*)>1
        ) x
      `);
      if(dupEmployees)warnings.push('Duplicate employee FIO inside the same organization: '+dupEmployees);
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

    if(existing.has('users')){
      const missingOrgUsers=await scalar(client,`
        SELECT COUNT(*) FROM users
        WHERE upper(trim(login))<>'ADMIN'
          AND role<>'Руководитель сайта'
          AND trim(COALESCE(organization,''))=''
      `);
      if(missingOrgUsers)warnings.push('Non-site users without organization: '+missingOrgUsers);
    }

    if(existing.has('salary_records')){
      const activeNoOrg=await scalar(client,
        "SELECT COUNT(*) FROM salary_records WHERE deleted_at IS NULL AND trim(COALESCE(organization,''))=''"
      );
      if(activeNoOrg)blockers.push('Active salary records without organization: '+activeNoOrg);

      const jsonIssues=await validateJsonText(client);
      if(jsonIssues.length){
        blockers.push('Invalid JSON text fields in salary_records: '+jsonIssues.length);
        warnings.push(...jsonIssues.slice(0,20));
        if(jsonIssues.length>20)warnings.push('...and '+(jsonIssues.length-20)+' more invalid JSON rows');
      }
    }

    if(existing.has('salary_records')&&existing.has('employees')){
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

    if(blockers.length){
      console.error('\nRESULT: SECURITY STAGE 1 NOT READY');
      process.exitCode=2;
    }else{
      console.log('\nRESULT: SECURITY STAGE 1 PASSED');
    }
  }finally{
    try{await client.query('ROLLBACK');}catch(e){}
    await client.end();
  }
}

main().catch(err=>{
  console.error('BLOCKER:',err.message);
  process.exit(2);
});
