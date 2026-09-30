'use strict';

require('dotenv').config();
const {spawnSync}=require('child_process');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const pg=require('pg');

if(!process.env.DATABASE_URL){
  console.error('BLOCKER: DATABASE_URL is required');
  process.exit(2);
}

const criticalTables=[
  'users','employees','objects','organizations','salary_records','action_log',
  'object_responsibles','object_user_responsibles','closed_salary_periods',
  'automatic_backups','security_log','email_codes','employee_balances',
  'bank_statement_payments','organization_aliases'
];

function commandAvailable(command){
  const r=spawnSync(command,['--version'],{encoding:'utf8'});
  return r.status===0;
}
function pgEnv(urlString){
  const u=new URL(urlString);
  const sslmode=u.searchParams.get('sslmode')||(
    String(process.env.DB_SSL||'auto').toLowerCase()==='true' ||
    String(process.env.DB_SSL||'auto').toLowerCase()==='require' ||
    /timeweb|twc1\.net/i.test(u.hostname) ? 'require' : 'prefer'
  );
  return {
    ...process.env,
    PGHOST:u.hostname,
    PGPORT:u.port||'5432',
    PGUSER:decodeURIComponent(u.username||''),
    PGPASSWORD:decodeURIComponent(u.password||''),
    PGDATABASE:decodeURIComponent((u.pathname||'/').replace(/^\//,'')),
    PGSSLMODE:sslmode
  };
}
function sslOptions(urlString){
  const u=new URL(urlString);
  const sslmode=(u.searchParams.get('sslmode')||'').toLowerCase();
  const explicit=String(process.env.DB_SSL||'auto').toLowerCase();
  const tls=sslmode==='require'||sslmode==='verify-ca'||sslmode==='verify-full'||
    explicit==='true'||explicit==='require'||/timeweb|twc1\.net/i.test(u.hostname);
  return tls?{ssl:{rejectUnauthorized:sslmode==='verify-full'||String(process.env.DB_SSL_REJECT_UNAUTHORIZED||'').toLowerCase()==='true'}}:{};
}
function sha256(file){
  const h=crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}
function isoCompact(){
  return new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');
}

async function main(){
  const pgDump=process.env.PG_DUMP_BIN||'pg_dump';
  if(!commandAvailable(pgDump)){
    console.error('BLOCKER: pg_dump is not installed or PG_DUMP_BIN is incorrect.');
    console.error('Install PostgreSQL client tools in a trusted admin environment and run again.');
    process.exit(2);
  }

  const outDir=path.resolve(process.env.BACKUP_DIR||'secure-backups');
  fs.mkdirSync(outDir,{recursive:true,mode:0o700});

  const stamp=isoCompact();
  const base='salary-online-'+stamp;
  const dumpPath=path.join(outDir,base+'.dump');
  const manifestPath=path.join(outDir,base+'.manifest.json');

  const client=new pg.Client({connectionString:process.env.DATABASE_URL,...sslOptions(process.env.DATABASE_URL)});
  await client.connect();
  try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const snapshot=(await client.query('SELECT pg_export_snapshot() AS snapshot')).rows[0].snapshot;
    const version=(await client.query('SHOW server_version')).rows[0].server_version;
    const tablesResult=await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'");
    const existing=new Set(tablesResult.rows.map(r=>r.table_name));
    const counts={};
    for(const table of criticalTables){
      if(!existing.has(table)){counts[table]=null;continue;}
      const q=await client.query('SELECT COUNT(*)::bigint AS n FROM "'+table+'"');
      counts[table]=Number(q.rows[0].n);
    }

    console.log('=== PostgreSQL backup ===');
    console.log('Output directory:',outDir);
    console.log('Dump file:',path.basename(dumpPath));
    console.log('Snapshot:',snapshot);

    const args=[
      '--format=custom',
      '--compress=9',
      '--no-owner',
      '--no-privileges',
      '--serializable-deferrable',
      '--snapshot='+snapshot,
      '--verbose',
      '--file='+dumpPath
    ];
    const result=spawnSync(pgDump,args,{env:pgEnv(process.env.DATABASE_URL),encoding:'utf8',stdio:['ignore','pipe','pipe']});
    if(result.status!==0){
      try{if(fs.existsSync(dumpPath))fs.unlinkSync(dumpPath);}catch(e){}
      console.error('BLOCKER: pg_dump failed.');
      console.error(String(result.stderr||result.stdout||'').slice(-6000));
      process.exitCode=2;
      return;
    }

    const stat=fs.statSync(dumpPath);
    if(stat.size===0){
      console.error('BLOCKER: backup file is empty');
      process.exitCode=2;
      return;
    }

    const checksum=sha256(dumpPath);
    const source=new URL(process.env.DATABASE_URL);
    const manifest={
      format:'postgresql-custom',
      created_at:new Date().toISOString(),
      dump_file:path.basename(dumpPath),
      size_bytes:stat.size,
      sha256:checksum,
      source_host:source.hostname,
      source_database:decodeURIComponent(source.pathname.replace(/^\//,'')),
      postgresql_version:version,
      snapshot,
      table_counts:counts,
      app:'salary-online'
    };
    fs.writeFileSync(manifestPath,JSON.stringify(manifest,null,2)+'\n',{mode:0o600});

    console.log('Size:',stat.size,'bytes');
    console.log('SHA-256:',checksum);
    console.log('Manifest:',path.basename(manifestPath));
    console.log('\nSnapshot table counts:');
    Object.keys(counts).sort().forEach(k=>console.log('  '+k+': '+counts[k]));
    console.log('\nRESULT: BACKUP CREATED');
    console.log('IMPORTANT: copy the dump + manifest to a second independent protected storage before encryption.');
  }finally{
    try{await client.query('ROLLBACK');}catch(e){}
    await client.end();
  }
}

main().catch(err=>{
  console.error('BLOCKER:',err.message);
  process.exit(2);
});
