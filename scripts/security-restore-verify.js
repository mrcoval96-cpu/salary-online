'use strict';

require('dotenv').config();
const {spawnSync}=require('child_process');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const pg=require('pg');

const dumpArg=process.argv[2];
if(!process.env.RESTORE_DATABASE_URL){
  console.error('BLOCKER: RESTORE_DATABASE_URL is required');
  process.exit(2);
}
if(!dumpArg){
  console.error('Usage: npm run restore:verify -- secure-backups/<file>.dump');
  process.exit(2);
}
if(String(process.env.CONFIRM_TEST_RESTORE||'').toLowerCase()!=='yes'){
  console.error('BLOCKER: set CONFIRM_TEST_RESTORE=yes to confirm the target DB is disposable test storage.');
  process.exit(2);
}

function safeIdentity(urlString){
  const u=new URL(urlString);
  return [u.hostname.toLowerCase(),u.port||'5432',decodeURIComponent(u.pathname.replace(/^\//,''))].join('|');
}
if(process.env.DATABASE_URL && safeIdentity(process.env.DATABASE_URL)===safeIdentity(process.env.RESTORE_DATABASE_URL)){
  console.error('BLOCKER: RESTORE_DATABASE_URL points to the same host/port/database as production.');
  process.exit(2);
}
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
    PGDATABASE:decodeURIComponent(u.pathname.replace(/^\//,'')),
    PGSSLMODE:sslmode
  };
}
function sha256(file){
  const h=crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}
function sslOptions(urlString){
  const u=new URL(urlString);
  const sslmode=(u.searchParams.get('sslmode')||'').toLowerCase();
  const explicit=String(process.env.DB_SSL||'auto').toLowerCase();
  const tls=sslmode==='require'||sslmode==='verify-ca'||sslmode==='verify-full'||
    explicit==='true'||explicit==='require'||/timeweb|twc1\.net/i.test(u.hostname);
  return tls?{ssl:{rejectUnauthorized:sslmode==='verify-full'||String(process.env.DB_SSL_REJECT_UNAUTHORIZED||'').toLowerCase()==='true'}}:{};
}
async function tableCounts(url,tables){
  const client=new pg.Client({connectionString:url,...sslOptions(url)});
  await client.connect();
  try{
    const existing=new Set((await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")).rows.map(r=>r.table_name));
    const counts={};
    for(const table of tables){
      if(!existing.has(table)){counts[table]=null;continue;}
      const r=await client.query('SELECT COUNT(*)::bigint AS n FROM "'+table+'"');
      counts[table]=Number(r.rows[0].n);
    }
    return counts;
  }finally{await client.end();}
}

(async()=>{
  const dumpPath=path.resolve(dumpArg);
  if(!fs.existsSync(dumpPath)){
    console.error('BLOCKER: dump file not found:',dumpPath);
    process.exit(2);
  }
  const manifestPath=dumpPath.replace(/\.dump$/,'')+'.manifest.json';
  if(!fs.existsSync(manifestPath)){
    console.error('BLOCKER: manifest file not found:',manifestPath);
    process.exit(2);
  }
  const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  const actualHash=sha256(dumpPath);
  if(actualHash!==manifest.sha256){
    console.error('BLOCKER: backup checksum mismatch');
    process.exit(2);
  }
  if(!manifest.table_counts || typeof manifest.table_counts!=='object'){
    console.error('BLOCKER: manifest does not contain snapshot table counts');
    process.exit(2);
  }

  const pgRestore=process.env.PG_RESTORE_BIN||'pg_restore';
  if(!commandAvailable(pgRestore)){
    console.error('BLOCKER: pg_restore is not installed or PG_RESTORE_BIN is incorrect.');
    process.exit(2);
  }

  console.log('=== Restore verification ===');
  console.log('Dump:',path.basename(dumpPath));
  console.log('Checksum: OK');
  console.log('Snapshot created at:',manifest.created_at);

  const args=[
    '--clean',
    '--if-exists',
    '--no-owner',
    '--no-privileges',
    '--exit-on-error',
    '--verbose',
    dumpPath
  ];
  const result=spawnSync(pgRestore,args,{env:pgEnv(process.env.RESTORE_DATABASE_URL),encoding:'utf8',stdio:['ignore','pipe','pipe']});
  if(result.status!==0){
    console.error('BLOCKER: pg_restore failed.');
    console.error(String(result.stderr||result.stdout||'').slice(-6000));
    process.exit(2);
  }

  const restored=await tableCounts(process.env.RESTORE_DATABASE_URL,Object.keys(manifest.table_counts));
  const mismatches=[];
  for(const [table,expected] of Object.entries(manifest.table_counts)){
    if(restored[table]!==expected)mismatches.push(table+': backup='+expected+', restored='+restored[table]);
  }

  console.log('\nRecord count comparison:');
  Object.keys(manifest.table_counts).sort().forEach(table=>{
    console.log('  '+table+': backup='+manifest.table_counts[table]+', restored='+restored[table]);
  });

  if(mismatches.length){
    console.error('\nBLOCKER: restored database differs from backup snapshot:');
    mismatches.forEach(x=>console.error('  - '+x));
    process.exit(2);
  }

  console.log('\nRESULT: RESTORE VERIFIED');
  console.log('The dump checksum is valid and critical table counts exactly match the backup snapshot.');
})().catch(err=>{
  console.error('BLOCKER:',err.message);
  process.exit(2);
});
