'use strict';

require('dotenv').config();
const {spawnSync}=require('child_process');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');

if(!process.env.DATABASE_URL){
  console.error('BLOCKER: DATABASE_URL is required');
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
    PGDATABASE:decodeURIComponent((u.pathname||'/').replace(/^\//,'')),
    PGSSLMODE:sslmode
  };
}
function sha256(file){
  const h=crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}
function isoCompact(){
  return new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');
}

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

console.log('=== PostgreSQL backup ===');
console.log('Output directory:',outDir);
console.log('Dump file:',path.basename(dumpPath));

const env=pgEnv(process.env.DATABASE_URL);
const args=[
  '--format=custom',
  '--compress=9',
  '--no-owner',
  '--no-privileges',
  '--verbose',
  '--file='+dumpPath
];
const result=spawnSync(pgDump,args,{env,encoding:'utf8',stdio:['ignore','pipe','pipe']});
if(result.status!==0){
  try{if(fs.existsSync(dumpPath))fs.unlinkSync(dumpPath);}catch(e){}
  console.error('BLOCKER: pg_dump failed.');
  console.error(String(result.stderr||result.stdout||'').slice(-6000));
  process.exit(2);
}

const stat=fs.statSync(dumpPath);
if(stat.size===0){
  console.error('BLOCKER: backup file is empty');
  process.exit(2);
}

const checksum=sha256(dumpPath);
const manifest={
  format:'postgresql-custom',
  created_at:new Date().toISOString(),
  dump_file:path.basename(dumpPath),
  size_bytes:stat.size,
  sha256:checksum,
  source_host:new URL(process.env.DATABASE_URL).hostname,
  source_database:decodeURIComponent(new URL(process.env.DATABASE_URL).pathname.replace(/^\//,'')),
  app:'salary-online'
};
fs.writeFileSync(manifestPath,JSON.stringify(manifest,null,2)+'\n',{mode:0o600});

console.log('Size:',stat.size,'bytes');
console.log('SHA-256:',checksum);
console.log('Manifest:',path.basename(manifestPath));
console.log('RESULT: BACKUP CREATED');
console.log('IMPORTANT: copy the dump + manifest to a second independent protected storage before encryption.');
