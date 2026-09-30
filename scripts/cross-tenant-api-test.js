'use strict';

const assert=require('assert');

const base=String(process.env.TEST_BASE_URL||'').replace(/\/$/,'');
const cfg={
  a:{login:process.env.TEST_TENANT_A_LOGIN,password:process.env.TEST_TENANT_A_PASSWORD},
  b:{login:process.env.TEST_TENANT_B_LOGIN,password:process.env.TEST_TENANT_B_PASSWORD}
};
if(!base||!cfg.a.login||!cfg.a.password||!cfg.b.login||!cfg.b.password){
  console.error('BLOCKER: set TEST_BASE_URL, TEST_TENANT_A_LOGIN/PASSWORD and TEST_TENANT_B_LOGIN/PASSWORD.');
  console.error('Use synthetic test accounts in two different tenants. Never store these passwords in Git.');
  process.exit(2);
}

function cookieFrom(headers,current=''){
  const values=typeof headers.getSetCookie==='function'?headers.getSetCookie():[headers.get('set-cookie')].filter(Boolean);
  if(!values.length)return current;
  const map=new Map();
  for(const part of String(current||'').split(/;\s*/)){const i=part.indexOf('=');if(i>0)map.set(part.slice(0,i),part.slice(i+1));}
  for(const value of values){
    const first=String(value).split(';')[0],i=first.indexOf('=');
    if(i>0)map.set(first.slice(0,i),first.slice(i+1));
  }
  return [...map].map(([k,v])=>k+'='+v).join('; ');
}

async function createClient(account){
  let cookie='',csrf='';
  async function request(path,options={}){
    const method=String(options.method||'GET').toUpperCase();
    const headers={...(options.headers||{})};
    if(cookie)headers.Cookie=cookie;
    if(!['GET','HEAD','OPTIONS'].includes(method)&&csrf)headers['X-CSRF-Token']=csrf;
    if(options.body!==undefined){headers['Content-Type']='application/json';options.body=JSON.stringify(options.body);}
    const res=await fetch(base+path,{...options,method,headers,redirect:'manual'});
    cookie=cookieFrom(res.headers,cookie);
    let data=null;try{data=await res.json();}catch(e){data=await res.text().catch(()=>null);}
    return {res,data};
  }
  let r=await request('/api/csrf-token');
  assert.equal(r.res.status,200,'CSRF bootstrap failed');
  csrf=r.data.token;
  r=await request('/api/login',{method:'POST',body:{login:account.login,password:account.password}});
  if(r.res.status===202&&r.data&&r.data.mfa_required){
    throw new Error('Test account requires MFA. Use non-platform synthetic tenant accounts for cross-tenant tests.');
  }
  assert.equal(r.res.status,200,'Login failed for '+account.login+': '+JSON.stringify(r.data));
  r=await request('/api/csrf-token');
  assert.equal(r.res.status,200,'CSRF refresh failed after login');
  csrf=r.data.token;
  return {request,user:r.data};
}

function assertTenantRows(label,rows,me){
  if(!Array.isArray(rows))throw new Error(label+' response is not an array');
  for(const row of rows){
    if(row.tenant_id!=null)assert.equal(Number(row.tenant_id),Number(me.tenant_id),label+' leaked tenant_id '+row.tenant_id+' to tenant '+me.tenant_id);
    if(row.organization!=null&&String(row.organization).trim())assert.equal(String(row.organization).trim().toLowerCase(),String(me.organization||'').trim().toLowerCase(),label+' leaked organization '+row.organization);
  }
}

(async()=>{
  console.log('=== Cross-tenant API negative tests ===');
  const A=await createClient(cfg.a),B=await createClient(cfg.b);
  const am=(await A.request('/api/me')).data,bm=(await B.request('/api/me')).data;
  assert(am&&bm,'Unable to read session users');
  assert(am.tenant_id&&bm.tenant_id,'Both test users must have tenant_id');
  assert.notEqual(Number(am.tenant_id),Number(bm.tenant_id),'Test accounts must belong to different tenants');
  assert(!['Руководитель сайта'].includes(am.role),'Tenant A must not be a site-wide account');
  assert(!['Руководитель сайта'].includes(bm.role),'Tenant B must not be a site-wide account');

  const endpoints=['/api/employees','/api/objects','/api/salary'];
  const dataA={},dataB={};
  for(const endpoint of endpoints){
    const ar=await A.request(endpoint),br=await B.request(endpoint);
    if(ar.res.status===200){dataA[endpoint]=ar.data;assertTenantRows('A '+endpoint,ar.data,am);}
    else console.log('SKIP A '+endpoint+' status='+ar.res.status);
    if(br.res.status===200){dataB[endpoint]=br.data;assertTenantRows('B '+endpoint,br.data,bm);}
    else console.log('SKIP B '+endpoint+' status='+br.res.status);
  }

  const bEmployees=dataB['/api/employees']||[];
  if(!bEmployees.length)throw new Error('Tenant B needs at least one synthetic employee for IDOR test');
  const target=bEmployees[0];
  const idor=await A.request('/api/employees/'+encodeURIComponent(target.id)+'/profile');
  assert([403,404].includes(idor.res.status),'IDOR FAILED: tenant A received status '+idor.res.status+' for tenant B employee profile');

  console.log('Tenant A:',am.organization,'tenant_id='+am.tenant_id);
  console.log('Tenant B:',bm.organization,'tenant_id='+bm.tenant_id);
  console.log('IDOR employee profile:',idor.res.status,'PASS');
  console.log('RESULT: CROSS-TENANT NEGATIVE TESTS PASSED');
})().catch(err=>{
  console.error('RESULT: CROSS-TENANT NEGATIVE TESTS FAILED');
  console.error(err&&err.stack||err);
  process.exit(2);
});
