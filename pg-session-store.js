'use strict';

const session=require('express-session');

class PgSessionStore extends session.Store{
  constructor(pool){
    super();
    this.pool=pool;
    this.cleanupTimer=setInterval(()=>{
      this.pool.query('DELETE FROM app_sessions WHERE expire<=NOW()').catch(()=>{});
    },60*60*1000);
    if(this.cleanupTimer.unref)this.cleanupTimer.unref();
  }
  get(sid,callback){
    this.pool.query("SELECT sess FROM app_sessions WHERE sid=$1 AND expire>NOW()",[sid])
      .then(r=>callback(null,r.rows.length?r.rows[0].sess:null))
      .catch(err=>callback(err));
  }
  set(sid,sess,callback){
    let expire=new Date(Date.now()+8*60*60*1000);
    if(sess&&sess.cookie){
      if(sess.cookie.expires){
        const parsed=new Date(sess.cookie.expires);
        if(!Number.isNaN(parsed.getTime()))expire=parsed;
      }else if(Number(sess.cookie.maxAge)>0){
        expire=new Date(Date.now()+Number(sess.cookie.maxAge));
      }
    }
    this.pool.query(
      `INSERT INTO app_sessions(sid,sess,expire,updated_at)
       VALUES($1,$2::jsonb,$3,NOW())
       ON CONFLICT(sid) DO UPDATE SET sess=EXCLUDED.sess,expire=EXCLUDED.expire,updated_at=NOW()`,
      [sid,JSON.stringify(sess||{}),expire]
    ).then(()=>callback&&callback(null)).catch(err=>callback&&callback(err));
  }
  destroy(sid,callback){
    this.pool.query('DELETE FROM app_sessions WHERE sid=$1',[sid])
      .then(()=>callback&&callback(null)).catch(err=>callback&&callback(err));
  }
  touch(sid,sess,callback){
    let expire=new Date(Date.now()+8*60*60*1000);
    if(sess&&sess.cookie&&Number(sess.cookie.maxAge)>0)expire=new Date(Date.now()+Number(sess.cookie.maxAge));
    this.pool.query('UPDATE app_sessions SET expire=$2,updated_at=NOW() WHERE sid=$1',[sid,expire])
      .then(()=>callback&&callback(null)).catch(err=>callback&&callback(err));
  }
  clear(callback){
    this.pool.query('DELETE FROM app_sessions').then(()=>callback&&callback(null)).catch(err=>callback&&callback(err));
  }
  length(callback){
    this.pool.query('SELECT COUNT(*)::int AS n FROM app_sessions WHERE expire>NOW()')
      .then(r=>callback(null,Number(r.rows[0].n||0))).catch(err=>callback(err));
  }
}

module.exports=PgSessionStore;
