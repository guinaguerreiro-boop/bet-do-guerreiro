const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '20kb' }));
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'https://bet-do-guerreiro.onrender.com';
app.use(cors({ origin: allowedOrigin.split(',').map(v => v.trim()), methods: ['GET','POST'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false }));

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
}) : null;

async function initializeDatabase() {
  if (!pool) { console.warn('DATABASE_URL ausente; API iniciada em modo de configuração.'); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY,
      display_name VARCHAR(40) NOT NULL,
      email VARCHAR(254) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(16) NOT NULL DEFAULT 'player' CHECK (role IN ('player','admin')),
      points INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS activities (
      id BIGSERIAL PRIMARY KEY,
      player_id BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      activity_name VARCHAR(80) NOT NULL,
      points_awarded INTEGER NOT NULL DEFAULT 10 CHECK (points_awarded >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS activities_player_created_idx ON activities(player_id, created_at DESC);
  `);
  console.log('PostgreSQL conectado; tabelas players e activities verificadas.');
}
function requireConfig(res) {
  if (!pool) { res.status(503).json({ error: 'Banco de dados ainda não configurado.' }); return false; }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) { res.status(503).json({ error: 'Autenticação ainda não configurada.' }); return false; }
  return true;
}
function auth(req,res,next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  if (!token) return res.status(401).json({error:'Autenticação necessária.'});
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Sessão inválida ou expirada.'}); }
}
app.get('/health', async (_req,res) => {
  let database = 'not_configured';
  if (pool) { try { await pool.query('SELECT 1'); database = 'connected'; } catch { database = 'unavailable'; } }
  res.status(200).json({status:'ok', service:'bet-do-guerreiro-api', database});
});
app.post('/api/auth/register', async (req,res) => {
  if (!requireConfig(res)) return;
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || name.length > 40 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 72)
      return res.status(400).json({error:'Informe nome, e-mail válido e senha com 10 a 72 caracteres.'});
    const hash = await bcrypt.hash(password, 12);
    const role = process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL.toLowerCase() ? 'admin' : 'player';
    const q = await pool.query('INSERT INTO players(display_name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,display_name,email,role,points,created_at',[name,email,hash,role]);
    const player = q.rows[0];
    const token = jwt.sign({sub:String(player.id),role:player.role},process.env.JWT_SECRET,{expiresIn:'7d'});
    res.status(201).json({token,player});
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({error:'Este e-mail já está cadastrado.'});
    console.error('register failed',e.message); res.status(500).json({error:'Não foi possível concluir o cadastro.'});
  }
});
app.post('/api/auth/login', async (req,res) => {
  if (!requireConfig(res)) return;
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT id,display_name,email,password_hash,role,points,created_at FROM players WHERE email=$1',[email]);
    const p = q.rows[0];
    if (!p || !(await bcrypt.compare(password,p.password_hash))) return res.status(401).json({error:'E-mail ou senha incorretos.'});
    const token = jwt.sign({sub:String(p.id),role:p.role},process.env.JWT_SECRET,{expiresIn:'7d'});
    delete p.password_hash;
    res.json({token,player:p});
  } catch (e) { console.error('login failed',e.message); res.status(500).json({error:'Não foi possível entrar.'}); }
});
app.get('/api/me',auth,async(req,res)=>{
  if(!requireConfig(res))return;
  const q=await pool.query('SELECT id,display_name,email,role,points,created_at FROM players WHERE id=$1',[req.user.sub]);
  if(!q.rowCount)return res.status(404).json({error:'Jogador não encontrado.'});
  res.json({player:q.rows[0]});
});
app.post('/api/activities',auth,async(req,res)=>{
  if(!requireConfig(res))return;
  const name=String(req.body.name||'').trim();
  if(name.length<2||name.length>80)return res.status(400).json({error:'Nome de atividade inválido.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const a=await client.query('INSERT INTO activities(player_id,activity_name,points_awarded) VALUES($1,$2,10) RETURNING id,activity_name,points_awarded,created_at',[req.user.sub,name]);
    const p=await client.query('UPDATE players SET points=points+10 WHERE id=$1 RETURNING points',[req.user.sub]);
    await client.query('COMMIT');
    res.status(201).json({activity:a.rows[0],points:p.rows[0].points});
  }catch(e){await client.query('ROLLBACK');console.error('activity failed',e.message);res.status(500).json({error:'Não foi possível registrar a atividade.'});}
  finally{client.release();}
});
app.get('/api/activities',auth,async(req,res)=>{
  if(!requireConfig(res))return;
  const q=await pool.query('SELECT id,activity_name,points_awarded,created_at FROM activities WHERE player_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.sub]);
  res.json({activities:q.rows});
});
app.get('/api/admin/players',auth,async(req,res)=>{
  if(req.user.role!=='admin')return res.status(403).json({error:'Acesso restrito ao administrador.'});
  if(!requireConfig(res))return;
  const q=await pool.query('SELECT id,display_name,email,role,points,created_at FROM players ORDER BY points DESC,created_at ASC LIMIT 100',[ ]);
  res.json({players:q.rows});
});
app.use((err,_req,res,_next)=>{console.error('request error',err.message);res.status(400).json({error:'Requisição inválida.'});});
const port=process.env.PORT||10000;
app.listen(port,'0.0.0.0',()=>console.log('BET DO GUERREIRO API listening on '+port));
initializeDatabase().catch(e=>console.error('database initialization failed:',e.message));
