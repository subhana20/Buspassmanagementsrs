'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT || 4000);
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const UPLOADS = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA,{recursive:true}); fs.mkdirSync(UPLOADS,{recursive:true});
const db = new Database(path.join(DATA,'bpms.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 phone TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'passenger',
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS routes(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE,
 origin TEXT NOT NULL, destination TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS pass_types(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, duration_days INTEGER NOT NULL,
 fare REAL NOT NULL, description TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS applications(
 id INTEGER PRIMARY KEY AUTOINCREMENT, application_no TEXT NOT NULL UNIQUE,
 user_id INTEGER NOT NULL REFERENCES users(id), pass_type_id INTEGER NOT NULL REFERENCES pass_types(id),
 route_id INTEGER NOT NULL REFERENCES routes(id), duration_days INTEGER NOT NULL, amount REAL NOT NULL,
 purpose TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
 reviewer_id INTEGER REFERENCES users(id), review_remarks TEXT DEFAULT '',
 reviewed_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, is_renewal INTEGER DEFAULT 0,
 previous_pass_id INTEGER
);
CREATE TABLE IF NOT EXISTS documents(
 id INTEGER PRIMARY KEY AUTOINCREMENT, application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL,
 uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments(
 id INTEGER PRIMARY KEY AUTOINCREMENT, application_id INTEGER NOT NULL REFERENCES applications(id),
 amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', transaction_ref TEXT UNIQUE,
 method TEXT DEFAULT 'manual', paid_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS passes(
 id INTEGER PRIMARY KEY AUTOINCREMENT, pass_no TEXT NOT NULL UNIQUE, application_id INTEGER NOT NULL REFERENCES applications(id),
 user_id INTEGER NOT NULL REFERENCES users(id), pass_type_id INTEGER NOT NULL REFERENCES pass_types(id),
 route_id INTEGER NOT NULL REFERENCES routes(id), valid_from TEXT NOT NULL, valid_until TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'active', qr_data TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pass_history(
 id INTEGER PRIMARY KEY AUTOINCREMENT, pass_id INTEGER NOT NULL REFERENCES passes(id),
 old_status TEXT, new_status TEXT NOT NULL, changed_by INTEGER REFERENCES users(id),
 remarks TEXT DEFAULT '', changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS password_resets(\n id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP\n);\nCREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity TEXT, entity_id TEXT, ip TEXT, details TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_pass_user ON passes(user_id);
CREATE INDEX IF NOT EXISTS idx_pass_number ON passes(pass_no);
`);
const count = db.prepare('SELECT COUNT(*) n FROM users').get().n;
if (!count) {
 const hash = bcrypt.hashSync('Admin@123',12);
 db.prepare('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)')
   .run('System Administrator','admin@bpms.local','9999999999',hash,'admin');
 db.prepare('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)')
   .run('Pass Staff','staff@bpms.local','9999999998',bcrypt.hashSync('Staff@123',12),'staff');
 db.prepare('INSERT INTO routes(name,code,origin,destination) VALUES(?,?,?,?)').run('City Central - University','R001','City Central','University');
 db.prepare('INSERT INTO routes(name,code,origin,destination) VALUES(?,?,?,?)').run('Railway Station - IT Park','R002','Railway Station','IT Park');
 db.prepare('INSERT INTO routes(name,code,origin,destination) VALUES(?,?,?,?)').run('Airport - City Centre','R003','Airport','City Centre');
 db.prepare('INSERT INTO pass_types(name,duration_days,fare,description) VALUES(?,?,?,?)').run('Monthly Pass',30,900,'Valid for 30 days');
 db.prepare('INSERT INTO pass_types(name,duration_days,fare,description) VALUES(?,?,?,?)').run('Quarterly Pass',90,2400,'Valid for 90 days');
 db.prepare('INSERT INTO pass_types(name,duration_days,fare,description) VALUES(?,?,?,?)').run('Student Monthly',30,450,'Student concession pass; eligibility subject to verification');
}
const SECRET = process.env.JWT_SECRET || 'development-only-change-this-secret-please-2026';
const sessionMs = (Number(process.env.SESSION_HOURS)||8)*3600000;
app.use(helmet({contentSecurityPolicy:false}));
app.use(compression()); app.use(express.json({limit:'1mb'})); app.use(express.urlencoded({extended:true}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:40,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(ROOT,'public')));
const q = (sql,...args)=>db.prepare(sql).all(...args);
const one = (sql,...args)=>db.prepare(sql).get(...args);
const run = (sql,...args)=>db.prepare(sql).run(...args);
const id = prefix=>prefix+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
const audit=(req,action,entity=null,entityId=null,details={})=>run(
 'INSERT INTO audit_logs(user_id,action,entity,entity_id,ip,details) VALUES(?,?,?,?,?,?)',
 req.user?.id||null,action,entity,String(entityId??''),req.ip,JSON.stringify(details));
function auth(req,res,next){
 const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
 if(!token) return res.status(401).json({error:'Please sign in to continue'});
 try {req.user=jwt.verify(token,SECRET); next();} catch {res.status(401).json({error:'Session expired. Please sign in again'});}
}
const allow=(...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:'You are not authorized to perform this action'});
const safeUser=u=>({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role,active:!!u.active});
app.get('/api/health',(req,res)=>res.json({status:'ok',service:'BPMS',time:new Date().toISOString()}));
app.post('/api/auth/register',async(req,res)=>{
 try{
  const {name,email,phone,password}=req.body;
  if(!name||!email||!password||String(password).length<8) return res.status(400).json({error:'Name, email and a password of at least 8 characters are required'});
  const normalized=String(email).trim().toLowerCase();
  if(one('SELECT id FROM users WHERE email=?',normalized)) return res.status(409).json({error:'An account with this email already exists'});
  const info=run('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)',String(name).trim(),normalized,phone||'',bcrypt.hashSync(password,12),'passenger');
  audit({user:{id:info.lastInsertRowid},ip:req.ip},'REGISTER','user',info.lastInsertRowid);
  res.status(201).json({message:'Account created. You can now sign in.'});
 }catch(e){res.status(500).json({error:'Unable to create account'});}
});
app.post('/api/auth/login',(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
 const user=one('SELECT * FROM users WHERE email=?',email);
 if(!user||!user.active||!bcrypt.compareSync(password,user.password_hash)){
  audit({ip:req.ip,user:null},'LOGIN_FAILED','user',email); return res.status(401).json({error:'Invalid email or password'});
 }
 const token=jwt.sign({id:user.id,role:user.role,name:user.name},SECRET,{expiresIn:sessionMs/1000});
 audit({ip:req.ip,user:{id:user.id}},'LOGIN','user',user.id);
 res.json({token,user:safeUser(user),expiresIn:sessionMs});
});

app.post('/api/auth/forgot-password',async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase();
 // Always return the same response to avoid disclosing whether an account exists.
 const generic={message:'If an account exists for that email and recovery email is configured, a reset link will be sent.'};
 const user=one('SELECT id,email FROM users WHERE email=? AND active=1',email);
 const configured=process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS&&process.env.MAIL_FROM;
 if(user&&configured){
  try{
   const raw=crypto.randomBytes(32).toString('hex');
   const hash=crypto.createHash('sha256').update(raw).digest('hex');
   const expiry=new Date(Date.now()+30*60*1000).toISOString();
   run('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(?,?,?)',user.id,hash,expiry);
   const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE)==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
   const base=(process.env.APP_BASE_URL||`${req.protocol}://${req.get('host')}`).replace(/\/$/,'');
   const link=`${base}/?reset=${raw}`;
   await transporter.sendMail({from:process.env.MAIL_FROM,to:user.email,subject:'Reset your TransitPass password',text:`Use this one-time link within 30 minutes to reset your password: ${link}`});
   audit({ip:req.ip,user:{id:user.id}},'PASSWORD_RESET_REQUESTED','user',user.id);
  }catch(e){console.error('Password recovery email failed:',e.message);}
 }
 res.json(generic);
});
app.post('/api/auth/reset-password',(req,res)=>{
 const {token,newPassword}=req.body;
 if(!token||!newPassword||String(newPassword).length<8)return res.status(400).json({error:'A valid reset token and a password of at least 8 characters are required'});
 const hash=crypto.createHash('sha256').update(String(token)).digest('hex');
 const reset=one('SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?',hash,new Date().toISOString());
 if(!reset)return res.status(400).json({error:'This reset link is invalid or has expired'});
 const tx=db.transaction(()=>{
  run('UPDATE users SET password_hash=? WHERE id=?',bcrypt.hashSync(newPassword,12),reset.user_id);
  run('UPDATE password_resets SET used=1 WHERE user_id=? AND used=0',reset.user_id);
 });
 tx();audit({ip:req.ip,user:{id:reset.user_id}},'PASSWORD_RESET_COMPLETED','user',reset.user_id);
 res.json({message:'Password reset successfully. You can now sign in.'});
});
app.get('/api/me',auth,(req,res)=>{const u=one('SELECT * FROM users WHERE id=?',req.user.id); if(!u)return res.status(404).json({error:'User not found'});res.json(safeUser(u));});
app.post('/api/auth/change-password',auth,(req,res)=>{
 const {currentPassword,newPassword}=req.body; const u=one('SELECT * FROM users WHERE id=?',req.user.id);
 if(!bcrypt.compareSync(currentPassword||'',u.password_hash))return res.status(400).json({error:'Current password is incorrect'});
 if(!newPassword||newPassword.length<8)return res.status(400).json({error:'New password must contain at least 8 characters'});
 run('UPDATE users SET password_hash=? WHERE id=?',bcrypt.hashSync(newPassword,12),u.id); audit(req,'PASSWORD_CHANGED','user',u.id);res.json({message:'Password updated'});
});
app.get('/api/catalog',(req,res)=>res.json({routes:q('SELECT * FROM routes WHERE active=1 ORDER BY name'),passTypes:q('SELECT * FROM pass_types WHERE active=1 ORDER BY fare')}));
const upload=multer({storage:multer.diskStorage({destination:UPLOADS,filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())}),
 limits:{fileSize:(Number(process.env.MAX_UPLOAD_MB)||5)*1024*1024,files:5},
 fileFilter:(req,file,cb)=>{const ok=['application/pdf','image/jpeg','image/png'].includes(file.mimetype)&&/\.(pdf|jpe?g|png)$/i.test(file.originalname);cb(ok?null:new Error('Only PDF, JPG and PNG files are accepted'),ok);}});
app.post('/api/applications',auth,allow('passenger'),upload.array('documents',5),(req,res)=>{
 try{
  const {passTypeId,routeId,purpose=''}=req.body;
  const pt=one('SELECT * FROM pass_types WHERE id=? AND active=1',Number(passTypeId));
  const rt=one('SELECT * FROM routes WHERE id=? AND active=1',Number(routeId));
  if(!pt||!rt)return res.status(400).json({error:'Select a valid pass type and route'});
  const appNo=id('APP');
  const create=db.transaction(()=>{
   const info=run(`INSERT INTO applications(application_no,user_id,pass_type_id,route_id,duration_days,amount,purpose)
   VALUES(?,?,?,?,?,?,?)`,appNo,req.user.id,pt.id,rt.id,pt.duration_days,pt.fare,String(purpose).slice(0,500));
   for(const f of req.files||[])run('INSERT INTO documents(application_id,original_name,stored_name,mime_type,size) VALUES(?,?,?,?,?)',info.lastInsertRowid,f.originalname,f.filename,f.mimetype,f.size);
   return info.lastInsertRowid;
  });
  const appId=create();audit(req,'APPLICATION_SUBMITTED','application',appId,{applicationNo:appNo});
  res.status(201).json({message:'Application submitted successfully',applicationNo:appNo,id:appId});
 }catch(e){for(const f of req.files||[])try{fs.unlinkSync(f.path)}catch{};res.status(500).json({error:'Unable to submit application'});}
});
app.get('/api/applications',auth,(req,res)=>{
 const where=req.user.role==='passenger'?'WHERE a.user_id=?':'';
 const rows=req.user.role==='passenger'?q(`SELECT a.*,u.name passenger_name,pt.name pass_type,r.name route_name FROM applications a JOIN users u ON u.id=a.user_id JOIN pass_types pt ON pt.id=a.pass_type_id JOIN routes r ON r.id=a.route_id ${where} ORDER BY a.created_at DESC`,req.user.id):
 q(`SELECT a.*,u.name passenger_name,u.email,pt.name pass_type,r.name route_name FROM applications a JOIN users u ON u.id=a.user_id JOIN pass_types pt ON pt.id=a.pass_type_id JOIN routes r ON r.id=a.route_id ORDER BY a.created_at DESC`);
 res.json(rows);
});
app.get('/api/applications/:id',auth,(req,res)=>{
 const a=one(`SELECT a.*,u.name passenger_name,u.email,pt.name pass_type,r.name route_name FROM applications a JOIN users u ON u.id=a.user_id JOIN pass_types pt ON pt.id=a.pass_type_id JOIN routes r ON r.id=a.route_id WHERE a.id=?`,Number(req.params.id));
 if(!a|| (req.user.role==='passenger'&&a.user_id!==req.user.id))return res.status(404).json({error:'Application not found'});
 a.documents=q('SELECT id,original_name,mime_type,size,uploaded_at FROM documents WHERE application_id=?',a.id);
 res.json(a);
});
app.get('/api/documents/:id',auth,allow('staff','admin'),(req,res)=>{
 const d=one('SELECT d.*,a.user_id FROM documents d JOIN applications a ON a.id=d.application_id WHERE d.id=?',Number(req.params.id));
 if(!d)return res.status(404).end();res.download(path.join(UPLOADS,d.stored_name),d.original_name);
});
app.post('/api/applications/:id/review',auth,allow('staff','admin'),(req,res)=>{
 const {decision,remarks=''}=req.body; if(!['approved','rejected','correction'].includes(decision))return res.status(400).json({error:'Invalid review decision'});
 const a=one('SELECT * FROM applications WHERE id=?',Number(req.params.id));
 if(!a)return res.status(404).json({error:'Application not found'});
 if(a.status!=='pending'&&a.status!=='correction')return res.status(409).json({error:'This application has already been processed'});
 run('UPDATE applications SET status=?,reviewer_id=?,review_remarks=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?',decision==='correction'?'correction':decision,req.user.id,String(remarks).slice(0,500),a.id);
 audit(req,'APPLICATION_'+decision.toUpperCase(),'application',a.id,{remarks});res.json({message:`Application ${decision}`});
});
app.post('/api/applications/:id/payment',auth,allow('passenger'),(req,res)=>{
 const a=one('SELECT * FROM applications WHERE id=? AND user_id=?',Number(req.params.id),req.user.id);
 if(!a)return res.status(404).json({error:'Application not found'});
 if(a.status!=='approved')return res.status(400).json({error:'Payment is available after staff approval'});
 if(one('SELECT id FROM payments WHERE application_id=? AND status=?',a.id,'paid'))return res.status(409).json({error:'Payment already recorded'});
 const ref=id('TXN');run('INSERT INTO payments(application_id,amount,status,transaction_ref,method,paid_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)',a.id,a.amount,'paid',ref,'demo/manual');
 audit(req,'PAYMENT_RECORDED','application',a.id,{reference:ref,amount:a.amount});
 res.json({message:'Payment recorded in demo mode',transactionRef:ref});
});
function issuePass(applicationId,actor){
 const a=one('SELECT * FROM applications WHERE id=?',applicationId);
 if(!a||a.status!=='approved')throw new Error('Application must be approved before issuance');
 if(!one('SELECT id FROM payments WHERE application_id=? AND status=?',a.id,'paid'))throw new Error('Payment must be recorded before issuance');
 if(one('SELECT id FROM passes WHERE application_id=?',a.id))throw new Error('A pass has already been issued for this application');
 const start=new Date(), end=new Date(start);end.setDate(end.getDate()+a.duration_days);
 const passNo=id('BUS'), qrData=JSON.stringify({passNo});
 const info=run(`INSERT INTO passes(pass_no,application_id,user_id,pass_type_id,route_id,valid_from,valid_until,status,qr_data)
 VALUES(?,?,?,?,?,?,?,'active',?)`,passNo,a.id,a.user_id,a.pass_type_id,a.route_id,start.toISOString().slice(0,10),end.toISOString().slice(0,10),qrData);
 run('INSERT INTO pass_history(pass_id,old_status,new_status,changed_by,remarks) VALUES(?,?,?,?,?)',info.lastInsertRowid,null,'active',actor,'Pass issued');
 audit({user:{id:actor},ip:'system'},'PASS_ISSUED','pass',info.lastInsertRowid,{passNo});
 return info.lastInsertRowid;
}
app.post('/api/applications/:id/issue',auth,allow('staff','admin'),(req,res)=>{
 try{const passId=db.transaction(()=>issuePass(Number(req.params.id),req.user.id))();res.status(201).json({message:'Pass issued',pass:one('SELECT * FROM passes WHERE id=?',passId)});}
 catch(e){res.status(400).json({error:e.message});}
});
app.get('/api/passes',auth,(req,res)=>{
 const sql=`SELECT p.*,pt.name pass_type,r.name route_name,a.application_no FROM passes p JOIN pass_types pt ON pt.id=p.pass_type_id JOIN routes r ON r.id=p.route_id JOIN applications a ON a.id=p.application_id ${req.user.role==='passenger'?'WHERE p.user_id=?':''} ORDER BY p.created_at DESC`;
 res.json(req.user.role==='passenger'?q(sql,req.user.id):q(sql));
});
app.get('/api/passes/:id/qr',auth,async(req,res)=>{
 const p=one('SELECT * FROM passes WHERE id=?',Number(req.params.id));
 if(!p||(req.user.role==='passenger'&&p.user_id!==req.user.id))return res.status(404).json({error:'Pass not found'});
 res.json({passNo:p.pass_no,qr:await QRCode.toDataURL(p.qr_data)});
});
app.post('/api/passes/verify',auth,allow('staff','admin'),(req,res)=>{
 const key=String(req.body.passNo||req.body.code||'').trim();
 let p=one(`SELECT p.*,u.name passenger_name,pt.name pass_type,r.name route_name FROM passes p JOIN users u ON u.id=p.user_id JOIN pass_types pt ON pt.id=p.pass_type_id JOIN routes r ON r.id=p.route_id WHERE p.pass_no=?`,key);
 if(!p){try{const parsed=JSON.parse(key);if(parsed.passNo)p=one(`SELECT p.*,u.name passenger_name,pt.name pass_type,r.name route_name FROM passes p JOIN users u ON u.id=p.user_id JOIN pass_types pt ON pt.id=p.pass_type_id JOIN routes r ON r.id=p.route_id WHERE p.pass_no=?`,parsed.passNo);}catch{}}
 if(!p){audit(req,'PASS_VERIFY_FAILED','pass',key);return res.json({valid:false,status:'not_found',message:'No pass found for this number'});}
 let status=p.status; if(status==='active'&&p.valid_until<new Date().toISOString().slice(0,10))status='expired';
 audit(req,'PASS_VERIFIED','pass',p.id,{result:status});
 res.json({valid:status==='active',status,pass:{passNo:p.pass_no,passengerName:p.passenger_name,passType:p.pass_type,route:p.route_name,validFrom:p.valid_from,validUntil:p.valid_until}});
});
app.patch('/api/passes/:id/status',auth,allow('staff','admin'),(req,res)=>{
 const {status,remarks=''}=req.body; if(!['active','suspended','cancelled'].includes(status))return res.status(400).json({error:'Invalid status'});
 const p=one('SELECT * FROM passes WHERE id=?',Number(req.params.id));if(!p)return res.status(404).json({error:'Pass not found'});
 const change=db.transaction(()=>{run('UPDATE passes SET status=? WHERE id=?',status,p.id);run('INSERT INTO pass_history(pass_id,old_status,new_status,changed_by,remarks) VALUES(?,?,?,?,?)',p.id,p.status,status,req.user.id,String(remarks).slice(0,500));});
 change();audit(req,'PASS_STATUS_CHANGED','pass',p.id,{from:p.status,to:status,remarks});res.json({message:'Pass status updated'});
});
app.get('/api/passes/:id/history',auth,(req,res)=>{
 const p=one('SELECT * FROM passes WHERE id=?',Number(req.params.id));if(!p||(req.user.role==='passenger'&&p.user_id!==req.user.id))return res.status(404).json({error:'Pass not found'});
 res.json(q('SELECT h.*,u.name changed_by_name FROM pass_history h LEFT JOIN users u ON u.id=h.changed_by WHERE pass_id=? ORDER BY changed_at DESC',p.id));
});
app.post('/api/passes/:id/renew',auth,allow('passenger'),(req,res)=>{
 const p=one('SELECT * FROM passes WHERE id=? AND user_id=?',Number(req.params.id),req.user.id);if(!p)return res.status(404).json({error:'Pass not found'});
 if(p.status!=='active'&&p.status!=='expired')return res.status(400).json({error:'Only active or expired passes can be renewed'});
 const info=run(`INSERT INTO applications(application_no,user_id,pass_type_id,route_id,duration_days,amount,purpose,status,is_renewal,previous_pass_id)
 VALUES(?,?,?,?,?,?,?,'pending',1,?)`,id('APP'),req.user.id,p.pass_type_id,p.route_id,one('SELECT duration_days FROM pass_types WHERE id=?',p.pass_type_id).duration_days,one('SELECT fare FROM pass_types WHERE id=?',p.pass_type_id).fare,'Renewal of '+p.pass_no,p.id);
 audit(req,'RENEWAL_REQUESTED','application',info.lastInsertRowid,{passId:p.id});res.status(201).json({message:'Renewal request submitted',applicationId:info.lastInsertRowid});
});
app.get('/api/admin/dashboard',auth,allow('staff','admin'),(req,res)=>{
 const scalar=(sql)=>one(sql).n;
 res.json({passengers:scalar("SELECT COUNT(*) n FROM users WHERE role='passenger'"),applications:scalar('SELECT COUNT(*) n FROM applications'),pending:scalar("SELECT COUNT(*) n FROM applications WHERE status IN ('pending','correction')"),issued:scalar("SELECT COUNT(*) n FROM passes"),revenue:one("SELECT COALESCE(SUM(amount),0) n FROM payments WHERE status='paid'").n,expiring:scalar("SELECT COUNT(*) n FROM passes WHERE status='active' AND valid_until BETWEEN date('now') AND date('now','+7 day')")});
});
app.get('/api/admin/users',auth,allow('admin'),(req,res)=>res.json(q('SELECT id,name,email,phone,role,active,created_at FROM users ORDER BY created_at DESC')));
app.patch('/api/admin/users/:id',auth,allow('admin'),(req,res)=>{
 const {role,active}=req.body;if(role&&!['passenger','staff','admin'].includes(role))return res.status(400).json({error:'Invalid role'});
 const u=one('SELECT * FROM users WHERE id=?',Number(req.params.id));if(!u)return res.status(404).json({error:'User not found'});
 run('UPDATE users SET role=?,active=? WHERE id=?',role||u.role,active===undefined?u.active:(active?1:0),u.id);audit(req,'USER_UPDATED','user',u.id,{role:role||u.role,active});res.json({message:'User updated'});
});
app.post('/api/admin/routes',auth,allow('admin'),(req,res)=>{
 const {name,code,origin,destination}=req.body;if(!name||!code||!origin||!destination)return res.status(400).json({error:'All route fields are required'});
 try{const r=run('INSERT INTO routes(name,code,origin,destination) VALUES(?,?,?,?)',name,code,origin,destination);audit(req,'ROUTE_CREATED','route',r.lastInsertRowid);res.status(201).json({id:r.lastInsertRowid});}catch{res.status(409).json({error:'Route code already exists'});}
});
app.patch('/api/admin/routes/:id',auth,allow('admin'),(req,res)=>{
 const r=one('SELECT * FROM routes WHERE id=?',Number(req.params.id));if(!r)return res.status(404).json({error:'Route not found'});
 run('UPDATE routes SET name=?,origin=?,destination=?,active=? WHERE id=?',req.body.name||r.name,req.body.origin||r.origin,req.body.destination||r.destination,req.body.active===undefined?r.active:(req.body.active?1:0),r.id);audit(req,'ROUTE_UPDATED','route',r.id);res.json({message:'Route updated'});
});
app.post('/api/admin/pass-types',auth,allow('admin'),(req,res)=>{
 const {name,durationDays,fare,description=''}=req.body;if(!name||Number(durationDays)<1||Number(fare)<0)return res.status(400).json({error:'Enter a name, positive duration and valid fare'});
 const r=run('INSERT INTO pass_types(name,duration_days,fare,description) VALUES(?,?,?,?)',name,Number(durationDays),Number(fare),description);audit(req,'PASS_TYPE_CREATED','pass_type',r.lastInsertRowid);res.status(201).json({id:r.lastInsertRowid});
});
app.patch('/api/admin/pass-types/:id',auth,allow('admin'),(req,res)=>{
 const p=one('SELECT * FROM pass_types WHERE id=?',Number(req.params.id));if(!p)return res.status(404).json({error:'Pass type not found'});
 run('UPDATE pass_types SET name=?,duration_days=?,fare=?,description=?,active=? WHERE id=?',req.body.name||p.name,Number(req.body.durationDays)||p.duration_days,req.body.fare===undefined?p.fare:Number(req.body.fare),req.body.description??p.description,req.body.active===undefined?p.active:(req.body.active?1:0),p.id);audit(req,'PASS_TYPE_UPDATED','pass_type',p.id);res.json({message:'Pass type updated'});
});
app.get('/api/admin/reports',auth,allow('staff','admin'),(req,res)=>{
 const summary=q(`SELECT status,COUNT(*) count,COALESCE(SUM(amount),0) amount FROM applications GROUP BY status`);
 const monthly=q(`SELECT strftime('%Y-%m',created_at) month,COUNT(*) applications FROM applications GROUP BY month ORDER BY month DESC LIMIT 12`);
 const payments=q(`SELECT COALESCE(SUM(amount),0) total,COUNT(*) transactions FROM payments WHERE status='paid'`);
 const expiring=q(`SELECT p.pass_no,u.name passenger,p.valid_until FROM passes p JOIN users u ON u.id=p.user_id WHERE p.status='active' AND p.valid_until BETWEEN date('now') AND date('now','+30 day') ORDER BY p.valid_until`);
 res.json({summary,monthly,payments,expiring});
});
app.get('/api/admin/audit',auth,allow('admin'),(req,res)=>res.json(q(`SELECT l.*,u.name user_name FROM audit_logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 300`)));
app.get('/api/admin/export/:kind',auth,allow('staff','admin'),(req,res)=>{
 const maps={applications:`SELECT application_no,u.name passenger,u.email,pt.name pass_type,r.name route,a.status,a.amount,a.created_at FROM applications a JOIN users u ON u.id=a.user_id JOIN pass_types pt ON pt.id=a.pass_type_id JOIN routes r ON r.id=a.route_id`,
 passes:`SELECT p.pass_no,u.name passenger,pt.name pass_type,r.name route,p.valid_from,p.valid_until,p.status FROM passes p JOIN users u ON u.id=p.user_id JOIN pass_types pt ON pt.id=p.pass_type_id JOIN routes r ON r.id=p.route_id`,
 payments:`SELECT a.application_no,p.amount,p.status,p.transaction_ref,p.method,p.paid_at FROM payments p JOIN applications a ON a.id=p.application_id`};
 if(!maps[req.params.kind])return res.status(400).json({error:'Unsupported export'});
 const rows=q(maps[req.params.kind]);const cols=Object.keys(rows[0]||{empty:''});
 const csv=[cols.join(','),...rows.map(r=>cols.map(c=>'"'+String(r[c]??'').replace(/"/g,'""')+'"').join(','))].join('\n');
 audit(req,'REPORT_EXPORTED',req.params.kind);res.type('text/csv').attachment(`${req.params.kind}.csv`).send(csv);
});
app.use((err,req,res,next)=>{
 if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'File exceeds the configured upload limit':err.message});
 if(err)return res.status(400).json({error:err.message||'Request failed'});next();
});
app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
app.listen(PORT,()=>console.log(`BPMS running at http://localhost:${PORT}`));
