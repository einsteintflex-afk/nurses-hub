const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { WebSocketServer } = require('ws');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

const STORE = {
  users:'users.json', sessions:'sessions.json', progress:'progress.json',
  payments:'payments.json', paymentEvents:'payment-events.json', enquiries:'enquiries.json',
  submissions:'submissions.json',
  passwordResets:'password-resets.json', messages:'messages.json', reports:'message-reports.json',
  applications:'applications.json', stories:'stories.json', friends:'friends.json', directMessages:'direct-messages.json', groups:'groups.json', groupMembers:'group-members.json', statuses:'statuses.json', notifications:'notifications.json', newsComments:'news-comments.json', newsLikes:'news-likes.json', supportMessages:'support-messages.json', lessonNotes:'lesson-notes.json'
};
const CONTENT = { syllabus:'syllabus.json', questions:'questions.json', travel:'travel.json', resources:'resources.json', jobs:'jobs.json', news:'news.json', institutions:'institutions.json', studyOptions:'study-options.json', testimonials:'testimonials.json' };
for (const f of [...Object.values(STORE), ...Object.values(CONTENT)]) {
  const p = path.join(DATA_DIR, f); if (!fs.existsSync(p)) fs.writeFileSync(p, '[]', 'utf8');
}

function autoMigrateLocalUserData(){
  const usersPath=fileFor('users'); let currentUsers=readJson('users');
  if(currentUsers.length) return;
  const parent=path.dirname(__dirname);
  let candidates=[];
  try{ candidates=fs.readdirSync(parent,{withFileTypes:true}).filter(d=>d.isDirectory()&&d.name!==path.basename(__dirname)&&/midwif|nurs/i.test(d.name)); }catch{}
  candidates.sort((a,b)=>{ try{return fs.statSync(path.join(parent,b.name)).mtimeMs-fs.statSync(path.join(parent,a.name)).mtimeMs}catch{return 0}});
  for(const dir of candidates){
    const oldUsers=path.join(parent,dir.name,'data','users.json');
    try{const list=JSON.parse(fs.readFileSync(oldUsers,'utf8'));if(Array.isArray(list)&&list.length){writeJson('users',list);['progress','applications'].forEach(name=>{const src=path.join(parent,dir.name,'data',STORE[name]); if(fs.existsSync(src)&&readJson(name).length===0){try{const val=JSON.parse(fs.readFileSync(src,'utf8'));if(Array.isArray(val))writeJson(name,val)}catch{}}});break;}}catch{}
  }
}

function fileFor(name){ const f = STORE[name] || CONTENT[name]; if(!f) throw new Error(`Unknown store ${name}`); return path.join(DATA_DIR,f); }
function readJson(name){ try { return JSON.parse(fs.readFileSync(fileFor(name),'utf8')); } catch { return []; } }
function writeJson(name, value){ const p=fileFor(name), tmp=`${p}.${process.pid}.${Date.now()}.tmp`; fs.writeFileSync(tmp, JSON.stringify(value,null,2),'utf8'); fs.renameSync(tmp,p); }
function now(){ return new Date().toISOString(); }
function uid(prefix){ return `${prefix}_${crypto.randomBytes(10).toString('hex')}`; }
function clean(v,max=500){ return String(v ?? '').trim().slice(0,max); }
function emailNorm(v){ return clean(v,180).toLowerCase(); }
function hashPassword(password){ const salt=crypto.randomBytes(16).toString('hex'); const digest=crypto.scryptSync(password,salt,64).toString('hex'); return {salt,digest}; }
function verifyPassword(password,record){ try { const a=Buffer.from(crypto.scryptSync(password,record.salt,64).toString('hex'),'hex'); const b=Buffer.from(record.digest,'hex'); return a.length===b.length && crypto.timingSafeEqual(a,b); } catch { return false; } }
function escapeHtml(v){ return String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#039;'}[c])); }
function parseCookies(req){ const out={}; for(const pair of String(req.headers.cookie||'').split(';')){ const i=pair.indexOf('='); if(i<0) continue; out[pair.slice(0,i).trim()]=decodeURIComponent(pair.slice(i+1).trim()); } return out; }
function setCookie(res,token,days){ const secure=process.env.NODE_ENV==='production'?'; Secure':''; res.setHeader('Set-Cookie',`nursinghub=${encodeURIComponent(token)}; Max-Age=${days*86400}; Path=/; HttpOnly; SameSite=Lax${secure}`); }
function clearCookie(res){ res.setHeader('Set-Cookie','nursinghub=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax'); }
function sessionFor(req){ const token=parseCookies(req).nursinghub; if(!token) return null; return readJson('sessions').find(s=>s.token===token && new Date(s.expiresAt)>new Date()) || null; }
function createSession(res,userId,role='user'){ const days=Math.max(1,Number(process.env.SESSION_DAYS||7)); const token=crypto.randomBytes(32).toString('hex'); const csrf=crypto.randomBytes(24).toString('hex'); const list=readJson('sessions').filter(s=>new Date(s.expiresAt)>new Date()); list.push({token,csrf,userId,role,createdAt:now(),expiresAt:new Date(Date.now()+days*86400000).toISOString()}); writeJson('sessions',list); setCookie(res,token,days); return csrf; }
function current(req){ const s=sessionFor(req); if(!s) return {session:null,user:null}; if(s.role==='admin') return {session:s,user:{id:s.userId,name:'Administrator',email:process.env.ADMIN_EMAIL||'admin',role:'admin',profession:'Platform Administration',subscription:{active:true}}}; const users=readJson('users'); const u=users.find(x=>x.id===s.userId); if(u){ensureTrial(u); writeJson('users',users);} return {session:s,user:u||null}; }
function safeUser(u){ if(!u) return null; syncMembership(u); return {id:u.id,name:u.name,email:u.email,role:u.role,profession:u.profession,institution:u.institution||null,studyLevel:u.studyLevel||null,programme:u.programme||null,avatar:u.avatar?`/api/profile/avatar/${encodeURIComponent(u.id)}`:null,subscription:u.subscription,trial:u.trial||null,createdAt:u.createdAt}; }
function requireAuth(req,res,next){ const {session,user}=current(req); if(!session||!user)return res.status(401).json({error:'Authentication required.'}); req.session=session; req.user=user; next(); }
function optionalAuth(req,res,next){ const {session,user}=current(req); if(session&&user){req.session=session;req.user=user;} next(); }
function requireCsrf(req,res,next){ if(!req.session) return next(); if(req.headers['x-csrf-token']!==req.session.csrf)return res.status(403).json({error:'Security token expired. Refresh the page and try again.'}); next(); }
function requirePremium(req,res,next){ syncMembership(req.user); if(!hasPremiumAccess(req.user))return res.status(403).json({error:'Your 7-day Premium Trial has ended. Subscribe to continue using this feature.'}); next(); }
function requireAdmin(req,res,next){ if(req.session?.role!=='admin')return res.status(403).json({error:'Administrator access required.'}); next(); }
function paystackSecretKey(){ return String(process.env.PAYSTACK_SECRET_KEY||'').trim(); }
function paystackReady(){ const k=paystackSecretKey(); return /^sk_(test|live)_[A-Za-z0-9_-]+$/.test(k)&&!k.includes('your_'); }
function priceGhs(purpose){ return purpose==='subscription'?Number(process.env.SUBSCRIPTION_AMOUNT_GHS||50):Number(process.env.DOCUMENT_EVALUATION_AMOUNT_GHS||450); }
function paymentCurrency(){ return 'GHS'; }
function checkoutAmount(purpose){ return priceGhs(purpose); }
function paymentLabel(purpose){ return purpose==='subscription'?'Hub Premium membership':'Document evaluation'; }
function trialDays(){ return Math.max(1,Number(process.env.TRIAL_DAYS||7)); }
function trialEndsAt(start){ return new Date(new Date(start).getTime()+trialDays()*86400000).toISOString(); }
function hasPremiumAccess(user){
  if(!user) return false;
  if(user.subscription?.active) return true;
  if(user.trial?.status==='active' && user.trial?.endsAt && new Date(user.trial.endsAt)>new Date()) return true;
  return false;
}
function syncMembership(user){
  if(!user) return user;
  if(user.trial?.status==='active' && user.trial.endsAt && new Date(user.trial.endsAt)<=new Date()) { user.trial.status='expired'; user.trial.expiredAt=user.trial.endsAt; }
  return user;
}
function ensureTrial(user){
  syncMembership(user);
  if(!user.trial && !user.subscription?.active){ const start=now(); user.trial={status:'active',startedAt:start,endsAt:trialEndsAt(start),days:trialDays()}; }
  return user;
}

// Paystack webhook: raw body must be captured before express.json().
app.post('/api/payments/webhook', express.raw({type:'application/json',limit:'2mb'}), (req,res)=>{
  if(!paystackReady()) return res.sendStatus(200);
  const signature=String(req.headers['x-paystack-signature']||'');
  const expected=crypto.createHmac('sha512',paystackSecretKey()).update(req.body).digest('hex');
  if(!signature || signature.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected))) return res.sendStatus(401);
  let event; try{event=JSON.parse(req.body.toString('utf8'));}catch{return res.sendStatus(400);}
  const events=readJson('paymentEvents'); if(events.some(x=>x.eventId===event.id && event.id)) return res.sendStatus(200);
  events.push({eventId:event.id||uid('evt'),event:event.event,receivedAt:now(),reference:event.data?.reference||null}); writeJson('paymentEvents',events.slice(-5000));
  const d=event.data||{}; const md=d.metadata||{}; const userId=md.userId; const purpose=md.purpose;
  if(!userId||!['subscription','transcript'].includes(purpose)) return res.sendStatus(200);
  const users=readJson('users'); const user=users.find(x=>x.id===userId); if(!user)return res.sendStatus(200);
  if(event.event==='charge.success'){
    if(purpose==='subscription') user.subscription={active:true,status:'active',provider:'paystack',reference:d.reference,planCode:process.env.PAYSTACK_SUBSCRIPTION_PLAN_CODE||null,subscriptionCode:d.subscription_code||d.subscription?.subscription_code||null,updatedAt:now()};
    recordPayment({userId,reference:d.reference,purpose,amount:Number(d.amount||0)/100,currency:d.currency||paymentCurrency(),status:'success'});
  }
  if(event.event==='subscription.disable') user.subscription={...(user.subscription||{}),active:false,status:'disabled',updatedAt:now()};
  if(event.event==='invoice.payment_failed') user.subscription={...(user.subscription||{}),status:'past_due',updatedAt:now()};
  writeJson('users',users); res.sendStatus(200);
});

app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],scriptSrcAttr:["'unsafe-inline'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'","ws:","wss:"],fontSrc:["'self'"],frameAncestors:["'none'"]}}}));
app.use(express.json({limit:'2mb'}));
app.use(express.urlencoded({extended:true,limit:'2mb'}));
app.use(rateLimit({windowMs:15*60*1000,limit:400,standardHeaders:'draft-7',legacyHeaders:false}));
app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false});
const payLimiter=rateLimit({windowMs:10*60*1000,limit:20,standardHeaders:'draft-7',legacyHeaders:false});
const chatLimiter=rateLimit({windowMs:60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false});

const upload=multer({dest:UPLOADS,limits:{files:5,fileSize:Math.max(1,Number(process.env.MAX_UPLOAD_MB||8))*1024*1024},fileFilter:(req,file,cb)=>cb(['application/pdf','image/jpeg','image/png'].includes(file.mimetype)?null:new Error('Only PDF, JPG and PNG files are accepted.'))});
function fileMagicOk(file){ try{const b=fs.readFileSync(file.path); if(file.mimetype==='application/pdf')return b.slice(0,5).toString()==='%PDF-'; if(file.mimetype==='image/png')return b.slice(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])); if(file.mimetype==='image/jpeg')return b[0]===255&&b[1]===216&&b[b.length-2]===255&&b[b.length-1]===217;}catch{} return false; }
function cleanupFiles(files){ for(const list of Object.values(files||{}))for(const f of list){try{fs.unlinkSync(f.path)}catch{}} }


function publicUser(u){
  if(!u) return null;
  const friends=readJson('friends').filter(x=>x.status==='accepted' && (x.userId===u.id || x.friendId===u.id)).length;
  return {id:u.id,name:u.name,profession:u.profession,role:u.role,institution:u.institution||null,studyLevel:u.studyLevel||null,programme:u.programme||null,avatar:u.avatar?`/api/profile/avatar/${encodeURIComponent(u.id)}`:null,friendsCount:friends};
}
function createNotification(userId,type,title,text,link=null){
  const list=readJson('notifications'); list.push({id:uid('notif'),userId,type,title:clean(title,140),text:clean(text,400),link:clean(link,120)||null,read:false,createdAt:now()}); writeJson('notifications',list.slice(-10000));
  broadcastToUser(userId,{type:'notification',data:list[list.length-1]});
}
function friendStatus(a,b){
  const item=readJson('friends').find(x=>(x.userId===a&&x.friendId===b)||(x.userId===b&&x.friendId===a));
  return item?.status||null;
}
function safeFilename(name){return String(name||'').replace(/[^a-zA-Z0-9._-]/g,'_').slice(-120)}
function mediaAllowed(file){
  const allowed=['image/jpeg','image/png','image/webp','audio/mpeg','audio/ogg','audio/wav','video/mp4','video/webm'];
  return allowed.includes(file.mimetype);
}
const mediaUpload=multer({dest:UPLOADS,limits:{files:1,fileSize:12*1024*1024},fileFilter:(req,file,cb)=>cb(mediaAllowed(file)?null:new Error('Only JPG, PNG, WEBP, MP3, OGG, WAV, MP4 and WEBM media are accepted (max 12 MB).'))});
function addFriendNotification(targetId,actor){createNotification(targetId,'friend_request',`${actor.name} sent you a friend request`,`Open Community to review the request.`,'community');}
function broadcastToUser(userId,payload){for(const entry of clients?.values?.()||[])if(entry.userId===userId&&entry.ws.readyState===1)entry.ws.send(JSON.stringify(payload));}


autoMigrateLocalUserData();

app.get('/api/config',(req,res)=>res.json({subscriptionGhs:priceGhs('subscription'),evaluationGhs:priceGhs('transcript'),paymentCurrency:'GHS',checkoutSubscription:checkoutAmount('subscription'),checkoutEvaluation:checkoutAmount('transcript'),paymentConfigured:paystackReady(),subscriptionPlanConfigured:Boolean(process.env.PAYSTACK_SUBSCRIPTION_PLAN_CODE&&!process.env.PAYSTACK_SUBSCRIPTION_PLAN_CODE.includes('your_')),autoRefreshMinutes:Number(process.env.AUTO_REFRESH_MINUTES||30),opportunityFeedsConfigured:Boolean(process.env.OPPORTUNITY_FEEDS_JSON&&process.env.OPPORTUNITY_FEEDS_JSON!=='[]'),maxUploadMb:Number(process.env.MAX_UPLOAD_MB||8),aiConfigured:Boolean(process.env.OPENAI_API_KEY),demoPayments:String(process.env.ALLOW_DEMO_PAYMENTS||'true')==='true',trialDays:trialDays()}));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'Nurses & Midwives Hub',time:now()}));
app.get('/api/institutions',(_,res)=>res.json(readJson('institutions')));
app.get('/api/study-options',(_,res)=>res.json(readJson('studyOptions').map(x=>({...x,applicationUrl:undefined}))));

app.get('/api/content',(req,res)=>{
  const jobs=readJson('jobs').map(j=>{const {applicationUrl,...publicJob}=j;return publicJob;});
  res.json({syllabus:readJson('syllabus'),questions:readJson('questions').map(({answer,...q})=>q),travel:readJson('travel').map(t=>({...t,links:undefined})),resources:readJson('resources').map(r=>({...r,sourceUrl:undefined})),jobs,news:readJson('news'),institutions:readJson('institutions'),studyOptions:readJson('studyOptions').map(x=>({...x,applicationUrl:undefined})),testimonials:readJson('testimonials'),stories:readJson('stories').filter(x=>x.status==='approved').map(x=>({id:x.id,type:x.type,text:x.text,name:x.anonymous?'Anonymous member':x.name,createdAt:x.createdAt}))});
});
app.get('/api/news/:id',(req,res)=>{const n=readJson('news').find(x=>x.id===req.params.id); if(!n)return res.status(404).json({error:'Article not found.'}); res.json(n);});
app.get('/api/jobs/:id',requireAuth,(req,res)=>{const j=readJson('jobs').find(x=>x.id===req.params.id); if(!j)return res.status(404).json({error:'Job not found.'}); res.json(j);});



app.get('/api/community/bootstrap',requireAuth,requirePremium,(req,res)=>{
  const allUsers=readJson('users');
  const users=allUsers.filter(u=>u.id!==req.user.id).slice(0,300).map(publicUser);
  const friends=readJson('friends').filter(x=>x.userId===req.user.id||x.friendId===req.user.id).map(x=>{const otherId=x.userId===req.user.id?x.friendId:x.userId;return {...x,otherUserId:otherId,otherUser:publicUser(allUsers.find(u=>u.id===otherId))};});
  const groupMembers=readJson('groupMembers').filter(x=>x.userId===req.user.id);
  const groups=readJson('groups').filter(g=>groupMembers.some(m=>m.groupId===g.id)).map(g=>({...g,members:readJson('groupMembers').filter(m=>m.groupId===g.id).length}));
  const statuses=readJson('statuses').filter(x=>new Date(x.expiresAt)>new Date()).slice(-100).map(x=>({...x,user:publicUser(allUsers.find(u=>u.id===x.userId))}));
  const notifications=readJson('notifications').filter(x=>x.userId===req.user.id).slice(-80).reverse();
  const messages=readJson('messages').slice(-150);
  res.json({people:users.filter(x=>friendStatus(req.user.id,x.id)!=='blocked'),friends,groups,statuses,notifications,messages,pendingRequests:friends.filter(x=>x.status==='pending'&&x.friendId===req.user.id)});
});
app.get('/api/community/people',requireAuth,requirePremium,(req,res)=>{
  const users=readJson('users').filter(u=>u.id!==req.user.id).map(publicUser);
  const suggestions=users.filter(x=>!friendStatus(req.user.id,x.id)).slice(0,20);
  res.json({suggestions});
});
app.get('/api/community/friends',requireAuth,requirePremium,(req,res)=>res.json(readJson('friends').filter(x=>x.userId===req.user.id||x.friendId===req.user.id)));
app.post('/api/community/friends',requireAuth,requirePremium,requireCsrf,chatLimiter,(req,res)=>{
  const friendId=clean(req.body.friendId,100); if(!friendId||friendId===req.user.id)return res.status(400).json({error:'Invalid friend request.'});
  const target=readJson('users').find(u=>u.id===friendId); if(!target)return res.status(404).json({error:'Member not found.'});
  const list=readJson('friends'); const existing=list.find(x=>(x.userId===req.user.id&&x.friendId===friendId)||(x.userId===friendId&&x.friendId===req.user.id));
  if(existing){ if(existing.status==='accepted') return res.json(existing); if(existing.status==='pending') return res.status(409).json({error:'Friend request already pending.'}); }
  const item={id:uid('fr'),userId:req.user.id,friendId,status:'pending',createdAt:now(),updatedAt:now()}; list.push(item); writeJson('friends',list); addFriendNotification(friendId,req.user); res.status(201).json(item);
});
app.post('/api/community/friends/:id/respond',requireAuth,requirePremium,requireCsrf,(req,res)=>{
  const list=readJson('friends'),item=list.find(x=>x.id===req.params.id&&(x.friendId===req.user.id||x.userId===req.user.id)); if(!item)return res.status(404).json({error:'Friend request not found.'});
  const action=req.body.action; if(!['accept','decline','block'].includes(action))return res.status(400).json({error:'Invalid action.'});
  item.status=action==='accept'?'accepted':action==='block'?'blocked':'declined'; item.updatedAt=now(); writeJson('friends',list);
  if(action==='accept')createNotification(item.userId===req.user.id?item.friendId:item.userId,'friend_accept','Friend request accepted','You are now connected in the Hub.','community');
  res.json(item);
});

app.get('/api/community/groups',requireAuth,requirePremium,(req,res)=>{
  const memberships=readJson('groupMembers').filter(x=>x.userId===req.user.id); const groups=readJson('groups').filter(g=>memberships.some(m=>m.groupId===g.id)); res.json(groups.map(g=>({...g,members:readJson('groupMembers').filter(m=>m.groupId===g.id).length})));
});
app.post('/api/community/groups',requireAuth,requirePremium,requireCsrf,(req,res)=>{
  const name=clean(req.body.name,100),description=clean(req.body.description,400); if(name.length<2)return res.status(400).json({error:'Group name is required.'});
  const groups=readJson('groups'); const g={id:uid('grp'),name,description,ownerId:req.user.id,createdAt:now()}; groups.push(g); writeJson('groups',groups); const members=readJson('groupMembers'); members.push({id:uid('gm'),groupId:g.id,userId:req.user.id,role:'owner',createdAt:now()}); writeJson('groupMembers',members); res.status(201).json(g);
});
app.post('/api/community/groups/:id/add',requireAuth,requirePremium,requireCsrf,(req,res)=>{
  const g=readJson('groups').find(x=>x.id===req.params.id); if(!g)return res.status(404).json({error:'Group not found.'}); const memberId=clean(req.body.userId,100); const members=readJson('groupMembers'); if(!members.some(x=>x.groupId===g.id&&x.userId===req.user.id))return res.status(403).json({error:'Join the group before managing it.'}); if(!readJson('users').some(x=>x.id===memberId))return res.status(404).json({error:'Member not found.'}); if(!members.some(x=>x.groupId===g.id&&x.userId===memberId))members.push({id:uid('gm'),groupId:g.id,userId:memberId,role:'member',createdAt:now()}); writeJson('groupMembers',members); createNotification(memberId,'group_invite',`You were added to ${g.name}`,'Open Community to join the conversation.','community'); res.json({ok:true});
});
app.post('/api/community/status',requireAuth,requirePremium,requireCsrf,mediaUpload.single('media'),(req,res)=>{
  try{
    const text=clean(req.body.text,500); if(!text&&!req.file)return res.status(400).json({error:'Add text or an image/audio/video status.'});
    const item={id:uid('status'),userId:req.user.id,text,media:req.file?{name:safeFilename(req.file.originalname),mime:req.file.mimetype,path:path.basename(req.file.path)}:null,createdAt:now(),expiresAt:new Date(Date.now()+24*3600000).toISOString()}; const list=readJson('statuses');list.push(item);writeJson('statuses',list.slice(-5000));res.status(201).json(item);
  }catch(e){if(req.file)try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:e.message||'Status failed.'});}
});
app.get('/api/community/status-media/:id',requireAuth,requirePremium,(req,res)=>{const s=readJson('statuses').find(x=>x.id===req.params.id);if(!s?.media)return res.sendStatus(404);res.sendFile(path.join(UPLOADS,s.media.path));});
app.get('/api/community/direct/:userId',requireAuth,requirePremium,(req,res)=>{const other=clean(req.params.userId,100); if(!readJson('users').some(u=>u.id===other))return res.status(404).json({error:'Member not found.'}); if(friendStatus(req.user.id,other)!=='accepted')return res.status(403).json({error:'Private messages are available between accepted connections.'}); const rows=readJson('directMessages').filter(x=>(x.fromId===req.user.id&&x.toId===other)||(x.fromId===other&&x.toId===req.user.id)).slice(-100); res.json(rows);});
app.post('/api/community/direct',requireAuth,requirePremium,chatLimiter,requireCsrf,mediaUpload.single('media'),(req,res)=>{
  try{const toId=clean(req.body.toId,100),text=clean(req.body.text,800); if(!readJson('users').some(u=>u.id===toId)||toId===req.user.id)return res.status(400).json({error:'Recipient is not valid.'}); if(friendStatus(req.user.id,toId)!=='accepted')return res.status(403).json({error:'Accept the connection before using private messages.'}); if(!text&&!req.file)return res.status(400).json({error:'Message is empty.'}); const item={id:uid('dm'),fromId:req.user.id,toId,text,media:req.file?{name:safeFilename(req.file.originalname),mime:req.file.mimetype,path:path.basename(req.file.path)}:null,createdAt:now()}; const list=readJson('directMessages');list.push(item);writeJson('directMessages',list.slice(-20000)); createNotification(toId,'message',`New message from ${req.user.name}`,text.slice(0,120),'community'); broadcastToUser(toId,{type:'direct_message',data:item}); res.status(201).json(item);}catch(e){if(req.file)try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:e.message||'Message failed.'});}
});
app.get('/api/community/media/:scope/:id',requireAuth,requirePremium,(req,res)=>{let item=null;if(req.params.scope==='direct'){item=readJson('directMessages').find(x=>x.id===req.params.id);if(!item||![item.fromId,item.toId].includes(req.user.id))return res.sendStatus(403);}if(req.params.scope==='status'){item=readJson('statuses').find(x=>x.id===req.params.id);if(!item||new Date(item.expiresAt)<=new Date())return res.sendStatus(404);}if(req.params.scope==='community'){item=readJson('messages').find(x=>x.id===req.params.id);if(!item)return res.sendStatus(404);}if(!item?.media)return res.sendStatus(404);const safe=path.basename(item.media.path);if(!/^[A-Za-z0-9._-]+$/.test(safe))return res.sendStatus(404);res.sendFile(path.join(UPLOADS,safe));});
app.get('/api/community/group/:id/messages',requireAuth,requirePremium,(req,res)=>{const gid=clean(req.params.id,100),members=readJson('groupMembers');if(!members.some(x=>x.groupId===gid&&x.userId===req.user.id))return res.status(403).json({error:'You are not a member of this group.'});res.json(readJson('messages').filter(x=>x.groupId===gid).slice(-200));});
app.post('/api/community/group/:id/messages',requireAuth,requirePremium,chatLimiter,requireCsrf,mediaUpload.single('media'),(req,res)=>{try{const gid=clean(req.params.id,100),members=readJson('groupMembers');if(!members.some(x=>x.groupId===gid&&x.userId===req.user.id))return res.status(403).json({error:'You are not a member of this group.'});const text=clean(req.body.text,800);if(!text&&!req.file)return res.status(400).json({error:'Message is empty.'});const item={id:uid('msg'),groupId:gid,userId:req.user.id,author:req.user.name,text,media:req.file?{name:safeFilename(req.file.originalname),mime:req.file.mimetype,path:path.basename(req.file.path)}:null,createdAt:now()};const list=readJson('messages');list.push(item);writeJson('messages',list.slice(-20000));const groupName=(readJson('groups').find(g=>g.id===gid)?.name)||'group';for(const m of members.filter(x=>x.userId!==req.user.id)){createNotification(m.userId,'group_message',`New message in ${groupName}`,text.slice(0,100),'community');broadcastToUser(m.userId,{type:'group_message',data:item});}res.status(201).json(item);}catch(e){if(req.file)try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:e.message||'Group message failed.'});}});


app.get('/api/support/messages',requireAuth,(req,res)=>res.json(readJson('supportMessages').filter(x=>x.userId===req.user.id).slice(-200)));
app.post('/api/support/messages',requireAuth,chatLimiter,requireCsrf,(req,res)=>{const text=clean(req.body.text,1000);if(!text)return res.status(400).json({error:'Message cannot be empty.'});const item={id:uid('sup'),userId:req.user.id,sender:'member',text,createdAt:now()};const list=readJson('supportMessages');list.push(item);writeJson('supportMessages',list.slice(-20000));createNotification(`admin:${process.env.ADMIN_EMAIL||'admin'}`,'support_message','New support message',text.slice(0,120),'admin');res.status(201).json(item);});
app.get('/api/community/summary',requireAuth,requirePremium,(req,res)=>{const friends=readJson('friends').filter(x=>x.status==='accepted'&&(x.userId===req.user.id||x.friendId===req.user.id)).length;const pending=readJson('friends').filter(x=>x.friendId===req.user.id&&x.status==='pending').length;const unread=readJson('notifications').filter(x=>x.userId===req.user.id&&!x.read).length;const online=[...clients?.values?.()||[]].filter(x=>x.userId!==req.user.id).length;res.json({friends,pending,unread,online});});

app.get('/api/notifications',requireAuth,(req,res)=>res.json(readJson('notifications').filter(x=>x.userId===req.user.id).slice(-100).reverse()));
app.post('/api/notifications/:id/read',requireAuth,requireCsrf,(req,res)=>{const list=readJson('notifications'),item=list.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!item)return res.status(404).json({error:'Notification not found.'});item.read=true;writeJson('notifications',list);res.json(item);});

app.get('/api/profile',requireAuth,(req,res)=>res.json(safeUser(req.user)));
app.patch('/api/profile',requireAuth,requireCsrf,(req,res)=>{const fields=['name','profession','institution','studyLevel','programme'];const users=readJson('users'),u=users.find(x=>x.id===req.user.id);for(const f of fields)if(req.body[f]!==undefined)u[f]=clean(req.body[f],180);if(u.role==='student'&&!u.institution)return res.status(400).json({error:'Students need an institution selected.'});writeJson('users',users);res.json(safeUser(u));});
app.post('/api/profile/avatar',requireAuth,requireCsrf,mediaUpload.single('avatar'),(req,res)=>{try{if(!req.file||!['image/jpeg','image/png','image/webp'].includes(req.file.mimetype))return res.status(400).json({error:'Please upload a JPG, PNG or WEBP profile image.'});const users=readJson('users'),u=users.find(x=>x.id===req.user.id);if(u.avatar)try{fs.unlinkSync(path.join(UPLOADS,u.avatar))}catch{};u.avatar=path.basename(req.file.path);writeJson('users',users);res.json(safeUser(u));}catch(e){if(req.file)try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:e.message||'Avatar upload failed.'});}});
app.get('/api/profile/avatar/:userId',requireAuth,(req,res)=>{const u=readJson('users').find(x=>x.id===req.params.userId);if(!u?.avatar)return res.sendStatus(404);res.sendFile(path.join(UPLOADS,u.avatar));});

app.get('/api/news/:id/comments',requireAuth,(req,res)=>res.json(readJson('newsComments').filter(x=>x.newsId===req.params.id).slice(-100)));
app.post('/api/news/:id/comments',requireAuth,requireCsrf,(req,res)=>{const text=clean(req.body.text,500);if(text.length<1)return res.status(400).json({error:'Comment cannot be empty.'});const item={id:uid('ncm'),newsId:req.params.id,userId:req.user.id,author:req.user.name,text,createdAt:now()};const list=readJson('newsComments');list.push(item);writeJson('newsComments',list.slice(-20000));res.status(201).json(item);});
app.post('/api/news/:id/like',requireAuth,requireCsrf,(req,res)=>{const list=readJson('newsLikes');const existing=list.find(x=>x.newsId===req.params.id&&x.userId===req.user.id);if(existing){const next=list.filter(x=>x!==existing);writeJson('newsLikes',next);return res.json({liked:false,count:next.filter(x=>x.newsId===req.params.id).length});}list.push({id:uid('nlike'),newsId:req.params.id,userId:req.user.id,createdAt:now()});writeJson('newsLikes',list);res.json({liked:true,count:list.filter(x=>x.newsId===req.params.id).length});});
app.get('/api/news/:id/social',requireAuth,(req,res)=>{const likes=readJson('newsLikes').filter(x=>x.newsId===req.params.id);res.json({liked:likes.some(x=>x.userId===req.user.id),count:likes.length,comments:readJson('newsComments').filter(x=>x.newsId===req.params.id).slice(-100)});});

app.post('/api/auth/register',authLimiter,(req,res)=>{
  const name=clean(req.body.name,100), email=emailNorm(req.body.email), password=String(req.body.password||''), role=clean(req.body.role,20), profession=clean(req.body.profession,80), institution=clean(req.body.institution,180), studyLevel=clean(req.body.studyLevel,80), programme=clean(req.body.programme,120);
  if(name.length<2||!email.includes('@')||password.length<8||!['student','graduate'].includes(role)||!profession)return res.status(400).json({error:'Provide a valid name, email, 8+ character password, profile type and profession.'});
  if(role==='student' && !institution)return res.status(400).json({error:'Students must select their university or training institution.'});
  const users=readJson('users'); if(users.some(u=>u.email===email))return res.status(409).json({error:'An account with that email already exists.'});
  const start=now(); const u={id:uid('usr'),name,email,role,profession,institution:role==='student'?institution:null,studyLevel:role==='student'?studyLevel:null,programme:role==='student'?programme:null,password:hashPassword(password),subscription:{active:false,status:'free'},trial:{status:'active',startedAt:start,endsAt:trialEndsAt(start),days:trialDays()},createdAt:start}; users.push(u); writeJson('users',users); const csrf=createSession(res,u.id); res.status(201).json({user:safeUser(u),csrf});
});
app.post('/api/auth/login',authLimiter,(req,res)=>{const email=emailNorm(req.body.email),password=String(req.body.password||''),users=readJson('users'),u=users.find(x=>x.email===email);if(!u||!verifyPassword(password,u.password))return res.status(401).json({error:'Invalid email or password.'});ensureTrial(u);writeJson('users',users);const csrf=createSession(res,u.id);res.json({user:safeUser(u),csrf});});
app.post('/api/auth/admin-login',authLimiter,(req,res)=>{const email=emailNorm(req.body.email),password=String(req.body.password||''),configured=String(process.env.ADMIN_PASSWORD||'');if(configured==='change-this-immediately')return res.status(503).json({error:'Administrator login is disabled until ADMIN_PASSWORD is changed in .env.'});if(!emailNorm(process.env.ADMIN_EMAIL)||email!==emailNorm(process.env.ADMIN_EMAIL)||password!==configured)return res.status(401).json({error:'Invalid administrator credentials.'});const csrf=createSession(res,`admin:${email}`,'admin');res.json({admin:true,csrf});});

async function sendResetEmail(to,resetUrl){
  if(process.env.RESEND_API_KEY&&process.env.RESEND_FROM_EMAIL){
    try{const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.RESEND_FROM_EMAIL,to:[to],subject:'Nurses & Midwives Hub password reset',html:`<p>A password-reset request was made for your Nurses & Midwives Hub account.</p><p><a href="${escapeHtml(resetUrl)}">Reset your password</a></p><p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>`})});return r.ok;}catch{} }
  return false;
}

app.post('/api/auth/forgot-password',authLimiter,async(req,res)=>{
  const email=emailNorm(req.body.email),users=readJson('users'),u=users.find(x=>x.email===email);
  const response={message:'If an account exists, a password-reset link has been prepared.'};
  if(!u) return res.json(response);
  const token=crypto.randomBytes(32).toString('hex'); const digest=crypto.createHash('sha256').update(token).digest('hex');
  const list=readJson('passwordResets').filter(x=>new Date(x.expiresAt)>new Date() && !x.used); list.push({id:uid('rst'),userId:u.id,digest,expiresAt:new Date(Date.now()+30*60*1000).toISOString(),createdAt:now()}); writeJson('passwordResets',list);
  const resetUrl=`${APP_URL}/?reset=${token}&email=${encodeURIComponent(u.email)}`;
  const mailed=await sendResetEmail(u.email,resetUrl);
  if(process.env.NODE_ENV!=='production' || !mailed) response.devResetUrl=resetUrl;
  res.json(response);
});
app.post('/api/auth/reset-password',authLimiter,(req,res)=>{
  const email=emailNorm(req.body.email),token=clean(req.body.token,120),password=String(req.body.password||'');
  if(password.length<8||!email||!token)return res.status(400).json({error:'A valid reset token and an 8+ character password are required.'});
  const users=readJson('users'),u=users.find(x=>x.email===email); const digest=crypto.createHash('sha256').update(token).digest('hex');
  const resets=readJson('passwordResets'),item=resets.find(x=>x.digest===digest&&!x.used&&new Date(x.expiresAt)>new Date()&&x.userId===u?.id); if(!u||!item)return res.status(400).json({error:'That reset link is invalid or has expired.'});
  u.password=hashPassword(password); item.used=true; writeJson('users',users); writeJson('passwordResets',resets); writeJson('sessions',readJson('sessions').filter(s=>s.userId!==u.id)); res.json({ok:true,message:'Password updated. You can now sign in.'});
});
app.post('/api/auth/logout',requireAuth,requireCsrf,(req,res)=>{writeJson('sessions',readJson('sessions').filter(s=>s.token!==req.session.token));clearCookie(res);res.json({ok:true});});
app.get('/api/me',requireAuth,(req,res)=>res.json({user:safeUser(req.user),progress:getProgress(req.user.id),csrf:req.session.csrf}));

function getProgress(userId){return readJson('progress').find(x=>x.userId===userId)||{userId,modules:{},lessons:{},questionsAnswered:0,correct:0,byDomain:{},updatedAt:null};}
function saveProgress(p){const list=readJson('progress').filter(x=>x.userId!==p.userId);list.push(p);writeJson('progress',list);return p;}
app.post('/api/progress',requireAuth,requireCsrf,(req,res)=>{const p=getProgress(req.user.id),moduleId=clean(req.body.moduleId,100),lessonId=clean(req.body.lessonId,120);if(moduleId)p.modules[moduleId]=Math.max(0,Math.min(100,Number(req.body.completed||0)));if(lessonId)p.lessons[lessonId]=Boolean(req.body.completed);p.updatedAt=now();res.json(saveProgress(p));});

app.get('/api/questions/all',requireAuth,requirePremium,(req,res)=>res.json(readJson('questions')));
app.get('/api/questions/download',requireAuth,requirePremium,(req,res)=>{const rows=['ID,Type,Domain,Difficulty,Question,Options,TheoryGuide'];for(const q of readJson('questions'))rows.push([q.id,q.type||'mcq',q.domain,q.difficulty,q.question,(q.options||[]).join(' | '),q.type==='theory'?(q.theoryGuide||''):'' ].map(v=>`"${String(v??'').replace(/"/g,'""')}"`).join(','));res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition','attachment; filename=nmhub-nmc-preparation.csv');res.send(rows.join('\n'));});
app.post('/api/questions/submit',requireAuth,requirePremium,requireCsrf,(req,res)=>{const q=readJson('questions').find(x=>x.id===req.body.id);if(!q)return res.status(404).json({error:'Question not found.'});const answer=Number(req.body.answer),correct=answer===q.answer,p=getProgress(req.user.id);p.questionsAnswered++;if(correct)p.correct++;p.byDomain[q.domain]=p.byDomain[q.domain]||{answered:0,correct:0};p.byDomain[q.domain].answered++;if(correct)p.byDomain[q.domain].correct++;p.updatedAt=now();saveProgress(p);res.json({correct,correctAnswer:q.answer,explanation:q.explanation,score:{answered:p.questionsAnswered,correct:p.correct,accuracy:p.questionsAnswered?Math.round(p.correct/p.questionsAnswered*100):0}});});

app.get('/api/applications',requireAuth,(req,res)=>res.json(readJson('applications').filter(x=>x.userId===req.user.id).sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt))));
app.post('/api/applications',requireAuth,requireCsrf,(req,res)=>{const jobId=clean(req.body.jobId,100),job=readJson('jobs').find(x=>x.id===jobId);if(!job)return res.status(404).json({error:'Job not found.'});const list=readJson('applications');let item=list.find(x=>x.userId===req.user.id&&x.jobId===jobId);if(!item){item={id:uid('app'),userId:req.user.id,jobId,status:'saved',createdAt:now(),updatedAt:now()};list.push(item)}else item.updatedAt=now();writeJson('applications',list);res.json(item);});
app.patch('/api/applications/:id',requireAuth,requireCsrf,(req,res)=>{const list=readJson('applications'),item=list.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!item)return res.status(404).json({error:'Application tracker item not found.'});if(['saved','preparing','applied','interview','offer','closed'].includes(req.body.status))item.status=req.body.status;item.updatedAt=now();writeJson('applications',list);res.json(item);});

function recommendedPathway(targetCountry,pathwayType,profession){
  const travel=readJson('travel'); const country=clean(targetCountry,80); const mode=pathwayType==='study'?'study':'work'; const hits=travel.filter(x=>x.mode===mode && x.country.toLowerCase()===country.toLowerCase());
  const chosen=hits[0]||travel.find(x=>x.mode===mode);
  if(!chosen)return {status:'manual_review',summary:'Your target was not in the automated pathway directory. A reviewer will provide a suitable official route.',links:[]};
  return {status:'preliminary',country:chosen.country,mode,profession,route:chosen.title,summary:chosen.summary,steps:chosen.steps,links:(chosen.links||[]).map(x=>({label:x[0],url:x[1]}))};
}

app.get('/api/travel/:id', (req,res)=>{const t=readJson('travel').find(x=>x.id===req.params.id);if(!t)return res.status(404).json({error:'Pathway not found.'});res.json({...t,sourceUrls:(t.links||[]).map(x=>({name:x[0],url:x[1]})),links:undefined});});

app.get('/api/stories',(_,res)=>res.json(readJson('stories').filter(x=>x.status==='approved').map(x=>({id:x.id,type:x.type,text:x.text,name:x.anonymous?'Anonymous member':x.name,createdAt:x.createdAt}))));
app.post('/api/stories',requireAuth,requireCsrf,(req,res)=>{const text=clean(req.body.text,1800),type=clean(req.body.type,80)||'Career experience',anonymous=req.body.anonymous!==false,consent=req.body.consent===true;if(text.length<30||!consent)return res.status(400).json({error:'A meaningful story and publication consent are required.'});const list=readJson('stories');list.push({id:uid('story'),userId:req.user.id,name:req.user.name,type,text,anonymous,consent,status:'pending',createdAt:now()});writeJson('stories',list);res.status(201).json({ok:true,message:'Story submitted for review.'});});

app.get('/api/enquiries',requireAuth,(req,res)=>res.json(readJson('enquiries').filter(x=>x.userId===req.user.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.post('/api/enquiries',optionalAuth,(req,res)=>{if(req.user && req.session && req.headers['x-csrf-token']!==req.session.csrf)return res.status(403).json({error:'Security token expired. Refresh the page and try again.'});const name=clean(req.body.name,100),email=emailNorm(req.body.email),subject=clean(req.body.subject,160)||'General enquiry',message=clean(req.body.message,3000);if(name.length<2||!email.includes('@')||message.length<5)return res.status(400).json({error:'Please provide your name, email and a useful enquiry.'});const item={id:uid('enq'),reference:`NMH-ENQ-${String(Date.now()).slice(-8)}`,userId:req.user?.id||null,name,email,subject,message,status:'open',createdAt:now(),updatedAt:now()};const list=readJson('enquiries');list.push(item);writeJson('enquiries',list);res.status(201).json({reference:item.reference,message:'Enquiry received.'});});

app.get('/api/community/messages',requireAuth,requirePremium,(req,res)=>res.json(readJson('messages').slice(-150).map(({id,userId,author,text,createdAt})=>({id,userId,author,text,createdAt}))));
app.post('/api/community/messages',requireAuth,requirePremium,chatLimiter,requireCsrf,mediaUpload.single('media'),(req,res)=>{try{const text=clean(req.body.text,800);if(!text&&!req.file)return res.status(400).json({error:'Message cannot be empty.'});const m={id:uid('msg'),userId:req.user.id,author:clean(req.user.name,60),text,media:req.file?{name:safeFilename(req.file.originalname),mime:req.file.mimetype,path:path.basename(req.file.path)}:null,createdAt:now()};const list=readJson('messages');list.push(m);writeJson('messages',list.slice(-3000));broadcast(m);res.status(201).json(m);}catch(e){if(req.file)try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:e.message||'Message failed.'});}});
app.post('/api/community/messages/:id/report',requireAuth,requirePremium,requireCsrf,(req,res)=>{const message=readJson('messages').find(x=>x.id===req.params.id);if(!message)return res.status(404).json({error:'Message not found.'});const reason=clean(req.body.reason,300);if(!reason)return res.status(400).json({error:'A report reason is required.'});const list=readJson('reports');if(!list.some(x=>x.messageId===message.id&&x.userId===req.user.id))list.push({id:uid('rep'),messageId:message.id,userId:req.user.id,reason,status:'open',createdAt:now()});writeJson('reports',list);res.json({ok:true});});

function recordPayment({userId,reference,purpose,amount,currency,status='success'}){const list=readJson('payments');if(!list.some(x=>x.reference===reference)){list.push({id:uid('pay'),userId,reference,purpose,amount,currency,status,createdAt:now()});writeJson('payments',list);}return list;}
app.get('/api/payments/history',requireAuth,(req,res)=>res.json(readJson('payments').filter(x=>x.userId===req.user.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));

app.post('/api/payments/initialize',requireAuth,payLimiter,requireCsrf,async(req,res)=>{
  const purpose=req.body.purpose; if(!['subscription','transcript'].includes(purpose))return res.status(400).json({error:'Invalid payment purpose.'});
  if(purpose==='subscription'&&req.user.subscription?.active)return res.status(400).json({error:'Premium membership is already active.'});
  const currency=paymentCurrency(), amount=checkoutAmount(purpose);
  const reference=`NMH-${purpose.toUpperCase()}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const callback=`${APP_URL}/?route=payment-result&purpose=${purpose}`;
  if(!paystackReady()){
    if(String(process.env.ALLOW_DEMO_PAYMENTS||'true')!=='true')return res.status(503).json({error:'Paystack is not configured.'});
    return res.json({demo:true,reference,authorization_url:`${APP_URL}/?route=payment-result&purpose=${purpose}&reference=${encodeURIComponent(reference)}&demo=1`});
  }
  if(!amount)return res.status(503).json({error:`Payment amount for ${currency} is not configured.`});
  const planCode=String(process.env.PAYSTACK_SUBSCRIPTION_PLAN_CODE||'').trim();
  if(purpose==='subscription'&&!planCode)return res.status(503).json({error:'Create a monthly Paystack plan and put its plan code in .env first.'});
  try{
    const payload={email:req.user.email,amount:Math.round(amount*100),currency,reference,metadata:{userId:req.user.id,purpose,amountGhs:amount},callback_url:callback};
    if(purpose==='subscription')payload.plan=planCode;
    const r=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${paystackSecretKey()}`,'Content-Type':'application/json'},body:JSON.stringify(payload)}); const d=await r.json(); if(!r.ok||!d.status)return res.status(502).json({error:d.message||'Paystack could not initialise the payment.'});
    res.json({reference,authorization_url:d.data.authorization_url,purpose,currency,amount});
  }catch{res.status(502).json({error:'Unable to reach Paystack right now.'});}
});

app.get('/api/payments/verify/:reference',requireAuth,async(req,res)=>{
  const reference=clean(req.params.reference,180); const isDemo=reference.startsWith('NMH-')&&!paystackReady()&&(String(process.env.ALLOW_DEMO_PAYMENTS||'true')==='true');
  if(isDemo){const purpose=reference.includes('-TRANSCRIPT-')?'transcript':'subscription',amount=priceGhs(purpose);const users=readJson('users');const user=users.find(x=>x.id===req.user.id);if(purpose==='subscription')user.subscription={active:true,status:'active',provider:'demo',reference,updatedAt:now()};writeJson('users',users);recordPayment({userId:req.user.id,reference,purpose,amount,currency:'GHS',status:'success'});return res.json({ok:true,purpose,user:safeUser(user),demo:true});}
  if(!paystackReady())return res.status(503).json({error:'Paystack is not configured.'});
  try{
    const r=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{headers:{Authorization:`Bearer ${paystackSecretKey()}`}});const d=await r.json();if(!r.ok||!d.status||d.data.status!=='success')return res.status(402).json({error:'Paystack has not confirmed a successful payment.'});
    const tx=d.data,md=tx.metadata||{};if(md.userId!==req.user.id)return res.status(403).json({error:'Payment owner mismatch.'});const purpose=md.purpose;if(!['subscription','transcript'].includes(purpose))return res.status(400).json({error:'Payment purpose could not be confirmed.'});const expected=checkoutAmount(purpose);if(expected && Number(tx.amount)!==Math.round(expected*100))return res.status(400).json({error:'Verified payment amount does not match the Hub price.'});if(tx.currency && String(tx.currency).toUpperCase()!==paymentCurrency())return res.status(400).json({error:'Verified payment currency does not match the configured checkout currency.'});
    const users=readJson('users'),user=users.find(x=>x.id===req.user.id);if(purpose==='subscription')user.subscription={active:true,status:'active',provider:'paystack',reference,planCode:process.env.PAYSTACK_SUBSCRIPTION_PLAN_CODE||null,subscriptionCode:tx.subscription_code||tx.subscription?.subscription_code||null,updatedAt:now()};writeJson('users',users);recordPayment({userId:req.user.id,reference,purpose,amount:Number(tx.amount||0)/100,currency:tx.currency||paymentCurrency(),status:'success'});res.json({ok:true,purpose,user:safeUser(user),demo:false});
  }catch{res.status(502).json({error:'Unable to verify the Paystack transaction right now.'});}
});

app.post('/api/transcript-evaluation',requireAuth,requireCsrf,upload.fields([{name:'transcript',maxCount:1},{name:'certificate',maxCount:1},{name:'registration',maxCount:1},{name:'idDocument',maxCount:1},{name:'cv',maxCount:1}]),(req,res)=>{
  try{
    const required=['fullName','profession','institution','qualification','targetCountry','pathwayType','paymentReference'].every(k=>clean(req.body[k],220)); if(!required){cleanupFiles(req.files);return res.status(400).json({error:'Complete the required evaluation fields.'});}
    for(const list of Object.values(req.files||{}))for(const file of list)if(!fileMagicOk(file)){cleanupFiles(req.files);return res.status(400).json({error:'One uploaded file failed its file-validation check.'});}
    const payment=readJson('payments').find(x=>x.reference===req.body.paymentReference&&x.userId===req.user.id&&x.purpose==='transcript'&&x.status==='success');if(!payment){cleanupFiles(req.files);return res.status(402).json({error:`The GHS ${priceGhs('transcript')} Document Evaluation payment has not been verified.`});}
    const preliminary=recommendedPathway(req.body.targetCountry,req.body.pathwayType,req.body.profession); const recommendation={...preliminary,links:[]};
    const files={};for(const [field,list] of Object.entries(req.files||{}))files[field]=list[0]?path.basename(list[0].path):null;
    const item={id:uid('eval'),reference:`NMH-DOC-${String(Date.now()).slice(-8)}`,userId:req.user.id,fullName:clean(req.body.fullName,100),profession:clean(req.body.profession,70),institution:clean(req.body.institution,160),country:clean(req.body.country,80),qualification:clean(req.body.qualification,160),graduationYear:clean(req.body.graduationYear,20),experienceYears:clean(req.body.experienceYears,20),targetCountry:clean(req.body.targetCountry,80),pathwayType:req.body.pathwayType==='study'?'study':'work',specialty:clean(req.body.specialty,100),englishStatus:clean(req.body.englishStatus,100),notes:clean(req.body.notes,3000),files,paymentReference:req.body.paymentReference,recommendation,status:'received',createdAt:now(),updatedAt:now()};
    const list=readJson('submissions');list.push(item);writeJson('submissions',list);res.status(201).json({ok:true,reference:item.reference,status:item.status,recommendation});
  }catch(e){cleanupFiles(req.files);res.status(400).json({error:e.message||'Unable to process evaluation.'});}
});
app.get('/api/transcript-evaluation',requireAuth,(req,res)=>res.json(readJson('submissions').filter(x=>x.userId===req.user.id).map(x=>({reference:x.reference,status:x.status,targetCountry:x.targetCountry,pathwayType:x.pathwayType,recommendation:x.recommendation,createdAt:x.createdAt,updatedAt:x.updatedAt}))));

const LESSON_HTML_ALLOWED_TAGS=new Set(['h4','p','ul','li','b','i','ol']);
function sanitizeLessonHtml(html){
  return String(html||'')
    .replace(/<script[\s\S]*?<\/script>/gi,'')
    .replace(/<style[\s\S]*?<\/style>/gi,'')
    .replace(/<\/?([a-zA-Z0-9]+)([^>]*)>/g,(full,tag,attrs)=>{
      const lower=tag.toLowerCase();
      if(!LESSON_HTML_ALLOWED_TAGS.has(lower))return '';
      const closing=full.startsWith('</');
      return closing?`</${lower}>`:`<${lower}>`;
    });
}
const TRACK_DOMAIN_HINTS={
  'Nursing Core':['Foundations','Medical-Surgical','Emergency','Emergency & Critical Care','Anatomy','Medication Safety','Infection Prevention','Geriatrics','Palliative Care'],
  'Midwifery Core':['Maternal','Maternal Care','Midwifery','Postnatal','Newborn Care'],
  'Community & Public Health':['Community','Community Health','Public Health'],
  'Professional Practice':['Professional Practice','Leadership','Research','Mental Health'],
  'Nutrition':['Nutrition']
};
function relatedQuestionsFor(module,lesson){
  const hints=TRACK_DOMAIN_HINTS[module.track]||[];
  const words=String(lesson).toLowerCase().split(/[^a-z]+/).filter(w=>w.length>3);
  const scored=readJson('questions').map(q=>{
    let score=hints.includes(q.domain)?1:0;
    const text=`${q.question} ${q.domain}`.toLowerCase();
    for(const w of words) if(text.includes(w)) score+=2;
    return {q,score};
  }).filter(x=>x.score>0).sort((a,b)=>b.score-a.score);
  return scored.slice(0,2).map(x=>x.q);
}
const LESSON_ANGLES=[
  {label:'Assessment first',prompt:'Start by identifying what you would assess first and why, before deciding on any action.'},
  {label:'Priority and escalation',prompt:'Focus on distinguishing the first priority action from a later one, and knowing exactly when to escalate to a senior colleague.'},
  {label:'Compare and contrast',prompt:'Compare this concept with a related one you already know from an earlier lesson, and write down what is genuinely different.'},
  {label:'Teach-back',prompt:'Explain this concept out loud as if teaching a junior colleague, without looking at any notes.'}
];
function buildFallbackLessonNotes(module,lesson,lessonIndex,related){
  const topics=module.topics;
  const coreTopic=topics[lessonIndex%topics.length]||topics[0];
  const siblingTopics=topics.filter(t=>t!==coreTopic);
  const angle=LESSON_ANGLES[lessonIndex%LESSON_ANGLES.length];
  const worked=related[0]?`<h4>Worked example from the Hub question bank</h4><p><b>Question:</b> ${escapeHtml(related[0].question)}</p><p><b>Why this matters here:</b> ${escapeHtml(related[0].explanation||'Review the related concept and connect it to this scenario.')}</p>`:'';
  const secondQuestion=related[1]?`<p><b>Try another:</b> ${escapeHtml(related[1].question)}</p>`:'';
  return `<h4>Learning focus — ${escapeHtml(angle.label)}</h4><p>This lesson, <b>${escapeHtml(lesson)}</b>, is where <b>${escapeHtml(module.title)}</b> gets specific about <b>${escapeHtml(coreTopic)}</b>. ${escapeHtml(angle.prompt)}</p><h4>Core concepts</h4><p>Work through <b>${escapeHtml(coreTopic)}</b> as a sequence: identify the relevant concept, explain the mechanism or rationale, recognise key assessment findings, identify the appropriate priority action, and understand when escalation or referral is needed.</p><p>Related areas in this module: ${siblingTopics.map(t=>`<b>${escapeHtml(t)}</b>`).join(', ')}. Compare them against <b>${escapeHtml(coreTopic)}</b> and note what is similar and what is different.</p>${worked}${secondQuestion}<h4>Why it matters</h4><p>Strong nursing and midwifery practice depends on accurate assessment, safe communication, appropriate prioritisation, documentation, ethical practice and evidence-informed decisions. Ask yourself: <i>What would I assess first? Why? What finding would change my plan? Who should I escalate to?</i></p><h4>Exam focus</h4><p>For licensing-style questions on <b>${escapeHtml(coreTopic)}</b>, identify the task in the stem first. Distinguish the first priority from a later action, distinguish assessment from intervention, and avoid options that are unsafe, outside scope or unsupported by the information in the scenario.</p>`;
}
app.post('/api/ai/lesson-notes',requireAuth,requirePremium,requireCsrf,async(req,res)=>{
  const moduleId=clean(req.body.moduleId,100),lessonIndex=Math.max(0,Number(req.body.lessonIndex||0));
  const module=readJson('syllabus').find(m=>m.id===moduleId); if(!module)return res.status(404).json({error:'Module not found.'});
  const lesson=module.lessons[lessonIndex]; if(!lesson)return res.status(404).json({error:'Lesson not found.'});
  const cacheKey=`${moduleId}::${lessonIndex}`; const cache=readJson('lessonNotes'); const cached=cache.find(x=>x.key===cacheKey);
  const related=relatedQuestionsFor(module,lesson); const relatedQuestions=related.map(q=>({id:q.id,question:q.question,domain:q.domain}));
  if(cached)return res.json({notesHtml:cached.notesHtml,ai:cached.ai,relatedQuestions});
  const fallback=buildFallbackLessonNotes(module,lesson,lessonIndex,related);
  if(!process.env.OPENAI_API_KEY||!process.env.OPENAI_MODEL){cache.push({key:cacheKey,notesHtml:fallback,ai:false,createdAt:now()});writeJson('lessonNotes',cache.slice(-8000));return res.json({notesHtml:fallback,ai:false,relatedQuestions});}
  const prompt=`Write detailed nursing/midwifery study notes for Nurses & Midwives Hub, for the lesson "${lesson}" inside the module "${module.title}" (${module.track}). Module topics: ${module.topics.join(', ')}. Write 500-700 words as HTML using only <h4>, <p>, <ul>, <li>, <b>, <i> tags (no <html>/<body>/<script>). Cover: learning focus specific to this exact lesson (not the whole module), core concepts explained step by step, clinical/professional application, common pitfalls, and exam-technique focus for licensing-style questions. Never claim to reproduce an official exam paper and never give individualized diagnosis or prescribing instructions. Return only the HTML, no surrounding commentary or markdown fences.`;
  try{
    const r=await fetch(process.env.OPENAI_BASE_URL||'https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:process.env.OPENAI_MODEL,input:prompt,max_output_tokens:1400})});
    const data=await r.json(); if(!r.ok)throw new Error('ai_failed');
    let text=data.output_text; if(!text&&Array.isArray(data.output))text=data.output.flatMap(x=>x.content||[]).map(x=>x.text||'').join('');
    text=sanitizeLessonHtml(String(text||'').replace(/^```html\s*|^```\s*|\s*```$/g,'').trim());
    if(!text)throw new Error('empty');
    cache.push({key:cacheKey,notesHtml:text,ai:true,createdAt:now()}); writeJson('lessonNotes',cache.slice(-8000));
    res.json({notesHtml:text,ai:true,relatedQuestions});
  }catch{cache.push({key:cacheKey,notesHtml:fallback,ai:false,createdAt:now()});writeJson('lessonNotes',cache.slice(-8000));res.json({notesHtml:fallback,ai:false,relatedQuestions});}
});

app.post('/api/ai/daily-tutorial',requireAuth,requirePremium,requireCsrf,async(req,res)=>{
  const syllabus=readJson('syllabus'); const day=Math.floor((Date.now()-new Date(new Date().getFullYear(),0,0))/86400000); const module=syllabus[day%syllabus.length];
  const fallback={title:`Daily Tutorial — ${module.title}`,moduleId:module.id,objectives:[`Explain the core concepts of ${module.topics[0]}.`,`Relate ${module.topics[0]} to safe clinical practice.`,`Identify common exam traps and priority decisions.`],lesson:`Today focus on ${module.topics.join(', ')}. Work through the module lessons, make one-page notes, then complete a short practice set.`,practice:[`Define ${module.topics[0]}.`,`List two clinical or professional implications of ${module.topics[1]||module.topics[0]}.`,`Write one exam-style priority question from this topic and justify the answer.`],source:'Nurses & Midwives Hub tutorial engine'};
  if(!process.env.OPENAI_API_KEY || !process.env.OPENAI_MODEL)return res.json({tutorial:fallback,ai:false});
  const prompt=`Create an extensive but digestible daily tutorial for Nurses & Midwives Hub based on the syllabus module "${module.title}". Topics: ${module.topics.join(', ')}. Provide title, 4 objectives, a 700-1000 word lesson with headings, why-it-matters explanations, 5 key points, 5 practice prompts, 5 key takeaways, and 3 original MCQs with answers and rationales. Do not claim to reproduce official exam papers. Return JSON with keys title, objectives, lesson, keyPoints, practice, takeaways, mcqs.`;
  try{
    const r=await fetch(process.env.OPENAI_BASE_URL||'https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:process.env.OPENAI_MODEL,input:prompt,max_output_tokens:1000})});
    const data=await r.json(); if(!r.ok) return res.json({tutorial:fallback,ai:false});
    let text=data.output_text; if(!text&&Array.isArray(data.output)) text=data.output.flatMap(x=>x.content||[]).map(x=>x.text||'').join('');
    if(!text)return res.json({tutorial:fallback,ai:false});
    const json=JSON.parse(String(text).replace(/^```json\s*|\s*```$/g,'')); res.json({tutorial:{...json,moduleId:module.id},ai:true});
  }catch{res.json({tutorial:fallback,ai:false});}
});


app.post('/api/ai/tutor',requireAuth,requirePremium,requireCsrf,async(req,res)=>{
  const question=clean(req.body.question,1200),topic=clean(req.body.topic,180)||'nursing and midwifery practice';
  if(question.length<4)return res.status(400).json({error:'Ask a complete study question.'});
  const matched=readJson('syllabus').find(m=>m.title.toLowerCase().includes(topic.toLowerCase())||m.topics.some(t=>t.toLowerCase().includes(topic.toLowerCase()))); const fallback={answer:`Let's work through this step by step. ${matched?`The relevant Hub module is ${matched.title}. Its key areas include ${matched.topics.slice(0,5).join(', ')}.`:''} Your question is: “${question}”. Start by defining the concept, then connect it to assessment, underlying physiology or rationale, safe practice, common complications and examination priorities. Study the related lesson and explain the idea back in your own words.`,keyPoints:['Define the concept clearly.','Explain why it matters in practice.','Identify priority actions and common pitfalls.','Apply the concept to a short clinical scenario.'],examTip:'For licensing-style questions, read the stem carefully, identify the priority, compare every option against the safest immediate action, and avoid choosing an option merely because it is generally correct.',followUps:['Explain the same concept with a clinical example.','What would change your management priority?','Give me 3 licensing-style MCQs on this topic.']};
  if(!process.env.OPENAI_API_KEY||!process.env.OPENAI_MODEL)return res.json({answer:fallback,ai:false});
  const history=Array.isArray(req.body.history)?req.body.history.slice(-8).map(x=>`${x.role||'user'}: ${clean(x.text,900)}`).join('\n'):''; const prompt=`You are the senior educational tutor inside Nurses & Midwives Hub. Teach nurses, midwives, nutrition professionals and public-health learners with a calm, rigorous, exam-ready style. Never claim to be an official regulator, never reproduce official exam papers, and do not provide individualized diagnosis, prescribing, or unsafe treatment instructions. Explain the learner's question in layers: simple explanation first, deeper mechanism/rationale, clinical/professional application, common misconceptions, exam priorities, and a short knowledge check. Topic: ${topic}. Current question: ${question}. Recent conversation for context:\n${history||'(none)'}. Return JSON with keys answer, keyPoints, examTip, followUps, miniQuiz. miniQuiz must contain 2-3 original questions with concise answers.`;
  try{const r=await fetch(process.env.OPENAI_BASE_URL||'https://api.openai.com/v1/responses',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:process.env.OPENAI_MODEL,input:prompt,max_output_tokens:1200})});const d=await r.json();if(!r.ok)return res.json({answer:fallback,ai:false});let text=d.output_text;if(!text&&Array.isArray(d.output))text=d.output.flatMap(x=>x.content||[]).map(x=>x.text||'').join('');const json=JSON.parse(String(text).replace(/^```json\s*|\s*```$/g,''));res.json({answer:json,ai:true});}catch{res.json({answer:fallback,ai:false});}
});



// Lightweight server-side source refresh. Uses public RSS where available and keeps Hub pages readable internally.
async function fetchText(url){const r=await fetch(url,{headers:{'User-Agent':'Nurses-Midwives-Hub/1.0'},redirect:'follow'});if(!r.ok)throw new Error(`HTTP ${r.status}`);return await r.text();}
function stripTags(x){return String(x||'').replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ').trim();}
function parseRss(xml,limit=12){const out=[];const blocks=String(xml).match(/<item[\s\S]*?<\/item>/gi)||[];for(const b of blocks.slice(0,limit)){const title=(b.match(/<title(?:\s[^>]*)?>([\s\S]*?)<\/title>/i)||[])[1];const link=(b.match(/<link(?:\s[^>]*)?>([\s\S]*?)<\/link>/i)||[])[1];const desc=(b.match(/<description(?:\s[^>]*)?>([\s\S]*?)<\/description>/i)||[])[1];const pub=(b.match(/<pubDate(?:\s[^>]*)?>([\s\S]*?)<\/pubDate>/i)||[])[1];if(title&&link)out.push({title:stripTags(title),link:stripTags(link),summary:stripTags(desc||''),date:pub?new Date(stripTags(pub)).toISOString().slice(0,10):now().slice(0,10)});}return out;}
function parseHtmlArticles(html,limit=10){
  const out=[]; const re=/<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi; let m;
  while((m=re.exec(String(html))) && out.length<limit*4){const title=stripTags(m[2]); if(title && title.length>=20 && title.length<=220){let link=m[1];out.push({title,link});}}
  const unique=[];const seen=new Set();for(const x of out){const k=x.title+'|'+x.link;if(!seen.has(k)){seen.add(k);unique.push(x);}}
  return unique.slice(0,limit);
}
function absoluteUrl(base,href){try{return new URL(href,base).href}catch{return href}}
async function refreshOfficialNews(){
  const sources=[
    {name:'WHO Africa',url:'https://www.afro.who.int/rss/featured-news.xml',category:'Global Health',type:'rss'},
    {name:'WHO Africa',url:'https://www.afro.who.int/rss/press-releases.xml',category:'Global Health',type:'rss'},
    {name:'N&MC Ghana',url:'https://www.nmc.gov.gh/web/news-and-events',category:'N&MC Ghana',type:'html'},
    {name:'Ghana Ministry of Health',url:'https://moh.gov.gh/category/news/',category:'Ghana Health',type:'html'}
  ];
  const news=readJson('news'); let changed=0;
  for(const src of sources){try{const raw=await fetchText(src.url);if(src.type==='rss'){for(const item of parseRss(raw,12)){const key=item.link||item.title;if(news.some(n=>n.sourceUrl===key))continue;news.unshift({id:uid('news'),category:src.category,title:item.title,date:item.date,source:src.name,sourceUrl:key,summary:item.summary||`New ${src.category.toLowerCase()} update from ${src.name}.`,body:[item.summary||'The Hub provides an internal summary and context. The authoritative source remains available through the source button.'],lastVerified:now().slice(0,10),autoImported:true});changed++;}}else{for(const item of parseHtmlArticles(raw,10)){const key=absoluteUrl(src.url,item.link);if(news.some(n=>n.sourceUrl===key))continue;news.unshift({id:uid('news'),category:src.category,title:item.title,date:now().slice(0,10),source:src.name,sourceUrl:key,summary:`New update published by ${src.name}. The Hub has imported the headline for internal reading and keeps source attribution visible.`,body:[`This Hub entry highlights a recent publication from ${src.name}. The authoritative source is retained for verification. The Hub does not reproduce an external article verbatim.`],lastVerified:now().slice(0,10),autoImported:true});changed++;}}}catch{} }
  if(changed)writeJson('news',news.slice(0,500)); return changed;
}
function parseOpportunityFeed(raw,source,defaultCountry){
  const text=String(raw||'');
  if(/<item[\s\S]*?<\/item>/i.test(text)) return parseRss(text,20).map(x=>({country:defaultCountry||'International',title:x.title,employer:source,location:defaultCountry||'International',type:'See source',closing:'',source,applicationUrl:x.link,verified:true,lastVerified:now().slice(0,10),summary:x.summary||'Official opportunity imported from the configured source feed.',autoImported:true}));
  try{const d=JSON.parse(text);const arr=Array.isArray(d)?d:(Array.isArray(d.jobs)?d.jobs:(Array.isArray(d.items)?d.items:[]));return arr.slice(0,30).map(x=>({country:x.country||defaultCountry||'International',title:clean(x.title,220),employer:clean(x.employer,180)||source,location:clean(x.location,160)||x.country||defaultCountry||'International',type:clean(x.type,100)||'See source',closing:clean(x.closing||x.deadline,50),source:clean(x.source,160)||source,applicationUrl:clean(x.applicationUrl||x.link||x.url,500),verified:true,lastVerified:now().slice(0,10),summary:clean(x.summary||x.description,900)||'Official opportunity imported from the configured source.',autoImported:true})).filter(x=>x.title&&/^https?:\/\//i.test(x.applicationUrl));}catch{return []}
}
async function refreshOpportunities(){
  let configs=[];try{configs=JSON.parse(process.env.OPPORTUNITY_FEEDS_JSON||'[]');if(!Array.isArray(configs))configs=[];}catch{configs=[]}
  if(!configs.length)return 0; const jobs=readJson('jobs'); let changed=0;
  for(const cfg of configs){try{const url=clean(cfg.url,600),source=clean(cfg.source,160)||url,defaultCountry=clean(cfg.country,80);if(!/^https?:\/\//i.test(url))continue;const raw=await fetchText(url);for(const item of parseOpportunityFeed(raw,source,defaultCountry)){if(jobs.some(j=>j.applicationUrl===item.applicationUrl&&j.title===item.title))continue;jobs.unshift({...item,id:uid('job')});changed++;}}catch{}}
  if(changed)writeJson('jobs',jobs.slice(0,500));return changed;
}
async function refreshAllSources(){const newsAdded=await refreshOfficialNews();const jobsAdded=await refreshOpportunities();return {newsAdded,jobsAdded};}
let refreshBusy=false;
async function autoRefresh(){if(refreshBusy)return;refreshBusy=true;try{await refreshAllSources();}finally{refreshBusy=false;}}
setTimeout(autoRefresh,2500); setInterval(autoRefresh,Number(process.env.AUTO_REFRESH_MINUTES||30)*60000);



app.get('/api/admin/support/:userId',requireAuth,requireAdmin,(req,res)=>res.json(readJson('supportMessages').filter(x=>x.userId===req.params.userId).slice(-300)));
app.post('/api/admin/support/:userId',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const userId=clean(req.params.userId,100),user=readJson('users').find(x=>x.id===userId);if(!user)return res.status(404).json({error:'User not found.'});const text=clean(req.body.text,1200);if(!text)return res.status(400).json({error:'Message cannot be empty.'});const item={id:uid('sup'),userId,sender:'admin',adminName:'Hub Admin',text,createdAt:now()};const list=readJson('supportMessages');list.push(item);writeJson('supportMessages',list.slice(-20000));createNotification(userId,'admin_message','Message from Hub Admin',text.slice(0,160),'community');broadcastToUser(userId,{type:'support_message',data:item});res.status(201).json(item);});
app.get('/api/admin/evaluations/:id/file/:field',requireAuth,requireAdmin,(req,res)=>{const allowed=['transcript','certificate','registration','idDocument','cv'];if(!allowed.includes(req.params.field))return res.sendStatus(404);const item=readJson('submissions').find(x=>x.id===req.params.id);if(!item)return res.sendStatus(404);const name=item.files?.[req.params.field];if(!name)return res.sendStatus(404);const safe=path.basename(name);if(!/^[A-Za-z0-9._-]+$/.test(safe))return res.sendStatus(404);res.sendFile(path.join(UPLOADS,safe));});

// Admin APIs
app.post('/api/admin/refresh-sources',requireAuth,requireAdmin,requireCsrf,async(req,res)=>{try{const result=await refreshAllSources();res.json({ok:true,...result,refreshedAt:now()});}catch(e){res.status(502).json({error:e.message||'Source refresh failed.'});}});

app.get('/api/admin/summary',requireAuth,requireAdmin,(req,res)=>{const users=readJson('users');res.json({users:users.length,activePremium:users.filter(u=>u.subscription?.active).length,activeTrials:users.filter(u=>u.trial?.status==='active'&&u.trial.endsAt&&new Date(u.trial.endsAt)>new Date()).length,enquiries:readJson('enquiries').length,evaluations:readJson('submissions').length,payments:readJson('payments').length,pendingStories:readJson('stories').filter(x=>x.status==='pending').length,openReports:readJson('reports').filter(x=>x.status==='open').length});});
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>res.json(readJson('users').map(safeUser)));
app.get('/api/admin/enquiries',requireAuth,requireAdmin,(req,res)=>res.json(readJson('enquiries')));
app.get('/api/admin/evaluations',requireAuth,requireAdmin,(req,res)=>res.json(readJson('submissions')));
app.get('/api/admin/stories',requireAuth,requireAdmin,(req,res)=>res.json(readJson('stories')));
app.get('/api/admin/reports',requireAuth,requireAdmin,(req,res)=>res.json(readJson('reports')));
app.patch('/api/admin/stories/:id',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const list=readJson('stories'),item=list.find(x=>x.id===req.params.id);if(!item)return res.status(404).json({error:'Story not found.'});if(!['pending','approved','rejected'].includes(req.body.status))return res.status(400).json({error:'Invalid status.'});item.status=req.body.status;item.reviewedAt=now();writeJson('stories',list);res.json(item);});
app.patch('/api/admin/enquiries/:id',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const list=readJson('enquiries'),item=list.find(x=>x.id===req.params.id);if(!item)return res.status(404).json({error:'Enquiry not found.'});if(['open','in_progress','resolved','closed'].includes(req.body.status))item.status=req.body.status;item.updatedAt=now();writeJson('enquiries',list);res.json(item);});
app.patch('/api/admin/evaluations/:id',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const list=readJson('submissions'),item=list.find(x=>x.id===req.params.id);if(!item)return res.status(404).json({error:'Evaluation not found.'});if(['received','reviewing','needs_information','completed','closed'].includes(req.body.status))item.status=req.body.status;if(req.body.finalRoute){try{item.recommendation=typeof req.body.finalRoute==='string'?JSON.parse(req.body.finalRoute):req.body.finalRoute}catch{return res.status(400).json({error:'finalRoute must be valid JSON.'})}}if(item.status==='completed' && !item.recommendation?.links?.length){const r=recommendedPathway(item.targetCountry,item.pathwayType,item.profession);item.recommendation={...r,links:r.links||[]};item.finalLinkIssuedAt=now();}item.updatedAt=now();writeJson('submissions',list);res.json(item);});
app.post('/api/admin/jobs',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const item={id:uid('job'),country:clean(req.body.country,80),title:clean(req.body.title,220),employer:clean(req.body.employer,180),type:clean(req.body.type,100),location:clean(req.body.location,160),closing:clean(req.body.closing,40),source:clean(req.body.source,160),applicationUrl:clean(req.body.applicationUrl,500),sponsorship:clean(req.body.sponsorship,180),verified:true,lastVerified:now().slice(0,10),summary:clean(req.body.summary,900)};if(!item.title||!item.country||!item.source||!/^https?:\/\//i.test(item.applicationUrl))return res.status(400).json({error:'Country, title, source and a valid application URL are required.'});const list=readJson('jobs');list.unshift(item);writeJson('jobs',list);res.status(201).json(item);});
app.post('/api/admin/news',requireAuth,requireAdmin,requireCsrf,(req,res)=>{const paragraphs=String(req.body.body||'').split(/\n\s*\n/).map(x=>clean(x,1500)).filter(Boolean).slice(0,12);const item={id:uid('news'),category:clean(req.body.category,80),title:clean(req.body.title,220),date:clean(req.body.date,30)||now().slice(0,10),source:clean(req.body.source,160),sourceUrl:clean(req.body.sourceUrl,500),summary:clean(req.body.summary,900),body:paragraphs,lastVerified:now().slice(0,10)};if(!item.title||!item.source||!item.sourceUrl||!paragraphs.length)return res.status(400).json({error:'Headline, source, source URL and article body are required.'});const list=readJson('news');list.unshift(item);writeJson('news',list);res.status(201).json(item);});

app.use((err,req,res,next)=>{ if(err instanceof multer.MulterError || err?.message) return res.status(400).json({error:err.message||'Request failed.'}); next(err); });

const httpServer=app.listen(PORT,()=>console.log(`Nurses & Midwives Hub running at ${APP_URL}`));
const wss=new WebSocketServer({server:httpServer,path:'/ws'});const clients=new Map();
function broadcast(payload){for(const entry of clients.values())if(entry.ws.readyState===1)entry.ws.send(JSON.stringify(payload?.type?payload:{type:'message',data:payload}));}
wss.on('connection',(ws,req)=>{const s=sessionFor(req);if(!s||s.role!=='user'){ws.close(1008,'Authentication required');return;}const u=readJson('users').find(x=>x.id===s.userId);if(!u||!hasPremiumAccess(u)){ws.close(1008,'Premium membership required');return;}const key=uid('ws');clients.set(key,{ws,userId:u.id});ws.send(JSON.stringify({type:'hello',data:{name:u.name}}));ws.on('close',()=>clients.delete(key));ws.on('error',()=>clients.delete(key));});

// Centralised request/upload error handling. Register before the server begins accepting traffic.

