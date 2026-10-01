import express from 'express'; import cookieParser from 'cookie-parser';
const app=express();app.use(express.urlencoded({extended:false}),cookieParser());
// Deliberately vulnerable LOCAL test fixture. Fake data only. Never deploy publicly.
app.get('/',(req,res)=>{res.cookie('weak_session','fake-session');res.type('html').send(`<h1>Xdigitex local test target</h1><a href="/reflect?q=hello">Reflection</a><a href="/go?next=/">Redirect</a><script src="/app.js"></script><form method="post" action="/api/profile"><input name="userId" value="1"><button>Profile</button></form>`)});
app.get('/reflect',(req,res)=>res.type('html').send(`<p>Search: ${String(req.query.q||'')}</p>`));
app.get('/go',(req,res)=>res.redirect(String(req.query.next||'/')));
app.get('/app.js',(_req,res)=>res.type('application/javascript').send(`window.PUBLIC_CONFIG={apiKey:"FAKE_TEST_API_KEY_123456789"};const q=location.hash.slice(1);document.querySelector('body').innerHTML += q;//# sourceMappingURL=/app.js.map`));
app.get('/app.js.map',(_req,res)=>res.json({version:3,sources:['src/app.ts'],names:[],mappings:''}));
app.get('/config.json',(_req,res)=>res.json({databaseUrl:'postgresql://fake:fake-password@invalid.local/fake'}));
app.post('/api/profile',express.urlencoded({extended:false}),(req,res)=>res.json({requestedUserId:req.body.userId,note:'deliberate local authorization mistake fixture'}));
app.get('/health',(_req,res)=>res.json({ok:true}));app.listen(Number(process.env.PORT||4010),'0.0.0.0',()=>console.log('local vulnerable test target on 4010'));
