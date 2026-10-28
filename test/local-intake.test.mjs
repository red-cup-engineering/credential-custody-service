import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { startLocalCredentialIntake } from "../src/local-intake.mjs";
import { openStore } from "../src/store.mjs";
const id="test.requested-key", metadata={kind:"api-key",holders:["test-host"],consumers:[]};
function memory(){let record=null;return {record:()=>record,requests:()=>[{id,state:"requested"}],recipients:()=>({hosts:{"test-host":"age-test"}}),put:async(_id,_value,fields)=>{record={id,...fields};}};}
async function start(store=memory(),extra={}){const i=await startLocalCredentialIntake({store,id,metadata,pattern:/^rk_test_[a-z]+$/,ttlMs:10000,...extra});return {...i,token:new URL(i.url).hash.slice(1)};}
function call(i,{path="/credential",method="POST",headers={},body=JSON.stringify({value:"rk_test_fixture"}),token=i.token}={}){
return new Promise((resolve,reject)=>{const u=new URL(i.origin+path);const r=request(u,{method,headers:{Authorization:"Bearer "+token,Origin:i.origin,"Content-Type":"application/json",Connection:"close",...headers}},res=>{let text="";res.setEncoding("utf8");res.on("data",s=>text+=s);res.on("end",()=>resolve({status:res.statusCode,headers:res.headers,text}));});r.on("error",reject);r.end(method==="GET"?undefined:body);});}
test("requested custody, holders and bounded policy required",async()=>{
await assert.rejects(start(memory(),{ttlMs:900001}),TypeError);
await assert.rejects(start(memory(),{pattern:/x/g}),TypeError);
const s=memory();s.record=()=>({id});await assert.rejects(start(s),TypeError);
const s2=memory();s2.requests=()=>[];await assert.rejects(start(s2),TypeError);
});
test("host, token, origin, media and input boundaries refuse without writing",async()=>{
const s=memory();let puts=0;s.put=async()=>{puts++};const i=await start(s);
try{
for(const [options,status] of [
[{headers:{Host:"evil.invalid"}},403],[{token:"wrong"},403],
[{headers:{Origin:"https://evil.invalid"}},403],
[{headers:{"Content-Type":"text/plain"}},415],
[{headers:{"Content-Encoding":"gzip"}},415],
[{body:'{"value":"rk_test_fixture","extra":true}'},400],
[{body:'{"value":"sk_live_other"}'},400],
[{body:"{"},400]])assert.equal((await call(i,options)).status,status);
assert.equal(puts,0);
}finally{await i.close();}
});
test("bounded body never reaches custody",async()=>{const s=memory();let puts=0;s.put=async()=>puts++;const i=await start(s);try{const r=await call(i,{body:JSON.stringify({value:"rk_test_"+"x".repeat(5000)})});assert.equal(r.status,413);assert.equal(puts,0);}finally{await i.close();}});
test("HTML uses nonce event listener and no credential URL or inline handler",async()=>{const i=await start();try{const html=await call(i,{path:"/",method:"GET"});assert.equal(html.status,200);assert.equal(html.headers["cache-control"],"no-store");assert.match(html.headers["content-security-policy"],/frame-ancestors 'none'/);assert.match(html.text,/addEventListener/);assert.doesNotMatch(html.text,/onclick=|onsubmit=/);assert.ok(!html.text.includes(i.token));assert.match(html.text,/history.replaceState/);assert.equal((await call(i,{path:"/details",method:"GET",token:"wrong"})).status,403);}finally{await i.close();}});
test("real encrypted custody is written once and closes after response",async()=>{
const dir=await mkdtemp(join(tmpdir(),"custody-intake-test-"));let i;
try{const s=openStore(dir);await s.initHost("test-host");s.request(id,{by:"test-host",reason:"native receiving fixture"});i=await start(s);
const response=await call(i);assert.equal(response.status,201);assert.deepEqual(await i.completed,{state:"stored-unverified",id});assert.equal(await s.get(id,"test-host"),"rk_test_fixture");
assert.ok(!(await readFile(join(dir,"sealed",id+".age"),"utf8")).includes("rk_test_fixture"));await assert.rejects(start(s),TypeError);
}finally{if(i)await i.close();await rm(dir,{recursive:true,force:true});}});
test("concurrent submission cannot duplicate an admitted write; cancellation drains it",async()=>{
const s=memory();let release,puts=0;const blocked=new Promise(r=>release=r);s.put=async()=>{puts++;await blocked};const i=await start(s);const first=call(i);
while(!puts)await new Promise(r=>setTimeout(r,5));
assert.equal((await call(i)).status,409);const closed=i.close();release();assert.equal((await first).status,201);assert.equal((await closed).state,"stored-unverified");assert.equal(puts,1);
});
test("expiry and custody failure preserve failure semantics",async()=>{
const i=await start(memory(),{ttlMs:10});assert.equal((await i.completed).state,"expired");
const s=memory();s.put=async()=>{throw Error("secret-like internal error")};const j=await start(s);try{const r=await call(j);assert.equal(r.status,500);assert.ok(!r.text.includes("secret-like"));}finally{await j.close();}
});
