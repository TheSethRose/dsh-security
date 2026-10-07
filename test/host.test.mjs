import {createServer} from 'node:http';
import test from 'node:test';import assert from 'node:assert/strict';import {Readable,Writable,PassThrough} from 'node:stream';import {mkdtemp} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {randomUUID} from 'node:crypto';import {apply,inject} from '../host.mjs';
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};const turn=()=>new Promise(resolve=>setImmediate(resolve));
async function harness(options={}){
 const repo=await mkdtemp(path.join(os.tmpdir(),'security-host-')),state=await mkdtemp(path.join(os.tmpdir(),'security-host-state-'));
 const workspaces=[{id:'workspace-a',path:repo,title:'A',sessionIds:['session-a']},{id:'workspace-b',path:repo,title:'B',sessionIds:['session-b']}];
 const maps={scans:new Map(options.scans??[]),leases:new Map(options.leases??[])},effects=[],calls=[],jobs=[],engines=new Map(),logs=[];let tool,handler,spec,closed=false;
 const models=[{provider:'deepseek',id:'deepseek-v4-pro',name:'Fixture model'},{provider:'other',id:'custom-model',name:'Fixture model'}];
 const started=deferred();const ctx={
  storageDomain:{open:async value=>{spec=value;return {table:name=>({get:id=>{const v=maps[name].get(id);return v===undefined?undefined:structuredClone(v);},entries:()=>[...maps[name]].map(([k,v])=>[k,structuredClone(v)])[Symbol.iterator](),put:async(id,row)=>{const value=spec.tables[name].valueSchema.parse(row);await options.put?.(name,id,value);maps[name].set(id,structuredClone(value));},delete:async id=>{await options.delete?.(name,id);return maps[name].delete(id);}}),close:async()=>{closed=true;}};}},
  workspaceRegistry:{get:id=>workspaces.find(w=>w.id===id),list:()=>workspaces},
  tools:{register:value=>{tool=value;return ()=>{};}},llm:{listProviders:()=>[{id:'deepseek',name:'DeepSeek'},{id:'other',name:'Other adapter'}],listModels:async provider=>options.adapterCatalog?options.adapterCatalog(provider):models.filter(m=>m.provider===provider),resolveModelInfo:async(provider,model,signal)=>options.resolveModel?options.resolveModel(provider,model,signal):{provider,id:model,name:'Fixture model',context:{contextWindow:131072},reasoning:{efforts:[{id:'high'}]}},prepareCall:async(config,signal)=>{options.prepared?.(config,signal);return {config:{...config},stream:async function*(call){options.stream?.(call);yield {type:'finish',reason:{kind:'stop'}};}}}},sessionController:{modelCatalog:async()=>options.nativeCatalog?options.nativeCatalog():{default:options.defaultSelection??{provider:'deepseek',model:'deepseek-v4-pro'},routableProviders:['deepseek','other'],groups:[{id:'deepseek',name:'DeepSeek',models:models.filter(m=>m.provider==='deepseek').map(({provider,...model})=>model)},{id:'other',name:'Other adapter',models:models.filter(m=>m.provider==='other').map(({provider,...model})=>model)}],failures:[]}},
  subprocess:{resolveExecutable:async command=>{assert.equal(command,process.env.DSH_SECURITY_DOCKER??'docker');if(options.resolveError)throw Error('Docker unavailable');return '/docker';},spawn:spawnSpec=>{
   const args=spawnSpec.argv.slice(1);calls.push(args);
   if(args[0]==='start'){
    const end=deferred(),stdout=new PassThrough(),name=args.at(-1);engines.set(name,end);
    const stdin=new Writable({write(data,_encoding,callback){const frame=JSON.parse(String(data).trim());if(frame.type==='start'){jobs.push(frame.job);started.resolve(frame.job);setImmediate(()=>{if(options.request){stdout.write(JSON.stringify({type:'request',id:1,method:'POST',path:'/responses',body:JSON.stringify({model:frame.job.model,input:'fixture'})})+'\n');}else if(options.autoComplete!==false){stdout.write(JSON.stringify({type:'result',value:{findings:{findings:[{title:'Fixture finding'}]},export:'fixture-export'}})+'\n');end.resolve({exitCode:0});}});}else if(frame.type==='end'&&options.request){stdout.write(JSON.stringify({type:'result',value:{findings:{findings:[]}}})+'\n');end.resolve({exitCode:0});}callback();}});
    return {stdin,stdout,done:end.promise,collected:{stderr:{readFrom:()=>({text:''})}},terminate:()=>end.resolve({exitCode:143}),waitForExit:async()=>{await end.promise;return true;}};
   }
   if(args[0]==='stop')for(const end of engines.values())end.resolve({exitCode:143});
   const response=options.command?.(args)??{exitCode:0,output:args[0]==='inspect'?JSON.stringify({id:'b'.repeat(64),labels:{'io.dsh.security.lease':args.at(-1).slice('dsh-security-'.length)}}):'',text:''};
   return {done:Promise.resolve(response).then(v=>({exitCode:v.exitCode??0})),collected:{stdout:{readFrom:()=>({text:response.output??''})},stderr:{readFrom:()=>({text:response.text??''})}}};
  }},
  connection:{requestRejection:()=>options.rejection??undefined},webServer:{register:value=>{handler=value.handler;return ()=>{};}},
  effect:setup=>{const disposer=setup();effects.push(disposer);return disposer;},logger:Object.fromEntries(['error','warn','info'].map(level=>[level,(...args)=>{logs.push(args);if(level==='error')options.log?.(...args);options.diagnosticLog?.(level,...args);}]))
 };
 const h={repo,state,ctx,maps,calls,jobs,logs,started:started.promise,get closed(){return closed;},get tool(){return tool;},get handler(){return handler;},get spec(){return spec;},async init(){await apply(ctx);h.panelToken=(await h.http({operation:'workspaces'})).panelToken;return h;},async shutdown(){for(const effect of [...effects].reverse())await effect?.();},
  async invoke(args,session='session-a'){return tool.execute(args,{signal:new AbortController().signal,agent:{id:session}});},
  async http(args,headers={}){const req=Readable.from([JSON.stringify(args)]);req.method='POST';req.headers={host:'127.0.0.1:19387',origin:'http://127.0.0.1:19387','x-dsh-security':'1','x-dsh-security-csrf':h.panelToken,...headers};req.socket={remoteAddress:'127.0.0.1'};let text;const res={statusCode:200,setHeader(){},end:value=>{text=value;}};await handler(req,res);return {status:res.statusCode,...JSON.parse(text)};}
 };return h;
}
const startArgs={provider:'deepseek',model:'deepseek-v4-pro',operation:'start',workspaceId:'workspace-a',userRequested:true,minutes:1};
function completed(id,workspaceId,state){return {id,workspaceId,state,operation:'scan',model:'deepseek-v4-pro',mode:'standard',minutes:1,status:'completed',createdAt:new Date().toISOString(),events:[],result:{findings:{findings:[{title:'Fixture'}]}}};}
test('real defineTool/domain declarations enforce agent denial and content-block array output',async t=>{
 const h=await (await harness()).init();t.after(()=>h.shutdown());assert.equal(h.spec.name,'security_scans');assert.ok(h.spec.tables.scans.valueSchema);assert.ok(h.spec.tables.leases.valueSchema);
 await assert.rejects(h.invoke({operation:'start',userRequested:true}),/must be one of \["status","list","get","cancel","export"\]/);await assert.rejects(h.invoke({operation:'validate',userRequested:true,id:randomUUID()}),/must be one of \["status","list","get","cancel","export"\]/);assert.equal(h.calls.length,0);
 const value=await h.invoke({operation:'status'});assert.equal(value.authentication,'configured-provider');assert.equal(value.routing,'harness-llm');assert.equal(Object.hasOwn(value,'credential'),false);assert.deepEqual(value.defaultSelection,{provider:'deepseek',model:'deepseek-v4-pro'});assert.deepEqual(value.models,[{provider:'deepseek',id:'deepseek-v4-pro',name:'Fixture model',providerName:'DeepSeek'},{provider:'other',id:'custom-model',name:'Fixture model',providerName:'Other adapter'}]);assert.ok(inject.includes('llm'));assert.ok(inject.includes('sessionController'));assert.ok(!inject.includes('credentials'));const blocks=h.tool.output.render({},value);assert.ok(Array.isArray(blocks));assert.equal(blocks[0].type,'text');assert.ok(!blocks[0].text.includes('TEST-ONLY-NOT-A-REAL-KEY'));
});
test('HTTP consent requires authenticated, custom-header, same-origin UI and checkbox',async t=>{
 const h=await (await harness()).init();t.after(()=>h.shutdown());
 assert.equal((await h.http(startArgs,{'x-dsh-security':undefined})).status,403);assert.equal((await h.http(startArgs,{origin:'http://evil.test'})).status,403);
 assert.match((await h.http(startArgs,{origin:undefined,'x-dsh-security-csrf':undefined})).error,/authorization is missing or expired/);assert.match((await h.http({...startArgs,userRequested:false})).error,/Explicit user authorization/);assert.equal(h.calls.length,0);
 const rejection=await (await harness({rejection:401})).init();t.after(()=>rejection.shutdown());assert.equal((await rejection.http(startArgs)).status,401);
});
test('UI CSRF token supports missing Origin and Fetch Metadata without bypassing consent',async t=>{
 const h=await (await harness()).init();t.after(()=>h.shutdown());
 const headers={origin:undefined,'sec-fetch-site':undefined};
 assert.match((await h.http({...startArgs,userRequested:false},headers)).error,/Explicit user authorization/);
 for(const token of [undefined,'','A'.repeat(43),['B'.repeat(43)],'é'.repeat(43)]){
  for(const operation of ['start','validate'])assert.equal((await h.http({...startArgs,operation},{...headers,'x-dsh-security-csrf':token})).status,403);
 }
 for(const site of ['none','same-site','cross-site'])assert.equal((await h.http(startArgs,{...headers,'sec-fetch-site':site})).status,403);
 for(const origin of ['','null','http://evil.test'])assert.equal((await h.http(startArgs,{origin,'sec-fetch-site':'same-origin'})).status,403);
 assert.equal(h.calls.length,0);
 const accepted=await h.http(startArgs,headers);assert.equal(accepted.status,200);assert.ok(accepted.result.id);await h.started;
});
test('UI token is authenticated, runtime-scoped and excluded from agent results and scan state',async t=>{
 const h=await (await harness()).init(),other=await (await harness()).init();t.after(()=>h.shutdown());t.after(()=>other.shutdown());
 assert.match(h.panelToken,/^[A-Za-z0-9_-]{43}$/);assert.notEqual(h.panelToken,other.panelToken);
 const result=await h.http({operation:'status',workspaceId:'workspace-a'},{origin:undefined});assert.equal(result.result.panelAuthorizationVerified,true);assert.equal(result.panelToken,h.panelToken);
 const stale=await h.http({operation:'status',workspaceId:'workspace-a'},{'x-dsh-security-csrf':other.panelToken});assert.equal(stale.result.panelAuthorizationVerified,false);assert.equal(stale.panelToken,h.panelToken);
 assert.equal((await h.http(startArgs,{'x-dsh-security-csrf':other.panelToken})).status,403);assert.equal(h.calls.length,0);
 assert.ok(!JSON.stringify(await h.invoke({operation:'status'})).includes(h.panelToken));assert.ok(!JSON.stringify([...h.maps.scans]).includes(h.panelToken));assert.ok(!JSON.stringify(h.logs).includes(h.panelToken));
 const unauth=await (await harness({rejection:401})).init();t.after(()=>unauth.shutdown());const rejected=await unauth.http({operation:'workspaces'});assert.equal(rejected.status,401);assert.equal(rejected.panelToken,undefined);
});
test('real loopback HTTP verifies the UI token without Origin, Fetch Metadata or inference',async t=>{
 const h=await (await harness()).init();t.after(()=>h.shutdown());let received;
 const server=createServer((req,res)=>{received={origin:req.headers.origin,fetchSite:req.headers['sec-fetch-site']};void h.handler(req,res);});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const url=`http://127.0.0.1:${server.address().port}/dsh-security/api`;
 const post=(args,token)=>fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-DSH-Security':'1',...(token?{'X-DSH-Security-CSRF':token}:{})},body:JSON.stringify(args)});
 const bootstrap=await post({operation:'workspaces'});assert.equal(bootstrap.status,200);assert.equal(bootstrap.headers.get('cache-control'),'no-store');const {panelToken}=await bootstrap.json();
 const preflight=await post({operation:'status',workspaceId:'workspace-a'},panelToken);assert.equal(preflight.status,200);assert.equal((await preflight.json()).result.panelAuthorizationVerified,true);
 assert.equal(received.origin,undefined);assert.equal(received.fetchSite,undefined);
 const denied=await post({...startArgs,userRequested:false},panelToken);assert.equal(denied.status,400);assert.match((await denied.json()).error,/Explicit user authorization/);
 const noToken=await post(startArgs);assert.equal(noToken.status,403);assert.equal(h.calls.length,0);assert.equal(h.maps.scans.size,0);
});
test('ownership comes from execution session; foreign IDs and unregistered sessions are rejected',async t=>{
 const h=await harness();const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-b',h.state));await h.init();t.after(()=>h.shutdown());
 assert.deepEqual(await h.invoke({operation:'list'}),[]);for(const operation of ['get','cancel','export'])await assert.rejects(h.invoke({operation,id,workspaceId:'workspace-b'}),/not found in this workspace/);
 await assert.rejects(h.invoke({operation:'status'},'unknown-session'),/Registered workspace required/);assert.equal((await h.invoke({operation:'get',id},'session-b')).id,id);
 assert.match((await h.http({...startArgs,operation:'validate',id,findingIndex:0})).error,/not found in this workspace/);
});
test('shutdown aborts and drains model resolution; late model resolution cannot start Docker',{timeout:3000},async()=>{
 const modelInfo=deferred(),entered=deferred();const h=await (await harness({resolveModel:()=>{entered.resolve();return modelInfo.promise;}})).init();
 const pending=h.http(startArgs);await entered.promise;assert.equal((await h.invoke({operation:'status'})).active,true);assert.match((await h.http(startArgs)).error,/already active/);
 await h.shutdown();assert.equal(h.closed,true);assert.ok((await pending).error);modelInfo.resolve({provider:'deepseek',id:'deepseek-v4-pro',name:'Fixture',context:{contextWindow:131072}});await turn();assert.equal(h.calls.length,0);
});
test('initial persistence failure releases workspace reservation and supports a later start',async t=>{
 let fail=true;const h=await (await harness({put:async table=>{if(table==='scans'&&fail){fail=false;throw Error('initial persistence failed');}}})).init();t.after(()=>h.shutdown());
 assert.match((await h.http(startArgs)).error,/initial persistence failed/);assert.equal((await h.invoke({operation:'status'})).active,false);assert.ok((await h.http(startArgs)).result);await h.started;
});
test('final persistence failure releases ownership; canceling its stale ID cannot abort a newer scan',{timeout:3000},async t=>{
 let failFinal=true;const failed=deferred();const h=await (await harness({put:async(table,_id,row)=>{if(table==='scans'&&row.status==='completed'&&failFinal){failFinal=false;throw Error('final persistence failed');}},log:()=>failed.resolve()})).init();t.after(()=>h.shutdown());
 const first=(await h.http(startArgs)).result;await failed.promise;await turn();assert.equal((await h.invoke({operation:'status'})).active,false);
 // Pause the second execution by replacing its command handle's completion behavior.
 const originalSpawn=h.ctx.subprocess.spawn;h.ctx.subprocess.spawn=spec=>{const handle=originalSpawn(spec);if(spec.argv[1]==='start'){
  const originalWrite=handle.stdin._write;handle.stdin._write=(data,encoding,cb)=>{if(JSON.parse(String(data)).type==='start'){h.jobs.push(JSON.parse(String(data)).job);cb();}else originalWrite.call(handle.stdin,data,encoding,cb);};
 }return handle;};
 const second=(await h.http(startArgs)).result;await turn();assert.equal((await h.invoke({operation:'status'})).active,true);await h.invoke({operation:'cancel',id:first.id});assert.equal((await h.invoke({operation:'status'})).active,true);await h.invoke({operation:'cancel',id:second.id});assert.equal((await h.invoke({operation:'status'})).active,false);
});
test('exports are tracked, canceled, and fully cleaned before domain close',{timeout:3000},async()=>{
 const gate=deferred(),removing=deferred();const h=await harness({autoComplete:false,command:args=>{if(args[0]==='rm'){removing.resolve();return gate.promise;}}});const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));await h.init();
 const exporting=h.invoke({operation:'export',id}).then(v=>({v}),error=>({error}));await h.started;let stopped=false;const shutdown=h.shutdown().then(()=>{stopped=true;});await removing.promise;assert.equal(h.closed,false);assert.equal(stopped,false);gate.resolve({exitCode:0});await shutdown;assert.equal(h.closed,true);assert.ok((await exporting).error);assert.equal(h.maps.leases.size,0);
});
test('startup reconciles labeled orphans before marking scan records interrupted',async t=>{
 const id=randomUUID();const h=await harness({command:args=>args[0]==='inspect'?{output:JSON.stringify({id:'b'.repeat(64),labels:{'io.dsh.security.lease':id}})}:undefined});
 const row={...completed(id,'workspace-a',h.state),status:'running'};h.maps.scans.set(id,row);h.maps.leases.set(id,{id,name:'dsh-security-'+id,image:'sha256:'+'a'.repeat(64),state:h.state,phase:'created',createdAt:new Date().toISOString()});await h.init();t.after(()=>h.shutdown());
 assert.equal(h.maps.leases.size,0);assert.equal(h.maps.scans.get(id).status,'interrupted');assert.deepEqual(h.calls.map(a=>a[0]),['inspect','rm']);
});
test('startup retains missing uncertain creation and fails closed on conflicting container labels',async()=>{
 const id=randomUUID();const missing=await harness({command:()=>({exitCode:1,text:'No such container'})});const lease={id,name:'dsh-security-'+id,image:'sha256:'+'a'.repeat(64),state:missing.state,phase:'creating',createdAt:new Date().toISOString()};missing.maps.leases.set(id,lease);await missing.init();assert.equal(missing.maps.leases.size,1);await missing.shutdown();
 const collision=await harness({command:()=>({output:JSON.stringify({id:'b'.repeat(64),labels:{'io.dsh.security.lease':'foreign'}})})});collision.maps.leases.set(id,{...lease,state:collision.state});await assert.rejects(collision.init(),/label mismatch/);assert.ok(!collision.calls.some(a=>a[0]==='rm'));await collision.shutdown();assert.equal(collision.closed,true);
});
test('initialization failure still owns a registered domain disposer',async()=>{
 const h=await harness({resolveError:true});await assert.rejects(h.init(),/Docker unavailable/);await h.shutdown();assert.equal(h.closed,true);
});
test('validation selects only a persisted finding from the owning completed scan',async t=>{
 const h=await harness();const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));await h.init();t.after(()=>h.shutdown());
 assert.match((await h.http({...startArgs,operation:'validate',id,findingIndex:999})).error,/Select an existing finding/);
 const result=await h.http({...startArgs,operation:'validate',id,findingIndex:0});assert.equal(result.result.operation,'validate');await h.started;assert.deepEqual(h.jobs[0].finding,{title:'Fixture'});
});

test('start and validation require an explicit configured provider/model without silent fallback',async t=>{
 const h=await harness();const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));await h.init();t.after(()=>h.shutdown());
 for(const operation of ['start','validate'])for(const selection of [{provider:undefined},{model:undefined},{provider:'unknown'},{model:'unknown'},{provider:'other',model:'deepseek-v4-pro'}]){
  const response=await h.http({...startArgs,operation,id,findingIndex:0,...selection});assert.match(response.error,/Choose a configured Harness|provider is not configured|not in the configured Harness catalog/);assert.equal(h.calls.length,0);assert.equal((await h.invoke({operation:'status'})).active,false);
 }
});
test('non-DeepSeek selection is persisted and preserved through the bound Harness adapter',async t=>{
 const prepared=[],streams=[];const h=await (await harness({request:true,prepared:config=>prepared.push(config),stream:call=>streams.push(call)})).init();t.after(()=>h.shutdown());
 const reply=await h.http({...startArgs,provider:'other',model:'custom-model',reasoningEffort:'high'});assert.ok(reply.result);await h.started;
 for(let i=0;i<20&&h.maps.scans.get(reply.result.id)?.status==='running';i++)await turn();
 assert.equal(h.jobs[0].provider,'other');assert.equal(h.jobs[0].model,'custom-model');assert.equal(h.jobs[0].contextWindow,131072);assert.equal(h.jobs[0].reasoningEffort,'high');assert.deepEqual(prepared,[{provider:'other',model:'custom-model',reasoningEffort:'high'}]);assert.equal(streams.length,1);assert.equal(streams[0].provider,'other');assert.equal(streams[0].model,'custom-model');assert.equal(h.maps.scans.get(reply.result.id).status,'completed');
});
test('validation can explicitly switch away from the original scan model',async t=>{
 const h=await harness();const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));await h.init();t.after(()=>h.shutdown());
 const response=await h.http({...startArgs,operation:'validate',id,findingIndex:0,provider:'other',model:'custom-model'});assert.ok(response.result);await h.started;assert.equal(h.jobs[0].provider,'other');assert.equal(h.jobs[0].model,'custom-model');assert.deepEqual(h.jobs[0].finding,{title:'Fixture'});
});
test('resolved model mismatch and unsupported reasoning effort cannot start Docker',async t=>{
 for(const options of [{resolveModel:async()=>({provider:'other',id:'custom-model',name:'wrong'})},{}]){const h=await (await harness(options)).init();t.after(()=>h.shutdown());const reply=await h.http({...startArgs,...(options.resolveModel?{}:{reasoningEffort:'unsupported'})});assert.match(reply.error,/Model mismatch: fallback is prohibited|reasoning effort is not supported/);assert.equal(h.calls.length,0);assert.equal((await h.invoke({operation:'status'})).active,false);}
});
test('native catalog default and isolated failures are reported without adapter fallback',async t=>{
 let adapterCalls=0;const secret='TEST-ONLY-NOT-A-REAL-KEY';
 const h=await (await harness({adapterCatalog:()=>{adapterCalls++;throw Error(secret);},nativeCatalog:async()=>({default:{provider:'other',model:'custom-model',reasoningEffort:'high'},routableProviders:['deepseek','other'],groups:[{id:'other',name:'Native Other',models:[{id:'custom-model',name:'Native model'}]}],failures:[{id:'deepseek',name:'DeepSeek',message:`adapter unavailable: ${secret}`}]} )})).init();t.after(()=>h.shutdown());
 const value=await h.invoke({operation:'status'});assert.deepEqual(value.defaultSelection,{provider:'other',model:'custom-model',reasoningEffort:'high'});assert.deepEqual(value.models,[{provider:'other',id:'custom-model',name:'Native model',providerName:'Native Other'}]);assert.equal(value.modelErrors.length,1);assert.equal(value.modelErrors[0].provider,'deepseek');assert.ok(!JSON.stringify(value).includes(secret));assert.equal(value.authentication,'configured-provider');assert.equal(Object.hasOwn(value,'credential'),false);
 const rejected=await h.http(startArgs);assert.match(rejected.error,/not in the configured Harness catalog/);assert.ok(!JSON.stringify(rejected).includes(secret));assert.equal(h.calls.length,0);assert.ok((await h.http({...startArgs,provider:'other',model:'custom-model'})).result);await h.started;assert.equal(adapterCalls,0);
});

test('native catalog exclusion rejects adapter-advertised models before metadata or Docker',async t=>{
 let adapterCalls=0,metadataCalls=0;const h=await (await harness({adapterCatalog:provider=>{adapterCalls++;return [{provider,id:'adapter-only-model',name:'Adapter-only model'}];},resolveModel:async(provider,model)=>{metadataCalls++;return {provider,id:model,name:'Adapter-only model'};}})).init();t.after(()=>h.shutdown());
 const status=await h.invoke({operation:'status'});assert.ok(!status.models.some(m=>m.id==='adapter-only-model'));
 const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));for(const operation of ['start','validate']){const reply=await h.http({...startArgs,operation,id,findingIndex:0,model:'adapter-only-model'});assert.match(reply.error,/not in the configured Harness catalog/);assert.equal((await h.invoke({operation:'status'})).active,false);}
 assert.equal(adapterCalls,0);assert.equal(metadataCalls,0);assert.equal(h.calls.length,0);assert.equal(h.maps.scans.size,1);
});

test('native catalog failure fails closed and sanitizes status and HTTP responses',async t=>{
 const secret='TEST-ONLY-NOT-A-REAL-KEY';let adapterCalls=0,metadataCalls=0;
 const h=await (await harness({nativeCatalog:async()=>{throw Error(`catalog unavailable ${secret}`);},adapterCatalog:provider=>{adapterCalls++;return [{provider,id:'deepseek-v4-pro',name:'Adapter fallback'}];},resolveModel:async()=>{metadataCalls++;throw Error(secret);}})).init();t.after(()=>h.shutdown());
 const value=await h.invoke({operation:'status'});assert.deepEqual(value.models,[]);assert.equal(value.modelErrors.length,1);assert.match(value.modelErrors[0].message,/catalog is unavailable/);assert.equal(Object.hasOwn(value,'defaultSelection'),false);assert.ok(!JSON.stringify(value).includes(secret));assert.equal(value.authentication,'configured-provider');assert.equal(Object.hasOwn(value,'credential'),false);
 const id=randomUUID();h.maps.scans.set(id,completed(id,'workspace-a',h.state));for(const operation of ['start','validate']){const reply=await h.http({...startArgs,operation,id,findingIndex:0});assert.equal(reply.status,400);assert.ok(reply.error);assert.ok(!JSON.stringify(reply).includes(secret));assert.equal((await h.invoke({operation:'status'})).active,false);}
 assert.equal(adapterCalls,0);assert.equal(metadataCalls,0);assert.equal(h.calls.length,0);assert.equal(h.maps.scans.size,1);
});

test('adapter model metadata errors are sanitized before HTTP responses',async t=>{
 const secret='TEST-ONLY-NOT-A-REAL-KEY';const h=await (await harness({resolveModel:async()=>{throw Error(`metadata unavailable ${secret}`);}})).init();t.after(()=>h.shutdown());
 const reply=await h.http(startArgs);assert.equal(reply.status,400);assert.match(reply.error,/model metadata is unavailable/);assert.ok(!JSON.stringify(reply).includes(secret));assert.equal(h.calls.length,0);assert.equal(h.maps.scans.size,0);assert.equal((await h.invoke({operation:'status'})).active,false);
});

test('failed history removal requires confirmed UI CSRF and preserves other statuses/workspaces/state',async t=>{
 const h=await harness();t.after(()=>h.shutdown());const failed=randomUUID(),success=randomUUID(),foreign=randomUUID(),cancelled=randomUUID();
 for(const [id,wid,status]of [[failed,'workspace-a','failed'],[success,'workspace-a','completed'],[foreign,'workspace-b','failed'],[cancelled,'workspace-a','cancelled']])h.maps.scans.set(id,{...completed(id,wid,h.state),status});
 await h.init();const args={operation:'clear_failed',workspaceId:'workspace-a',ids:[failed],userRequested:true};
 await assert.rejects(h.invoke(args),/must be one of/);
 for(const token of [undefined,'wrong'])assert.equal((await h.http(args,{'x-dsh-security-csrf':token})).status,403);
 assert.equal((await h.http({...args,userRequested:false})).status,400);
 for(const id of [success,foreign,cancelled]){assert.equal((await h.http({...args,ids:[failed,id]})).status,400);assert.ok(h.maps.scans.has(failed),'entire snapshot checked before deletion');}
 assert.equal((await h.http({...args,ids:[]})).status,400);
 const reply=await h.http({...args,ids:[failed,failed]});assert.equal(reply.status,200);assert.deepEqual(reply.result,{removed:[failed]});
 assert.equal(h.maps.scans.has(failed),false);for(const id of [success,foreign,cancelled])assert.ok(h.maps.scans.has(id));
 assert.equal(h.calls.length,0,'no engine command or private file cleanup');
 const restarted=await (await harness({scans:[...h.maps.scans]})).init();t.after(()=>restarted.shutdown());assert.equal((await restarted.invoke({operation:'list'})).some(row=>row.id===failed),false);
});

test('storage delete errors expose partial removal without deleting unrelated history',async t=>{
 const ids=[randomUUID(),randomUUID()],h=await (await harness({scans:ids.map(id=>[id,{...completed(id,'workspace-a','/private/state'),status:'failed'}]),delete:async(name,id)=>{if(name==='scans'&&id===ids[1])throw Error('storage unavailable');}})).init();t.after(()=>h.shutdown());
 assert.equal((await h.http({operation:'clear_failed',workspaceId:'workspace-a',ids,userRequested:true})).status,400);assert.equal(h.maps.scans.has(ids[0]),false);assert.equal(h.maps.scans.has(ids[1]),true);assert.deepEqual((await h.invoke({operation:'list'})).map(row=>row.id),[ids[1]]);
});

test('failed entry with outstanding lease or finishing task is not removable',async t=>{
 const id=randomUUID(),row={...completed(id,'workspace-a','/private/state'),status:'failed'};
 const h=await (await harness({scans:[[id,row]],leases:[[id,{id,name:'dsh-security-'+id,image:'sha256:'+'a'.repeat(64),state:row.state,phase:'creating',createdAt:row.createdAt}]],command:a=>a[0]==='inspect'?{exitCode:1,text:'No such container'}:undefined})).init();t.after(()=>h.shutdown());
 assert.match((await h.http({operation:'clear_failed',workspaceId:'workspace-a',ids:[id],userRequested:true})).error,/cleanup is still pending/);assert.ok(h.maps.scans.has(id));
 const held=deferred(),finishing=deferred();const live=await (await harness({request:true,stream:()=>{throw Object.assign(Error('private adapter message'),{code:'INVALID_REQUEST'});},put:async(name,_id,r)=>{if(name==='scans'&&r.status==='failed'){live.maps.scans.set(_id,structuredClone(r));finishing.resolve();await held.promise;}}})).init();t.after(()=>live.shutdown());
 const started=await live.http(startArgs);await finishing.promise;
 assert.equal((await live.http({operation:'clear_failed',workspaceId:'workspace-a',ids:[started.result.id],userRequested:true})).status,400);held.resolve();await live.shutdown();
 assert.equal((await live.invoke({operation:'status'})).active,false);
});

test('gateway and engine diagnostics persist through failure, exclude secrets and isolate logger failures',async t=>{
 const secret='TEST-ONLY-SOURCE-AND-CREDENTIAL-CANARY';
 const h=await (await harness({request:true,stream:()=>{throw Object.assign(Error(secret),{code:'INVALID_REQUEST',status:413,requestId:secret});},diagnosticLog:()=>{throw Error(secret);}})).init();t.after(()=>h.shutdown());
 const started=await h.http(startArgs);await h.started;for(let n=0;n<20&&(await h.invoke({operation:'status'})).active;n++)await turn();
 const row=await h.invoke({operation:'get',id:started.result.id});assert.equal(row.status,'failed');assert.equal(row.diagnostics.length,2);
 const gateway=row.diagnostics.find(d=>d.kind==='gateway');assert.equal(gateway.stage,'iterate');assert.equal(gateway.code,'INVALID_REQUEST');assert.equal(gateway.upstreamStatus,413);assert.equal(gateway.reason,'size_rejection');assert.equal(gateway.contextWindow,131072);
 assert.ok(!JSON.stringify(row.diagnostics).includes(secret));assert.ok(!JSON.stringify(h.logs).includes(secret));assert.ok(!JSON.stringify(row).includes(h.panelToken));
 assert.equal(Object.hasOwn((await h.invoke({operation:'list'}))[0],'diagnostics'),false);
 const schema=h.spec.tables.scans.valueSchema;assert.equal(schema.safeParse({...row,diagnostics:Array(129).fill(gateway)}).success,false);
 assert.equal(schema.safeParse({...row,diagnostics:[{...gateway,message:secret}]}).success,false);assert.equal(schema.safeParse({...row,diagnostics:[{...gateway,requestBytes:-1}]}).success,false);
 const restored=await (await harness({scans:[...h.maps.scans]})).init();t.after(()=>restored.shutdown());assert.deepEqual((await restored.invoke({operation:'get',id:row.id})).diagnostics,row.diagnostics);
});
