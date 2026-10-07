import test from 'node:test';import assert from 'node:assert/strict';import {Writable,PassThrough} from 'node:stream';import {randomUUID} from 'node:crypto';import {runEngine,reconcileContainerLease} from '../transport.mjs';
const image='sha256:'+'a'.repeat(64),model='deepseek-v4-pro',containerId='b'.repeat(64);
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const inspection=id=>JSON.stringify({id:containerId,labels:{'io.dsh.security.lease':id}});
function fake(options={}){
 const calls=[],frames=[],started=deferred(),ready=deferred();let engine;const finish=(code=0)=>{engine?.end.resolve({exitCode:code});};
 const subprocess={spawn(spec){const args=spec.argv.slice(1);calls.push(args);if(args[0]!=='start'){
  const value=options.command?.(args,spec)??{exitCode:0,text:'',output:args[0]==='inspect'?inspection(args.at(-1).slice('dsh-security-'.length)):''};const done=Promise.resolve(value).then(v=>({exitCode:v.exitCode??0}));
  return {done,collected:{stderr:{readFrom:()=>({text:typeof value?.text==='string'?value.text:''})},stdout:{readFrom:()=>({text:typeof value?.output==='string'?value.output:''})}}};
 }
 const end=deferred(),stdout=new PassThrough();engine={end,stdout};
 const emit=v=>stdout.write(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v)+'\n');
 const stdin=new Writable({write(chunk,_encoding,callback){for(const line of String(chunk).trim().split('\n')){const frame=JSON.parse(line);frames.push(frame);if(frame.type==='start'){started.resolve();setImmediate(()=>{ready.resolve();options.script?.({emit,finish,frame});});}else options.input?.({frame,emit,finish});}if(!options.wedgeWrites||frames.at(-1)?.type==='start')callback();}});
 return {stdin,stdout,done:end.promise,collected:{stderr:{readFrom:()=>({text:options.stderr??''})}},terminate:()=>finish(143),waitForExit:async()=>{await end.promise;return true;}};
 }};
 return {subprocess,calls,frames,started:started.promise,ready:ready.promise,finish};
}
function args(f,extra={}){return {subprocess:f.subprocess,docker:'/docker',image,repo:'/repo',state:'/state',job:{id:randomUUID(),model},signal:new AbortController().signal,gateway:async()=>new Response(''),...extra};}
const request=(id=1,extra={})=>({type:'request',id,method:'POST',path:'/responses',body:JSON.stringify({model,input:'fixture'}),...extra});
test('container creation has a managed 30-second client deadline',async()=>{
 let bounded=false;const f=fake({command:(a,spec)=>{if(a[0]==='create'){bounded=spec.signal instanceof AbortSignal;assert.equal(spec.signal.aborted,false);}},script:({emit,finish})=>{emit({type:'result',value:'ok'});finish();}});
 assert.equal(await runEngine(args(f)),'ok');assert.equal(bounded,true);
});
test('gateway HTTP errors cannot echo adapter secrets into container frames',async()=>{
 const f=fake({script:({emit})=>emit(request())});await assert.rejects(runEngine(args(f,{gateway:async()=>new Response('HOST-ONLY-KEY',{status:401})})),/Harness model request failed; no fallback attempted/);assert.ok(!JSON.stringify(f.frames).includes('HOST-ONLY-KEY'));
});
test('successful framed result cleans by immutable container ID and releases its durable lease',async()=>{
 const events=[],leases=[];const f=fake({script:({emit,finish})=>{emit({type:'progress',value:'ready'});emit({type:'result',value:{ok:true}});finish();}});
 const result=await runEngine(args(f,{onEvent:e=>events.push(e),lease:{acquire:async v=>leases.push(['acquire',v]),created:async id=>leases.push(['created',id]),release:async id=>leases.push(['release',id])}}));
 assert.deepEqual(result,{ok:true});assert.equal(events.length,1);assert.deepEqual(leases.map(x=>x[0]),['acquire','created','release']);assert.ok(f.calls[0].includes('io.dsh.security.lease='+leases[0][1].id));assert.deepEqual(f.calls.at(-1),['rm','--force',containerId]);
});
test('bound Harness gateway receives checked body and signal; streaming frames preserve store:false',async()=>{
 let forwarded;const f=fake({script:({emit})=>emit(request()),input:({frame,emit,finish})=>{if(frame.type==='end'){emit({type:'result',value:'ok'});finish();}}});
 assert.equal(await runEngine(args(f,{gateway:async(body,signal)=>{forwarded={body,signal};return new Response('payload',{headers:{'content-type':'text/event-stream'}});}})),'ok');
 assert.equal(forwarded.body.model,model);assert.equal(forwarded.body.store,false);assert.ok(forwarded.signal instanceof AbortSignal);assert.ok(!JSON.stringify(f.calls).includes('HOST-ONLY-KEY'));assert.equal(Buffer.from(f.frames.find(f=>f.type==='chunk').data,'base64').toString(),'payload');
});
for(const [label,frame]of [['foreign model',request(1,{body:JSON.stringify({model:'gpt-5',input:'x'})})],['foreign endpoint',request(1,{path:'https://api.openai.com/responses'})],['compact endpoint',request(1,{path:'/responses/compact'})],['hosted tool',request(1,{body:JSON.stringify({model,tools:[{type:'web_search'}]})})],['stored/background request',request(1,{body:JSON.stringify({model,background:true})})]])test('fail closed before gateway: '+label,async()=>{
 let fetches=0;const f=fake({script:({emit})=>emit(frame)});
 await assert.rejects(runEngine(args(f,{gateway:async()=>{fetches++;return new Response('');}})));assert.equal(fetches,0);assert.equal(f.calls.at(-1)[0],'rm');
});
test('cancellation waits for creation before removal and never starts a canceled container',async()=>{
 const creation=deferred(),controller=new AbortController();const f=fake({command:a=>a[0]==='create'?creation.promise:undefined});
 const task=runEngine(args(f,{signal:controller.signal}));await Promise.resolve();controller.abort();assert.equal(f.calls.length,1);creation.resolve({exitCode:0});await assert.rejects(task,/cancel|abort/i);assert.ok(!f.calls.some(a=>a[0]==='start'));assert.equal(f.calls.at(-1)[0],'rm');
});
test('already canceled invocation does not create or remove any container',async()=>{
 const f=fake();await assert.rejects(runEngine(args(f,{signal:AbortSignal.abort()})));assert.equal(f.calls.length,0);
});
test('gateway preparation and wedged stdin cannot prevent cancellation/cleanup',{timeout:3000},async()=>{
 const controller=new AbortController(),waiting=deferred(),f=fake({wedgeWrites:true,script:({emit})=>emit(request())});
 const task=runEngine(args(f,{signal:controller.signal,gateway:()=>waiting.promise}));await f.ready;controller.abort();await assert.rejects(task,/cancel/i);assert.equal(f.calls.at(-1)[0],'rm');waiting.resolve(new Response('late'));
});
test('fifth simultaneous request terminates without forwarding extra work',{timeout:3000},async()=>{
 let forwards=0;const f=fake({script:({emit})=>{for(let n=1;n<=5;n++)emit(request(n));}});
 await assert.rejects(runEngine(args(f,{gateway:async()=>{forwards++;return new Promise(()=>{});}})),/limit exceeded/);assert.ok(forwards<=4);assert.equal(f.calls.at(-1)[0],'rm');
});
test('101st sequential request exceeds the total request ceiling',{timeout:3000},async()=>{
 let count=0;const f=fake({script:({emit})=>emit(request(1)),input:({frame,emit})=>{if(frame.type==='end')emit(request(++count+1));}});let forwards=0;
 await assert.rejects(runEngine(args(f,{gateway:async()=>{forwards++;return new Response('');}})),/limit exceeded/);assert.equal(forwards,100);
});
test('provider errors are sanitized and never attempt fallback',async()=>{
 const f=fake({script:({emit})=>emit(request())});let calls=0;
 await assert.rejects(runEngine(args(f,{gateway:async()=>{calls++;throw Error('secret-host-bearer-or-provider-response');}})),error=>error.message==='Harness model request failed; no fallback attempted');assert.equal(calls,1);
});
for(const [label,script]of [['unknown frame',({emit})=>emit({type:'untrusted'})],['duplicate ID',({emit})=>{emit(request());emit(request());}],['invalid ID',({emit})=>emit(request('not-a-number'))],['incomplete frame',({emit,finish})=>{emit('{"type":"result"');finish();}],['oversized frame',({emit})=>emit('x'.repeat(32*1024*1024+1))]])test('invalid protocol terminates: '+label,{timeout:3000},async()=>{
 const f=fake({script});await assert.rejects(runEngine(args(f,{gateway:async()=>new Promise(()=>{})})));assert.equal(f.calls.at(-1)[0],'rm');
});
test('chunked Unicode is decoded without corruption',async()=>{
 const value={text:'DeepSeek 🔒 é'},encoded=Buffer.from(JSON.stringify({type:'result',value})+'\n'),split=encoded.indexOf(Buffer.from('🔒'))+1;
 const f=fake({script:({emit,finish})=>{emit(encoded.subarray(0,split));emit(encoded.subarray(split));finish();}});assert.deepEqual(await runEngine(args(f)),value);
});
test('cleanup failure rejects successful results and retains the durable lease',async()=>{
 let released=false;const f=fake({script:({emit,finish})=>{emit({type:'result',value:'ok'});finish();},command:a=>a[0]==='rm'?{exitCode:1,text:'daemon refused'}:undefined});
 await assert.rejects(runEngine(args(f,{lease:{acquire:async()=>{},created:async()=>{},release:async()=>{released=true;}}})),/cleanup failed/);assert.equal(released,false);
});
test('failed ambiguous creation retains its lease when cleanup reports missing container',async()=>{
 let released=false;const f=fake({command:a=>a[0]==='create'?{exitCode:1,text:'daemon connection lost'}:a[0]==='inspect'?{exitCode:1,text:'No such container'}:undefined});
 await assert.rejects(runEngine(args(f,{lease:{acquire:async()=>{},created:async()=>{},release:async()=>{released=true;}}})),/creation failed/);assert.equal(released,false);assert.ok(!f.calls.some(a=>a[0]==='rm'));
});
test('a create name collision never stops or removes the unrelated container',async()=>{
 const f=fake({command:a=>a[0]==='create'?{exitCode:1,text:'name collision'}:a[0]==='inspect'?{output:inspection('foreign-lease')}:undefined});
 await assert.rejects(runEngine(args(f)),/label mismatch/);assert.ok(!f.calls.some(a=>['stop','rm'].includes(a[0])));
});
test('startup recovery verifies exact labels, immutable ID, and missing uncertain creations',async()=>{
 const id=randomUUID(),lease={id,name:'dsh-security-'+id,image,state:'/state',phase:'creating'};
 const uncertain=fake({command:()=>({exitCode:1,text:'No such object'})});assert.equal(await reconcileContainerLease({subprocess:uncertain.subprocess,docker:'/docker',lease}),false);assert.equal(await reconcileContainerLease({subprocess:uncertain.subprocess,docker:'/docker',lease:{...lease,phase:'created'}}),true);
 const collision=fake({command:()=>({exitCode:0,output:inspection('someone-else')})});await assert.rejects(reconcileContainerLease({subprocess:collision.subprocess,docker:'/docker',lease}),/label mismatch/);assert.ok(!collision.calls.some(a=>a[0]==='rm'));
 const orphan=fake({command:a=>a[0]==='inspect'?{output:inspection(id)}:undefined});assert.equal(await reconcileContainerLease({subprocess:orphan.subprocess,docker:'/docker',lease}),true);assert.deepEqual(orphan.calls.at(-1),['rm','--force',containerId]);
});
test('missing gateway fails closed without any external forwarding',async()=>{
 const f=fake({script:({emit})=>emit(request())});await assert.rejects(runEngine(args(f,{gateway:undefined})),/Configured Harness model gateway is required/);assert.equal(f.calls.at(-1)[0],'rm');
});
test('oversized provider response terminates before its body reaches the engine',{timeout:3000},async()=>{
 const f=fake({script:({emit})=>emit(request())});const body={async *[Symbol.asyncIterator](){yield Buffer.alloc(64*1024*1024+1);}};
 await assert.rejects(runEngine(args(f,{gateway:async()=>({status:200,headers:new Headers(),body})})),/Harness model request failed; no fallback attempted/);assert.ok(!f.frames.some(frame=>frame.type==='chunk'));
});
test('a stalled provider response body is abortable without cooperative iterator cancellation',{timeout:3000},async()=>{
 const controller=new AbortController(),entered=deferred(),f=fake({script:({emit})=>emit(request())});const body={[Symbol.asyncIterator](){return {next(){entered.resolve();return new Promise(()=>{});}};}};
 const task=runEngine(args(f,{signal:controller.signal,gateway:async()=>({status:200,headers:new Headers(),body})}));await entered.promise;controller.abort();await assert.rejects(task,/cancel/i);assert.equal(f.calls.at(-1)[0],'rm');
});

test('engine terminal diagnostics are safe, single and unaffected by observer exceptions',async()=>{
 const diagnostics=[],secret='TEST-ONLY-PRIVATE-ENGINE-STDERR';const f=fake({stderr:secret,script:({emit,finish})=>{emit(request());emit({type:'result',value:'ok'});finish();}});
 assert.equal(await runEngine(args(f,{onDiagnostic:d=>{diagnostics.push(d);throw Error(secret);}})),'ok');assert.equal(diagnostics.length,1);assert.equal(diagnostics[0].stage,'complete');assert.equal(diagnostics[0].outcome,'completed');assert.equal(diagnostics[0].requestCount,1);assert.equal(diagnostics[0].peakActive,1);assert.ok(!JSON.stringify(diagnostics).includes(secret));
});
test('engine diagnostic records cleanup failure and pre-start cancellation without leaking Docker errors',async()=>{
 const diagnostics=[],secret='TEST-ONLY-PRIVATE-DOCKER-ERROR',f=fake({script:({emit,finish})=>{emit({type:'result',value:'ok'});finish();},command:a=>a[0]==='rm'?{exitCode:1,text:secret}:undefined});
 await assert.rejects(runEngine(args(f,{onDiagnostic:d=>diagnostics.push(d)})),/cleanup failed/);assert.equal(diagnostics.length,1);assert.equal(diagnostics[0].stage,'cleanup');assert.equal(diagnostics[0].outcome,'failed');assert.equal(diagnostics[0].reason,'engine_failure');assert.ok(!JSON.stringify(diagnostics).includes(secret));
 const cancelled=[];await assert.rejects(runEngine(args(fake(),{signal:AbortSignal.abort(),onDiagnostic:d=>cancelled.push(d)})));assert.equal(cancelled.length,1);assert.equal(cancelled[0].stage,'create');assert.equal(cancelled[0].outcome,'cancelled');assert.equal(cancelled[0].reason,'abort');
});
