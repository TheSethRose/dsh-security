import test from 'node:test';
import assert from 'node:assert/strict';
import {createHarnessGateway} from '../harness-gateway.mjs';
import {retainDiagnostic,DIAGNOSTIC_LIMIT} from '../core.mjs';
test('retention caps actual entries at 128 and accounts for dropped entries without numeric overflow',()=>{
 const job={};for(let n=0;n<DIAGNOSTIC_LIMIT+3;n++)assert.equal(retainDiagnostic(job,{sequence:n}),n<DIAGNOSTIC_LIMIT);
 assert.equal(job.diagnostics.length,128);assert.equal(job.diagnosticsDropped,3);assert.equal(job.diagnostics.at(-1).sequence,127);
 job.diagnosticsDropped=Number.MAX_SAFE_INTEGER;assert.equal(retainDiagnostic(job,{sequence:132}),false);assert.equal(job.diagnosticsDropped,Number.MAX_SAFE_INTEGER);
});
const selection={provider:'offline',model:'fixture',contextWindow:8192};
const secret='TEST-ONLY-SOURCE-SCHEMA-REPLAY-CREDENTIAL-CANARY';
const request={model:'fixture',input:secret,instructions:secret,tools:[{type:'function',name:secret,description:secret,parameters:{type:'object',properties:{[secret]:{type:'string'}}}}],max_output_tokens:50,temperature:0,stream:true};
function setup({failure,thrown,prepareError,observer}={}){
 const diagnostics=[];let dispatches=0;
 const gateway=createHarnessGateway({selection,onDiagnostic:entry=>{diagnostics.push(entry);observer?.(entry);},llm:{async prepareCall(config){if(prepareError)throw prepareError;return{config,stream(){dispatches++;if(thrown)throw thrown;return(async function*(){if(failure)yield{type:'finish',reason:{kind:'error',failure}};else{yield{type:'block-start',index:0,blockType:'text'};yield{type:'text-delta',index:0,text:secret};yield{type:'block-end',index:0,block:{type:'text',text:secret}};yield{type:'finish',reason:{kind:'stop'}};}})();}};}}});
 return{gateway,diagnostics,get dispatches(){return dispatches;}};
}

test('one bounded terminal snapshot records safe sizes/counts/controls, never content or schema keys',async()=>{
 const f=setup();await(await f.gateway(request)).text();assert.equal(f.diagnostics.length,1);const d=f.diagnostics[0];
 assert.equal(d.stage,'complete');assert.equal(d.outcome,'completed');assert.equal(d.code,'NONE');assert.equal(d.requestBytes,Buffer.byteLength(JSON.stringify(request)));assert.equal(d.inputTextChars,secret.length);assert.equal(d.systemChars,secret.length);assert.equal(d.inputMessages,1);assert.equal(d.toolCount,1);assert.ok(d.toolSchemaBytes>0);assert.equal(d.chunkCount,4);assert.equal(d.blockCount,1);assert.ok(d.replyBytes>0);assert.equal(d.maxTokens,50);assert.equal(d.temperature,0);assert.equal(d.contextWindow,8192);assert.equal(d.requestedTemperature,true);assert.equal(d.stream,true);
 assert.match(d.requestId,/^[a-f0-9-]{36}$/);assert.ok(d.elapsedMs>=0);assert.ok(JSON.stringify(d).length<2048);assert.ok(!JSON.stringify(d).includes(secret));
});

test('trusted upstream status distinguishes size rejection, code alone remains ambiguous',async()=>{
 for(const [status,reason]of [[undefined,'ambiguous_request_rejection'],[400,'request_rejected'],[413,'size_rejection'],[0,'ambiguous_request_rejection'],[600,'ambiguous_request_rejection'],['413','ambiguous_request_rejection']]){
  const f=setup({failure:{code:'INVALID_REQUEST',message:secret,status,requestId:secret,headers:{Authorization:secret},stack:secret}});await(await f.gateway(request)).text();const d=f.diagnostics[0];assert.equal(d.code,'INVALID_REQUEST');assert.equal(d.reason,reason);assert.equal(d.stage,'iterate');assert.equal(d.outcome,'failed');assert.equal(d.upstreamStatus,status===400||status===413?status:undefined);assert.ok(!JSON.stringify(d).includes(secret));assert.equal(f.dispatches,1);
 }
});

test('prepare, dispatch and translation failures identify stage without raw errors',async()=>{
 const error=Object.assign(Error(secret),{code:'AUTH'});
 for(const [opts,stage]of [[{prepareError:error},'prepare'],[{thrown:error},'dispatch']]){const f=setup(opts);await(await f.gateway(request)).text();assert.equal(f.diagnostics.length,1);assert.equal(f.diagnostics[0].stage,stage);assert.equal(f.diagnostics[0].code,'AUTH');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));}
 const f=setup();assert.equal((await f.gateway({...request,max_output_tokens:-1})).status,400);assert.equal(f.diagnostics[0].stage,'translate');assert.equal(f.diagnostics[0].code,'PROTOCOL_ERROR');assert.equal(f.dispatches,0);
});

test('unknown failure codes and diagnostic getters are not exposed or evaluated',async()=>{
 let reads=0;for(const field of ['code','status','failure']){const error=Object.defineProperty(Error(secret),field,{get(){reads++;throw Error(secret);}});const f=setup({thrown:error});await(await f.gateway(request)).text();assert.equal(f.diagnostics[0].code,'UNKNOWN');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));}assert.equal(reads,0);
 const f=setup({failure:{code:secret,message:secret}});await(await f.gateway(request)).text();assert.equal(f.diagnostics[0].code,'UNKNOWN');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));
});

test('diagnostic callback exceptions cannot alter successful inference',async()=>{
 const f=setup({observer:()=>{throw Error(secret);}});const text=await(await f.gateway(request)).text();assert.match(text,/response.completed/);assert.equal(f.dispatches,1);assert.equal(f.diagnostics.length,1);
});

test('stream cancellation and aborted preparation each emit exactly one terminal snapshot',async()=>{
 const f=setup();const response=await f.gateway(request);await response.body.cancel();assert.equal(f.diagnostics.length,1);assert.equal(f.diagnostics[0].outcome,'cancelled');
 const entries=[],controller=new AbortController();const gateway=createHarnessGateway({selection,onDiagnostic:e=>entries.push(e),llm:{prepareCall:()=>new Promise(()=>{})}});const pending=gateway(request,controller.signal);controller.abort();assert.equal((await pending).status,499);assert.equal(entries.length,1);assert.equal(entries[0].stage,'prepare');assert.equal(entries[0].reason,'abort');
});
