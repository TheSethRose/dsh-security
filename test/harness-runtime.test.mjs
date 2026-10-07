import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire,findPackageJSON} from 'node:module';
import {pathToFileURL} from 'node:url';
import {createHarnessGateway} from '../harness-gateway.mjs';

// Resolve the actual runtime shipped with the pinned Harness tools package.
const require=createRequire(import.meta.url);
const shipped=createRequire(require.resolve('@deepseek-ai/dsh-tools'));
const {Context}=await import(shipped.resolve('@deepseek-ai/cordis'));
const {LlmRuntime,LlmAdapter}=await import(shipped.resolve('@deepseek-ai/dsh-llm'));
const selection={provider:'offline-runtime-fixture',model:'offline-model'};
const {PiAiAdapter}=await import(shipped.resolve('@deepseek-ai/dsh-llm-pi-ai'));
const piPackage=findPackageJSON('@earendil-works/pi-ai',shipped.resolve('@deepseek-ai/dsh-llm-pi-ai'));
const {withOpenCodeSessionHeader}=await import(new URL('./dist/providers/opencode-headers.js',pathToFileURL(piPackage)).href);

test('real Harness and pi-ai adapter supply OpenCode session header without altering prepared config',async()=>{
 const ctx=new Context(),llm=new LlmRuntime(ctx),calls=[],model={...selection,id:selection.model,name:selection.model,api:'openai-completions',input:['text'],reasoning:false,contextWindow:8192,maxTokens:8192};
 const profile={modelErrors:new Map(),configuredMaxTokens:new Map([[selection.model,8192]]),piProvider:{},headers:{'X-OFFLINE-FIXTURE':'preserved'},streamIdleTimeoutMs:5000},profiles=new Map([[selection.provider,profile]]);
 const streamSimple=async function*(model,context,options){
  calls.push(options);const message={role:'assistant',content:[],api:model.api,provider:model.provider,model:model.id,timestamp:0,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},stopReason:'stop'};
  if(!options.headers['x-opencode-session']){message.stopReason='error';message.errorMessage='400: '+JSON.stringify({type:'MissingSessionID',message:'Request is missing x-opencode-session and cannot be routed efficiently.'});yield{type:'error',error:message};}
  else{message.content=[{type:'text',text:'offline'}];yield{type:'text_start',contentIndex:0};yield{type:'text_delta',contentIndex:0,delta:'offline'};yield{type:'text_end',contentIndex:0,content:'offline'};yield{type:'done',message};}
 };
 const adapter=new PiAiAdapter({profiles:()=>profiles,resolveApiKey:async()=>undefined});
 // Only the model collection/provider stream is synthetic. Run the shipped
 // runtime, adapter preparation/forwarding and OpenCode header wrapper unchanged.
 adapter.snapshot={profiles,models:{getModel:(provider,id)=>provider===selection.provider&&id===selection.model?model:undefined,...withOpenCodeSessionHeader({streamSimple})}};
 llm.registerAdapter([selection.provider],adapter);
 try{
  const prepared=await llm.prepareCall(selection);assert.equal(prepared.config.sessionId,undefined);
  const control=[];for await(const chunk of prepared.stream({...prepared.config,messages:[]}))control.push(chunk);assert.equal(control.at(-1).reason.failure.code,'INVALID_REQUEST');assert.match(control.at(-1).reason.failure.message,/MissingSessionID/);
  const entries=[],gateway=createHarnessGateway({llm,selection,sessionId:'offline-scan-session',onDiagnostic:d=>entries.push(d)});
  for(const stream of [false,true]){const reply=await gateway({model:selection.model,input:'offline',stream,sessionId:'container-spoof',metadata:{sessionId:'metadata-spoof','x-opencode-session':'header-spoof'}});const text=await reply.text();assert.equal(reply.status,200,text);assert.match(text,/"status":"completed"/);assert.ok(!text.includes('offline-scan-session'));}
  assert.equal(calls.length,3);for(const call of calls.slice(1)){assert.equal(call.sessionId,'offline-scan-session');assert.equal(call.headers['x-opencode-session'],'offline-scan-session');assert.equal(call.headers['X-OFFLINE-FIXTURE'],'preserved');assert.equal(call.maxRetries,0);assert.equal(call.maxTokens,8192);}
  assert.ok(entries.every(d=>d.outcome==='completed'));assert.ok(!JSON.stringify(entries).includes('offline-scan-session'));
 }finally{await ctx.fiber.dispose();}
});
test('routing identity is stable across concurrent requests and separate between gateways',async()=>{
 const f=fixture();try{const one=createHarnessGateway({llm:f.llm,selection}),two=createHarnessGateway({llm:f.llm,selection});await Promise.all([one,one,two].map(async gateway=>{await(await gateway({model:selection.model,input:'offline'})).text();}));assert.equal(f.calls.length,3);assert.match(f.calls[0].sessionId,/^[a-f0-9-]{36}$/);assert.equal(f.calls[0].sessionId,f.calls[1].sessionId);assert.notEqual(f.calls[0].sessionId,f.calls[2].sessionId);}finally{await f.ctx.fiber.dispose();}
});
test('invalid routing identifiers fail before model preparation',()=>{
 for(const sessionId of [null,'','bad\r\nx-header: injected','x'.repeat(257),{},42])assert.throws(()=>createHarnessGateway({llm:{prepareCall(){assert.fail('Must not prepare');}},selection,sessionId}),/bounded session routing ID/);
});

function fixture(failure){
  const ctx=new Context(),llm=new LlmRuntime(ctx),calls=[];
  class OfflineAdapter extends LlmAdapter {
    async prepareCall(provider,model){
      return {model:{provider,id:model,name:model,defaultMaxTokens:8192},stream:async function*(options){
        calls.push(options);
        if(failure){yield {type:'finish',reason:{kind:'error',failure}};return;}
        yield {type:'block-start',index:0,blockType:'text'};
        yield {type:'text-delta',index:0,text:'offline'};
        yield {type:'block-end',index:0,block:{type:'text',text:'offline'}};
        yield {type:'finish',reason:{kind:'stop'}};
      }};
    }
  }
  llm.registerAdapter([selection.provider],new OfflineAdapter());
  return {ctx,llm,calls};
}

test('shipped Harness rejects request controls changed after prepareCall',async()=>{
  const f=fixture();
  try {
    const prepared=await f.llm.prepareCall(selection);
    assert.equal(prepared.config.maxTokens,8192);
    assert.throws(()=>prepared.stream({...prepared.config,maxTokens:50,messages:[]}),{code:'INVALID_PREPARED_CALL'});
    assert.equal(f.calls.length,0);
  } finally {await f.ctx.fiber.dispose();}
});

test('actual Harness preserves adapter-formatted rejection for safe plugin diagnostics',async()=>{
 const canary='OFFLINE-PRIVATE-SCHEMA-KEY',f=fixture({code:'INVALID_REQUEST',message:'400: '+JSON.stringify({error:{type:'invalid_request_error',code:'unsupported_parameter',param:'temperature',message:'Unsupported parameter: temperature. '+canary},source:canary})}),entries=[];
 try{const gateway=createHarnessGateway({llm:f.llm,selection,onDiagnostic:d=>entries.push(d)});const text=await(await gateway({model:selection.model,input:canary,stream:true})).text();assert.equal(entries.length,1);assert.equal(entries[0].reportedHttpStatus,400);assert.equal(entries[0].upstreamStatus,undefined);assert.equal(entries[0].rejectedParameter,'temperature');assert.deepEqual(entries[0].rejectionHints,['unsupported_parameter']);assert.ok(!JSON.stringify(entries).includes(canary));assert.ok(!text.includes(canary));assert.equal(f.calls.length,1);assert.equal(f.calls[0].maxTokens,8192);}finally{await f.ctx.fiber.dispose();}
});

test('gateway binds native request controls before real Harness preparation and dispatch',async()=>{
  for(const stream of [false,true])for(const controls of [{},{max_output_tokens:50},{temperature:0},{max_output_tokens:50,temperature:0.2}]){
    const f=fixture();
    try {
      const gateway=createHarnessGateway({llm:f.llm,selection});
      const response=await gateway({model:selection.model,input:'offline fixture',stream,...controls});
      assert.equal(response.status,200,await response.clone().text());
      const text=await response.text();
      assert.ok(!text.includes('"status":"failed"'),text);
      assert.ok(text.includes('"status":"completed"'),text);
      assert.equal(f.calls.length,1);
      assert.equal(f.calls[0].maxTokens,controls.max_output_tokens??8192);
      assert.equal(f.calls[0].temperature,controls.temperature);
    } finally {await f.ctx.fiber.dispose();}
  }
});
