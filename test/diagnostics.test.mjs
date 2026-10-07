import test from 'node:test';
import assert from 'node:assert/strict';
import {createHarnessGateway,PROTOCOL_INVARIANTS} from '../harness-gateway.mjs';
import {readFile} from 'node:fs/promises';
import {retainDiagnostic,DIAGNOSTIC_LIMIT} from '../core.mjs';
test('retention caps actual entries at 128 and accounts for dropped entries without numeric overflow',()=>{
 const job={};for(let n=0;n<DIAGNOSTIC_LIMIT+3;n++)assert.equal(retainDiagnostic(job,{sequence:n}),n<DIAGNOSTIC_LIMIT);
 assert.equal(job.diagnostics.length,128);assert.equal(job.diagnosticsDropped,3);assert.equal(job.diagnostics.at(-1).sequence,127);
 job.diagnosticsDropped=Number.MAX_SAFE_INTEGER;assert.equal(retainDiagnostic(job,{sequence:132}),false);assert.equal(job.diagnosticsDropped,Number.MAX_SAFE_INTEGER);
});
test('explicit private capture preserves unfamiliar rejection verbatim without leaking into normal diagnostics',async()=>{
 const message='400: '+JSON.stringify({error:{message:'An unfamiliar provider explanation '+secret,code:'private_unknown_code'}});
 for(const kind of ['prepare','dispatch','iterate']){
  const captured=[],error=Object.assign(Error(message),{code:'INVALID_REQUEST'}),opts={privateObserver:value=>captured.push(value),...(kind==='prepare'?{prepareError:error}:kind==='dispatch'?{thrown:error}:{failure:{code:'INVALID_REQUEST',message}})};
  const f=setup(opts),reply=await(await f.gateway(request)).text();assert.equal(captured.length,1);assert.equal(captured[0].message.text,message);assert.equal(captured[0].message.truncated,false);assert.equal(captured[0].stage,kind);assert.equal(captured[0].requestId,f.diagnostics[0].requestId);assert.ok(!JSON.stringify(f.diagnostics).includes(secret));assert.ok(!reply.includes(secret));assert.equal(f.dispatches,kind==='prepare'?0:1);
 }
});
test('private capture is bounded by UTF-8 bytes, ignores accessors, and cannot break gateway failures',async()=>{
 const captured=[],failure={code:'INVALID_REQUEST',message:'🙂'.repeat(100000),error:{message:'nested '+secret}};const f=setup({failure,privateObserver:v=>captured.push(v)});await(await f.gateway(request)).text();assert.equal(captured.length,1);assert.ok(Buffer.byteLength(captured[0].message.text)<=65536);assert.equal(captured[0].message.truncated,true);assert.equal(captured[0].message.chars,failure.message.length);assert.equal(captured[0].nestedMessage.text,'nested '+secret);
 let reads=0;const getter=Object.defineProperty({code:'INVALID_REQUEST'},'message',{get(){reads++;throw Error(secret);}});const g=setup({failure:getter,privateObserver:()=>{throw Error(secret);}});await(await g.gateway(request)).text();assert.equal(reads,0);assert.equal(g.dispatches,1);assert.equal(g.diagnostics[0].outcome,'failed');
 const rejected=setup({failure,privateObserver:async()=>{throw Error(secret);}});await(await rejected.gateway(request)).text();assert.equal(rejected.dispatches,1);
});
test('private capture never runs for successful, cancelled, or local protocol requests',async()=>{
 const captured=[],f=setup({privateObserver:v=>captured.push(v)});await(await f.gateway(request)).text();await(await f.gateway({...request,max_output_tokens:-1})).text();const controller=new AbortController();controller.abort();await(await f.gateway(request,controller.signal)).text();assert.equal(captured.length,0);
});
const selection={provider:'offline',model:'fixture',contextWindow:8192};
const secret='TEST-ONLY-SOURCE-SCHEMA-REPLAY-CREDENTIAL-CANARY';
const request={model:'fixture',input:secret,instructions:secret,tools:[{type:'function',name:secret,description:secret,parameters:{type:'object',properties:{[secret]:{type:'string'}}}}],max_output_tokens:50,temperature:0,stream:true};
function setup({failure,thrown,prepareError,observer,privateObserver}={}){
 const diagnostics=[];let dispatches=0;
 const gateway=createHarnessGateway({selection,onPrivateError:privateObserver,onDiagnostic:entry=>{diagnostics.push(entry);observer?.(entry);},llm:{async prepareCall(config){if(prepareError)throw prepareError;return{config,stream(){dispatches++;if(thrown)throw thrown;return(async function*(){if(failure)yield{type:'finish',reason:{kind:'error',failure}};else{yield{type:'block-start',index:0,blockType:'text'};yield{type:'text-delta',index:0,text:secret};yield{type:'block-end',index:0,block:{type:'text',text:secret}};yield{type:'finish',reason:{kind:'stop'}};}})();}};}}});
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
 const f=setup();assert.equal((await f.gateway({...request,max_output_tokens:-1})).status,400);assert.equal(f.diagnostics[0].stage,'translate');assert.equal(f.diagnostics[0].code,'PROTOCOL_ERROR');assert.equal(f.diagnostics[0].protocolInvariant,'invalid_token_limit');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));assert.equal(f.dispatches,0);
});

test('every literal local rejection has a fixed invariant, with no provider-controlled invariant',async()=>{
  const source=await readFile(new URL('../harness-gateway.mjs',import.meta.url),'utf8');
  const map=source.slice(source.indexOf('const PROTOCOL_MESSAGES'),source.indexOf('export const PROTOCOL_INVARIANTS'));
  const mapped=[...map.matchAll(/^  ([a-z_]+): '([^']+)',/gm)];
  assert.deepEqual(PROTOCOL_INVARIANTS,[...mapped.map(match=>match[1]),'unclassified']);
  for(const [,message]of source.matchAll(/(?:fail|new ProtocolError)\('([^']+)'\)/g))assert.ok(mapped.some(match=>match[2]===message),'Missing invariant: '+message);
  const f=setup({failure:{code:'INVALID_REQUEST',protocolInvariant:secret,message:secret}});await(await f.gateway(request)).text();
  assert.equal(f.diagnostics[0].protocolInvariant,undefined);assert.ok(!JSON.stringify(f.diagnostics).includes(secret));
});

test('cached replay rejection records its exact fixed invariant without retaining assistant text',async()=>{
  const f=setup();const frames=(await(await f.gateway(request)).text()).trim().split('\n\n').map(frame=>JSON.parse(frame.split('\n').find(line=>line.startsWith('data: ')).slice(6)));
  const output=frames.find(frame=>frame.type==='response.completed').response.output;
  output[0].content[0].text+='edited';
  assert.equal((await f.gateway({...request,input:output})).status,400);
  assert.equal(f.diagnostics[1].protocolInvariant,'replay_group_mismatch');assert.equal(f.diagnostics[1].stage,'translate');assert.equal(f.dispatches,1);assert.ok(!JSON.stringify(f.diagnostics).includes(secret));
});

test('unknown failure codes and diagnostic getters are not exposed or evaluated',async()=>{
 let reads=0;for(const field of ['code','status','failure']){const error=Object.defineProperty(Error(secret),field,{get(){reads++;throw Error(secret);}});const f=setup({thrown:error});await(await f.gateway(request)).text();assert.equal(f.diagnostics[0].code,'UNKNOWN');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));}assert.equal(reads,0);
 const f=setup({failure:{code:secret,message:secret}});await(await f.gateway(request)).text();assert.equal(f.diagnostics[0].code,'UNKNOWN');assert.ok(!JSON.stringify(f.diagnostics).includes(secret));
});

test('SDK formatted JSON rejection yields actionable enums without raw body or schema paths',async()=>{
 const message='400: '+JSON.stringify({error:{code:'invalid_function_parameters',type:'invalid_request_error',param:`tools[12].function.parameters.properties.${secret}`,message:`Invalid schema for function '${secret}': 'additionalProperties' is required to be supplied and to be false. 'required' is required to include all fields. Missing '${secret}'.`,requestId:secret},source:secret});
 const f=setup({failure:{code:'INVALID_REQUEST',message}});const response=await(await f.gateway(request)).text(),d=f.diagnostics[0];
 assert.equal(d.diagnosticVersion,2);assert.equal(d.reportedHttpStatus,400);assert.equal(d.upstreamStatus,undefined);assert.equal(d.reason,'ambiguous_request_rejection');assert.equal(d.providerErrorCode,'invalid_function_parameters');assert.equal(d.providerErrorType,'invalid_request_error');assert.equal(d.rejectedParameter,'tools');assert.equal(d.rejectedToolIndex,12);assert.deepEqual(d.rejectionHints,['tool_schema_invalid','schema_additional_properties','schema_required']);assert.equal(d.providerMessageChars,message.length);assert.equal(d.providerMessageTruncated,false);assert.ok(!JSON.stringify(d).includes(secret));assert.ok(!response.includes(secret));assert.equal(f.dispatches,1);
});

test('quoted statuses and parameter failures stay evidence, never trusted status or changed inference',async()=>{
 for(const [message,status,hint]of [['413: <html>Payload too large '+secret+'</html>',413,'request_body_too_large'],['400 max_tokens must be at most 8192. '+secret,400,'output_token_limit'],['400 Unsupported parameter temperature. '+secret,400,'unsupported_parameter'],['context window exceeds maximum '+secret,undefined,'context_limit'],['model does not exist '+secret,undefined,'model_unavailable']]){
  const f=setup({failure:{code:'INVALID_REQUEST',message}});await(await f.gateway(request)).text();const d=f.diagnostics[0];assert.equal(d.reportedHttpStatus,status);assert.equal(d.upstreamStatus,undefined);assert.ok(d.rejectionHints.includes(hint),JSON.stringify(d));assert.ok(!JSON.stringify(d).includes(secret));assert.equal(f.dispatches,1);
 }
});

test('unknown provider values, echoed body fields, non-prefix numbers and hostile messages cannot leak',async()=>{
 for(const message of ['request '+secret+' status 413',JSON.stringify({error:{code:secret,type:secret,param:secret,message:secret},source:'unsupported parameter; payload too large'})]){
  const f=setup({failure:{code:'INVALID_REQUEST',message}});await(await f.gateway(request)).text();const d=f.diagnostics[0];assert.equal(d.reportedHttpStatus,undefined);assert.equal(d.providerErrorCode,undefined);assert.equal(d.providerErrorType,undefined);assert.equal(d.rejectedParameter,undefined);assert.deepEqual(d.rejectionHints,['unclassified']);assert.ok(!JSON.stringify(d).includes(secret));
 }
 let reads=0;const error=Object.defineProperty(Object.assign(Error(),{code:'INVALID_REQUEST'}),'message',{get(){reads++;throw Error(secret);}});const f=setup({thrown:error});await(await f.gateway(request)).text();assert.equal(reads,0);assert.equal(f.diagnostics[0].messageAvailable,false);
});

test('truncated/malformed JSON never classifies echoed body fields and response schemas are not tool schemas',async()=>{
 for(const message of ['400: '+JSON.stringify({source:'unsupported parameter; payload too large; rate limit',padding:'x'.repeat(40000),error:{message:'Opaque rejection'}}),'400: {"source":"unsupported parameter; payload too large",','400: '+JSON.stringify({error:false,source:'unsupported parameter; payload too large'})]){const f=setup({failure:{code:'INVALID_REQUEST',message}});await(await f.gateway(request)).text();assert.deepEqual(f.diagnostics[0].rejectionHints,['unclassified']);}
 const f=setup({failure:{code:'INVALID_REQUEST',message:'400: '+JSON.stringify({error:{code:'invalid_json_schema',param:'response_format',message:'Invalid JSON schema'}})}});await(await f.gateway(request)).text();assert.deepEqual(f.diagnostics[0].rejectionHints,['schema_invalid']);assert.equal(f.diagnostics[0].rejectedParameter,'response_format');
});

test('nested structured error text and parameters are bounded and truncation is reported honestly',async()=>{
 const error=Object.assign(Error('adapter error'),{code:'INVALID_REQUEST',error:{param:'a'.repeat(1000000),message:'x'.repeat(40000)+' unsupported parameter'}}),f=setup({prepareError:error});await(await f.gateway(request)).text();const d=f.diagnostics[0];assert.equal(d.providerMessageTruncated,true);assert.equal(d.providerMessageChars,13);assert.equal(d.inspectedMessageChars,error.error.message.length);assert.equal(d.rejectedParameter,undefined);assert.deepEqual(d.rejectionHints,['unclassified']);
});

test('message inspection is bounded and never persists a large raw error',async()=>{
 const message='400 '+secret.repeat(2000)+' payload too large';const f=setup({failure:{code:'INVALID_REQUEST',message}});await(await f.gateway(request)).text();const d=f.diagnostics[0];assert.equal(d.providerMessageTruncated,true);assert.equal(d.providerMessageChars,message.length);assert.deepEqual(d.rejectionHints,['unclassified']);assert.ok(JSON.stringify(d).length<2048);assert.ok(!JSON.stringify(d).includes(secret));
});

test('diagnostic callback exceptions cannot alter successful inference',async()=>{
 const f=setup({observer:()=>{throw Error(secret);}});const text=await(await f.gateway(request)).text();assert.match(text,/response.completed/);assert.equal(f.dispatches,1);assert.equal(f.diagnostics.length,1);
});

test('stream cancellation and aborted preparation each emit exactly one terminal snapshot',async()=>{
 const f=setup();const response=await f.gateway(request);await response.body.cancel();assert.equal(f.diagnostics.length,1);assert.equal(f.diagnostics[0].outcome,'cancelled');
 const entries=[],controller=new AbortController();const gateway=createHarnessGateway({selection,onDiagnostic:e=>entries.push(e),llm:{prepareCall:()=>new Promise(()=>{})}});const pending=gateway(request,controller.signal);controller.abort();assert.equal((await pending).status,499);assert.equal(entries.length,1);assert.equal(entries[0].stage,'prepare');assert.equal(entries[0].reason,'abort');
});
