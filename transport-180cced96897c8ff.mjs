import {StringDecoder} from 'node:string_decoder';
import {dockerArgs,checkRequest} from './core-180cced96897c8ff.mjs';
export const ENGINE_FAILURE_HINTS=Object.freeze(['state_directory_ownership','container_creation','container_cleanup','frame_protocol','unclassified']);
function engineFailureHint(failure,stage,frameError){
 if(stage==='cleanup')return 'container_cleanup';if(stage==='create')return 'container_creation';if(frameError===failure)return 'frame_protocol';
 try{const message=Object.getOwnPropertyDescriptor(failure,'message')?.value;if(typeof message==='string'&&/Scan output directory must be owned by the current user/i.test(message.slice(0,32768)))return 'state_directory_ownership';}catch{}
 return 'unclassified';
}
export function writeFrame(stream,value){return new Promise((resolve,reject)=>stream.write(JSON.stringify(value)+'\n',error=>error?reject(error):resolve()));}
export function abortable(promise,signal){
 if(!signal)return Promise.resolve(promise);if(signal.aborted){void Promise.resolve(promise).catch(()=>{});return Promise.reject(signal.reason??Error('Operation cancelled'));}
 return new Promise((resolve,reject)=>{const aborted=()=>reject(signal.reason??Error('Operation cancelled'));signal.addEventListener('abort',aborted,{once:true});Promise.resolve(promise).then(resolve,reject).finally(()=>signal.removeEventListener('abort',aborted));});
}
const missing=text=>/No such (?:container|object)/.test(text);
async function command(subprocess,docker,state,args,timeout){
 const handle=subprocess.spawn({argv:[docker,...args],cwd:state,stdio:{stdin:'ignore',stdout:{maxBytes:4000},stderr:{maxBytes:4000}},graceMs:6000,...(timeout?{signal:AbortSignal.timeout(timeout)}:{})});
 const outcome=await handle.done;return {...outcome,text:handle.collected.stderr.readFrom(0).text,output:handle.collected.stdout.readFrom(0).text};
}
// A missing *creating* lease is not proof of cleanup: a daemon request from a
// crashed client may still complete later. Keep the durable tombstone and retry.
export async function reconcileContainerLease({subprocess,docker,lease,cwd=process.cwd()}){
 if(lease.name!=='dsh-security-'+lease.id)throw Error('Invalid security container lease');
 const inspected=await command(subprocess,docker,cwd,['inspect','--format','\u007b"id":{{json .Id}},"labels":{{json .Config.Labels}}}',lease.name],15000);
 if(inspected.exitCode!==0){if(missing(inspected.text))return lease.phase==='created';throw Error('Security container reconciliation failed');}
 let container;try{container=JSON.parse(inspected.output);}catch{throw Error('Invalid security container inspection');}
 if(!/^[a-f0-9]{64}$/.test(container?.id??''))throw Error('Invalid security container identity');
 if(container.labels?.['io.dsh.security.lease']!==lease.id)throw Error('Security container lease label mismatch; refusing removal');
 const removed=await command(subprocess,docker,cwd,['rm','--force',container.id],15000);
 if(removed.exitCode!==0&&!missing(removed.text))throw Error('Docker container cleanup failed');return true;
}
export async function runEngine({subprocess,docker,image,repo,state,job,signal,gateway,onEvent=()=>{},onDiagnostic=()=>{},lease}){
 const name='dsh-security-'+job.id,abort=new AbortController();let child,stopping,cleanupError,creationAttempted=false,created=false,acquired=false;
 const cmd=(args,timeout)=>command(subprocess,docker,state,args,timeout);
 const stop=()=>stopping??=(async()=>{
  abort.abort();if(!creationAttempted){if(acquired)await lease.release(job.id);return;}if(child){void writeFrame(child.stdin,{type:'cancel'}).catch(()=>{});}
  // Await the bounded create client before teardown. A daemon-side create
  // can outlive that client: uncertain missing creating leases remain tombstones.
  // Even a failed create may mean a name collision: never stop/remove a
  // pre-existing container unless its durable lease label matches exactly.
  try{
  const inspected=await cmd(['inspect','--format','\u007b"id":{{json .Id}},"labels":{{json .Config.Labels}}}',name],15000);
  if(inspected.exitCode!==0){
   if(!missing(inspected.text))throw Error('Security container inspection failed during cleanup');
   if(child){child.terminate();try{await child.waitForExit(AbortSignal.timeout(10000));}catch{}}
   if(acquired&&created)await lease.release(job.id);return;
  }
  let container;try{container=JSON.parse(inspected.output);}catch{throw Error('Invalid security container inspection');}
  if(!/^[a-f0-9]{64}$/.test(container?.id??''))throw Error('Invalid security container identity');
  if(container.labels?.['io.dsh.security.lease']!==job.id)throw Error('Security container lease label mismatch; refusing removal');
  try{await cmd(['stop','--time','5',container.id],15000);}catch{}
  if(child){child.terminate();try{await child.waitForExit(AbortSignal.timeout(10000));}catch{}}
  const removed=await cmd(['rm','--force',container.id],15000);
  if(removed.exitCode!==0&&!missing(removed.text))throw Error('Docker container cleanup failed');
  if(acquired&&(removed.exitCode===0||created))await lease.release(job.id);
  }finally{if(child){child.terminate();try{await child.waitForExit(AbortSignal.timeout(10000));}catch{}}}
 })();
 const onAbort=()=>{void stop().catch(e=>{cleanupError=e;});};
 let result,engineError,buffer='',requestCount=0,active=0,peakActive=0,frameError,stage='create',failure;
 const started=performance.now();
 const decoder=new StringDecoder('utf8'),requests=new Set(),requestIds=new Set();
 try {
  signal?.throwIfAborted();
  const args=dockerArgs({image,repo,state,name});args.splice(1,0,'--label','io.dsh.security.lease='+job.id);
  if(lease){await lease.acquire({id:job.id,name,image,state,phase:'creating',createdAt:new Date().toISOString()});acquired=true;}
  signal?.throwIfAborted();creationAttempted=true;
  const creation=await cmd(args,30000);
  if(creation.exitCode!==0)throw Error('Scanner container creation failed: '+creation.text);created=true;
  if(lease)await lease.created(job.id);
  signal?.throwIfAborted();
  stage='start';
  child=subprocess.spawn({argv:[docker,'start','--attach','--interactive',name],cwd:state,stdio:{stdin:'pipe',stdout:'pipe',stderr:{maxBytes:16000}},graceMs:6000});
  signal?.addEventListener('abort',onAbort,{once:true});signal?.throwIfAborted();
  async function forward(frame){
   const send=value=>abortable(writeFrame(child.stdin,{...value,id:frame.id}),abort.signal);let counted=false;
   try {
    if(++requestCount>100||active>=4)throw Error('Model request limit exceeded');active++;peakActive=Math.max(peakActive,active);counted=true;
    const body=checkRequest(frame,job.model);
    if(typeof gateway!=='function')throw Error('Configured Harness model gateway is required');
    abort.signal.throwIfAborted();
    const requestSignal=AbortSignal.any([abort.signal,AbortSignal.timeout(180000)]);
    const response=await abortable(gateway(body,requestSignal),requestSignal);
    if(response.status>=400){void response.body?.cancel?.().catch(()=>{});throw Error('Upstream rejected request');}
    await send({type:'headers',status:response.status,contentType:response.headers.get('content-type')??'application/json'});
    let bytes=0;const iterator=(response.body??[])[Symbol.asyncIterator]?.()??[][Symbol.iterator]();
    for(;;){const item=await abortable(iterator.next(),requestSignal);if(item.done)break;const chunk=item.value;bytes+=chunk.length;if(bytes>64*1024*1024)throw Error('Model response limit exceeded');await send({type:'chunk',data:Buffer.from(chunk).toString('base64')});}await send({type:'end'});
   }catch(error){
    const message=['Model mismatch: fallback is prohibited','Configured Harness model gateway is required','Model request limit exceeded','Only the isolated Responses endpoint is allowed','External hosted tools are prohibited','Remote background/storage is prohibited'].includes(error.message)?error.message:'Harness model request failed; no fallback attempted';
    engineError??=message;onAbort();
    try{await send({type:'headers',status:502,contentType:'application/json'});await send({type:'chunk',data:Buffer.from(JSON.stringify({error:{message}})).toString('base64')});await send({type:'end'});}catch{}
   }finally{if(counted)active--;}
  }
  function handle(frame){
   if(!frame||typeof frame!=='object'||Array.isArray(frame))throw Error('Invalid scanner frame');
   if(frame.type==='request'){
    if(!Number.isSafeInteger(frame.id)||frame.id<1||requestIds.has(frame.id))throw Error('Invalid or duplicate scanner request ID');requestIds.add(frame.id);
    const task=forward(frame);requests.add(task);void task.finally(()=>requests.delete(task));
   }else if(frame.type==='result'){if(result!==undefined)throw Error('Duplicate scanner result');result=frame.value;}
   else if(frame.type==='error')engineError=String(frame.message).slice(0,4000);
   else if(['progress','warning'].includes(frame.type))onEvent(frame);
   else throw Error('Unexpected scanner frame');
  }
  child.stdout.on('data',chunk=>{
   try{buffer+=decoder.write(chunk);if(Buffer.byteLength(buffer)>32*1024*1024)throw Error('Scanner frame exceeds limit');
    let end;while((end=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,end);buffer=buffer.slice(end+1);if(line)handle(JSON.parse(line));}
   }catch(e){frameError=e;onAbort();}
  });child.stdin.on('error',()=>{});
  stage='frames';
  await abortable(writeFrame(child.stdin,{type:'start',job}),abort.signal);
  let outcome;try{outcome=await abortable(child.done,abort.signal);}catch(error){throw frameError??(engineError?Error(engineError):signal?.aborted?Error('Scan cancelled or deadline reached'):error);}
  // The engine may exit in the same turn that it consumes the last end frame.
  // Let pending Writable callbacks finish before aborting abandoned forwards.
  await new Promise(resolve=>setImmediate(resolve));abort.abort();await Promise.allSettled([...requests]);
  buffer+=decoder.end();if(buffer.trim())frameError??=Error('Incomplete scanner frame');
  if(frameError)throw frameError;if(cleanupError)throw cleanupError;
  if(signal?.aborted)throw Error('Scan cancelled or deadline reached');if(engineError)throw Error(engineError);
  if(outcome.exitCode!==0||result===undefined)throw Error('Scanner failed: '+child.collected.stderr.readFrom(0).text.slice(-4000));return result;
 }catch(error){failure=error;throw error;}
 finally{signal?.removeEventListener('abort',onAbort);abort.abort();
  try{await stop();}catch(error){failure=error;stage='cleanup';throw error;}
  finally{await Promise.allSettled([...requests]);
   const outcome=signal?.aborted?'cancelled':failure?'failed':'completed';
   try{onDiagnostic({kind:'engine',diagnosticVersion:2,...(failure?{engineFailureHint:engineFailureHint(failure,stage,frameError)}:{}),at:new Date().toISOString(),stage:outcome==='completed'?'complete':stage,outcome,code:failure?'UNKNOWN':'NONE',reason:outcome==='cancelled'?'abort':failure?'engine_failure':'complete',elapsedMs:Math.min(86400000,Math.max(0,Math.round(performance.now()-started))),requestCount,peakActive});}catch{}
  }
 }
}
