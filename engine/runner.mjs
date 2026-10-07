import http from 'node:http';
import readline from 'node:readline';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import {CodexSecurity, exportArtifact} from '@openai/codex-security';
const emit = value => process.stdout.write(JSON.stringify(value)+'\n');
const pending = new Map(); let next = 0, started = false;
const controller = new AbortController();
process.on('SIGTERM',()=>controller.abort());process.on('SIGINT',()=>controller.abort());
const gateway=http.createServer(async(req,res)=>{
  try {
    let body=''; for await (const chunk of req) {body+=chunk; if(Buffer.byteLength(body)>16*1024*1024)throw Error('Model request too large');}
    const id=++next; pending.set(id,res); res.on('close',()=>pending.delete(id));
    emit({type:'request',id,method:req.method,path:req.url,body});
  } catch {res.writeHead(413);res.end();}
});
await new Promise(resolve=>gateway.listen(0,'127.0.0.1',resolve));
const port=gateway.address().port;
const lines=readline.createInterface({input:process.stdin});
lines.on('line',line=>{
  try {
    const frame=JSON.parse(line);
    if(frame.type==='start'&&!started){started=true;void run(frame.job).catch(e=>{emit({type:'error',message:e.message});process.exitCode=2;}).finally(()=>{gateway.closeAllConnections();gateway.close();lines.close();process.stdin.destroy();});return;}
    if(frame.type==='cancel'){controller.abort();return;}
    const res=pending.get(frame.id);if(!res)return;
    if(frame.type==='headers')res.writeHead(frame.status,{'content-type':frame.contentType??'application/json'});
    if(frame.type==='chunk')res.write(Buffer.from(frame.data,'base64'));
    if(frame.type==='end'){res.end();pending.delete(frame.id);}
  }catch{controller.abort();}
});
async function run(job){
  await mkdir('/scratch/home',{recursive:true});await mkdir('/scratch/codex',{recursive:true});
  if(job.operation==='probe'){
    let readonly=false;try{await writeFile('/repo/.dsh-readonly-probe','not allowed');}catch(e){readonly=e.code==='EROFS'||e.code==='EACCES';}
    const response=await fetch(`http://127.0.0.1:${port}/responses`,{method:'POST',body:JSON.stringify({model:job.model,input:'transport probe',max_output_tokens:1}),signal:controller.signal});
    emit({type:'result',value:{readonly,transportStatus:response.status,transportBody:await response.text()}});return;
  }
  const catalog=JSON.parse(await readFile('/opt/security/models.json','utf8'));
  catalog.models[0].slug=job.model;
  if(Number.isSafeInteger(job.contextWindow)&&job.contextWindow>0&&job.contextWindow<=4194304){catalog.models[0].context_window=job.contextWindow;catalog.models[0].max_context_window=job.contextWindow;}
  await writeFile('/scratch/models.json',JSON.stringify(catalog));
  const security=new CodexSecurity({pythonPath:'/usr/bin/python3',codexOverrides:{
    model:job.model,model_provider:'harness',model_reasoning_effort:'high',model_catalog_json:'/scratch/models.json',web_search:'disabled',
    approval_policy:'never',analytics:{enabled:false},cli_auth_credentials_store:'file',mcp_servers:{},
    model_providers:{harness:{name:'Harness isolated model gateway',base_url:`http://127.0.0.1:${port}/`,wire_api:'responses',supports_websockets:false,request_max_retries:0,stream_max_retries:0,
      auth:{command:'/usr/local/bin/node',args:['/opt/security/token.mjs'],timeout_ms:5000,refresh_interval_ms:0}}}
  }});
  try {
    if(job.operation==='export'){
      const result=await exportArtifact({source:{directory:'/state/result'},artifact:'findings',format:job.format,output:`/state/export.${job.format}`,pythonPath:'/usr/bin/python3',signal:controller.signal});
      emit({type:'result',value:{export:await readFile(`/state/export.${job.format}`,'utf8'),metadata:result}});return;
    }
    if(job.operation==='validate'){
      const result=await security.validate({repositoryPath:'/repo',finding:job.finding,outputDir:'/state/validation',auth:'auto',signal:controller.signal});
      emit({type:'result',value:result});return;
    }
    const result=await security.run('/repo',{mode:job.mode??'standard',outputDir:'/state/result',auth:'auto',signal:controller.signal,
      ...(job.mock?{mock:true}:{}),...(job.mode==='deep'?{workers:2,subagents:2,maxDiscoveryRuns:6,maxTimeHours:job.minutes/60}:{}),
      onProgress:value=>emit({type:'progress',value}),onDeepProgress:value=>emit({type:'progress',value}),onWarning:value=>emit({type:'warning',value})});
    emit({type:'result',value:{...result.toJSON(),report:await readFile(result.reportPath,'utf8')}});
  } finally {await security.close();}
}
