import {randomUUID,randomBytes,timingSafeEqual} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,lstat,realpath} from 'node:fs/promises';
export const DIAGNOSTIC_LIMIT=128;
export function retainDiagnostic(job,entry){
  job.diagnostics??=[];
  if(job.diagnostics.length>=DIAGNOSTIC_LIMIT){job.diagnosticsDropped=Math.min(Number.MAX_SAFE_INTEGER,(job.diagnosticsDropped??0)+1);return false;}
  job.diagnostics.push(entry);return true;
}
export function checkRequest(frame,model){
  if(frame.method!=='POST'||frame.path!=='/responses')throw Error('Only the isolated Responses endpoint is allowed');
  if(typeof frame.body!=='string'||Buffer.byteLength(frame.body)>16*1024*1024)throw Error('Invalid request body');
  const body=JSON.parse(frame.body);
  if(typeof model!=='string'||!model||!body||typeof body!=='object'||Array.isArray(body)||body.model!==model)throw Error('Model mismatch: fallback is prohibited');
  if(body.background===true||body.store===true)throw Error('Remote background/storage is prohibited');
  // Web/remote MCP and provider routing are outside the authorized scan boundary.
  const localTools=tools=>Array.isArray(tools)&&tools.every(t=>t&&(['function','custom'].includes(t.type)||(t.type==='namespace'&&localTools(t.tools))));
  if(body.tools!==undefined&&!localTools(body.tools))throw Error('External hosted tools are prohibited');
  return {...body,store:false};
}
export function ownedScan(table,workspaceId,id){const scan=table.get(id);if(!scan||scan.workspaceId!==workspaceId)throw Error('Scan not found in this workspace');return scan;}
export function dockerArgs({image,repo,state,name,seccomp=fileURLToPath(new URL('./seccomp-647901da553bcb98.json',import.meta.url))}){
  if(!/^sha256:[a-f0-9]{64}$/.test(image))throw Error('A verified immutable scanner image is required');
  for(const value of [repo,state])if(!path.isAbsolute(value)||/[\r\n,]/.test(value))throw Error('Unsafe Docker mount path');
  const uid=process.getuid?.()??1000,gid=process.getgid?.()??1000;if(uid===0)throw Error('Run Harness as a non-root user');
  return ['create','--interactive','--user',`${uid}:${gid}`,'--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--security-opt',`seccomp=${seccomp}`,'--pids-limit','512','--memory','4g','--cpus','4','--tmpfs','/tmp:rw,nosuid,size=512m','--tmpfs',`/scratch:rw,nosuid,uid=${uid},gid=${gid},size=512m`,
    '--mount',`type=bind,src=${repo},dst=/repo,readonly,bind-propagation=rprivate,bind-recursive=readonly`,
    '--mount',`type=bind,src=${state},dst=/state`,image];
}
export async function privateState(root,workspacePath){
  await mkdir(root,{recursive:true,mode:0o700});
  const resolved=await realpath(root),repo=await realpath(workspacePath);
  if(resolved===repo||resolved.startsWith(repo+path.sep))throw Error('Scanner state must be outside the source workspace');
  for(let dir=resolved;;dir=path.dirname(dir)){
    try{await lstat(path.join(dir,'.git'));throw Error('Scanner state must be outside every Git worktree');}catch(e){if(e.code!=='ENOENT')throw e;}
    if(path.dirname(dir)===dir)break;
  }
  if((await lstat(resolved)).mode&0o077)throw Error('Scanner state directory must have mode 700');
  return {root:resolved,repo};
}
export function newId(){return randomUUID();}
export function scanSummary(scan){const{result,events,diagnostics,...rest}=scan;return {...rest,findings:result?.findings?.findings?.length??0,lastEvent:events?.at(-1)};}
// An authenticated, non-cacheable UI bootstrap issues this per-runtime CSRF
// token. It never enters agent tool results, scan state, exports or logs.
export function newPanelToken(){return randomBytes(32).toString('base64url');}
export function panelTokenAllowed(req,token){
  const supplied=req.headers['x-dsh-security-csrf'];
  return typeof supplied==='string'&&/^[A-Za-z0-9_-]{43}$/.test(supplied)&&timingSafeEqual(Buffer.from(supplied),Buffer.from(token));
}
export function localRequestAllowed(req){
  const host=req.headers.host??'',origin=req.headers.origin;
  return req.method==='POST'&&req.headers['x-dsh-security']==='1'&&/^(127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(host)&&(origin===undefined||origin===`http://${host}`)&&(req.headers['sec-fetch-site']===undefined||req.headers['sec-fetch-site']==='same-origin')&&['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
}
