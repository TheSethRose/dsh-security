import {z} from 'zod';
import {defineDomain,domainTable} from '@deepseek-ai/dsh-storage-domain';
import {defineTool} from '@deepseek-ai/dsh-tools';
import {mkdir,readFile} from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';
import {ownedScan,privateState,newId,scanSummary,localRequestAllowed} from './core-339429f00f8f0e4b.mjs';
import {runEngine,reconcileContainerLease} from './transport-339429f00f8f0e4b.mjs';
import {modelCatalog,resolveSelection} from './models-339429f00f8f0e4b.mjs';
import {createHarnessGateway} from './harness-gateway-339429f00f8f0e4b.mjs';
export const name='dsh-security';
export const inject=['storageDomain','workspaceRegistry','tools','llm','sessionController','subprocess','webServer','connection'];
const identity=z.string().min(1).max(512);
const record=z.object({id:z.string().uuid(),workspaceId:z.string(),operation:z.enum(['scan','validate']),parentId:z.string().optional(),provider:identity.optional(),model:identity,reasoningEffort:identity.optional(),contextWindow:z.number().int().positive().optional(),mode:z.enum(['standard','deep']),minutes:z.number(),state:z.string(),status:z.enum(['running','completed','failed','cancelled','interrupted']),createdAt:z.string(),finishedAt:z.string().optional(),error:z.string().optional(),events:z.array(z.string()),result:z.unknown().optional()}).strict();
const leaseRecord=z.object({id:z.string().uuid(),name:z.string(),image:z.string(),state:z.string(),phase:z.enum(['creating','created']),createdAt:z.string()}).strict();
const spec=defineDomain({name:'security_scans',version:1,tables:{scans:domainTable(record),leases:domainTable(leaseRecord)}});
const request=z.object({operation:z.enum(['workspaces','status','list','get','start','cancel','validate','export']),workspaceId:z.string().optional(),id:z.string().uuid().optional(),provider:identity.optional(),model:identity.optional(),reasoningEffort:identity.optional(),mode:z.enum(['standard','deep']).optional(),minutes:z.number().int().min(1).max(120).optional(),format:z.enum(['json','csv','sarif']).optional(),findingIndex:z.number().int().min(0).optional(),userRequested:z.boolean().optional()}).strict();
export async function apply(ctx){
  const domain=await ctx.storageDomain.open(spec),table=domain.table('scans'),leases=domain.table('leases');
  const running=new Map(),exportsPending=new Set();let closing=false,recoveryTimer,recoveryTask;
  ctx.effect(()=>async()=>{closing=true;clearInterval(recoveryTimer);const tasks=[...running.values(),...exportsPending];for(const task of tasks)task.controller.abort();await Promise.allSettled([...tasks.map(t=>t.done),recoveryTask]);await domain.close();},'security scan shutdown');
  const image=(JSON.parse(await readFile(new URL('./image-339429f00f8f0e4b.json',import.meta.url),'utf8'))).image;
  const root=path.join(os.homedir(),'.dsh','security-scans');
  const docker=await ctx.subprocess.resolveExecutable(process.env.DSH_SECURITY_DOCKER??'docker');
  const lease={acquire:row=>leases.put(row.id,row),created:async id=>{const row=leases.get(id);await leases.put(id,{...row,phase:'created'});},release:id=>leases.delete(id)};
  async function recover(){for(const [id,row]of leases.entries()){
    if([...running.values()].some(t=>t.record?.id===id)||[...exportsPending].some(t=>t.id===id))continue;
    if(await reconcileContainerLease({subprocess:ctx.subprocess,docker,lease:row}))await leases.delete(id);
  }}
  await recover();
  for(const [id,row]of table.entries())if(row.status==='running')await table.put(id,{...row,status:'interrupted',finishedAt:new Date().toISOString(),error:'Runtime stopped; scans are not resumed automatically'});
  recoveryTimer=setInterval(()=>{if(closing||recoveryTask)return;recoveryTask=recover().catch(error=>ctx.logger?.error?.('Security orphan reconciliation failed: %s',error.message)).finally(()=>{recoveryTask=undefined;});},30000);recoveryTimer.unref?.();
  async function start(workspace,args,operation='scan'){
    if(args.userRequested!==true)throw Error('Explicit user authorization to send workspace source to the selected Harness provider is required');
    if(closing||running.has(workspace.id))throw Error('A scan is already active for this workspace, or the plugin is stopping');
    const controller=new AbortController();let settle;const task={controller,done:new Promise(resolve=>{settle=resolve;})};running.set(workspace.id,task);
    const deadline=setTimeout(()=>controller.abort(),(args.minutes??30)*60000);
    try {
      const parent=operation==='validate'?ownedScan(table,workspace.id,args.id):undefined;
      const finding=parent?.result?.findings?.findings?.[args.findingIndex];
      if(operation==='validate'&&(!finding||parent.status!=='completed'||parent.operation!=='scan'))throw Error('Select an existing finding from a completed scan');
      const selection=await resolveSelection(ctx.llm,{provider:args.provider,model:args.model,...(args.reasoningEffort!==undefined?{reasoningEffort:args.reasoningEffort}:{})},AbortSignal.any([controller.signal,AbortSignal.timeout(15000)]),ctx.sessionController);
      const paths=await privateState(root,workspace.path);
      const id=newId(),state=path.join(paths.root,id);await mkdir(state,{mode:0o700});
      controller.signal.throwIfAborted();if(closing)throw Error('Plugin is stopping');
      const job=record.parse({id,workspaceId:workspace.id,operation,...(parent?{parentId:parent.id}:{}),...selection,mode:args.mode??'standard',minutes:args.minutes??30,state,status:'running',createdAt:new Date().toISOString(),events:[]});
      await table.put(id,job);task.record=job;
      const execution=(async()=>{
        try {
          const gateway=createHarnessGateway({llm:ctx.llm,selection:{provider:job.provider,model:job.model,...(job.reasoningEffort!==undefined?{reasoningEffort:job.reasoningEffort}:{})}});
          const result=await runEngine({subprocess:ctx.subprocess,docker,image,repo:paths.repo,state,job:{...job,...(finding?{finding}: {})},signal:controller.signal,gateway,lease,
            onEvent:event=>{job.events.push(JSON.stringify(event).slice(0,2000));job.events=job.events.slice(-50);}});
          job.result=result;job.status='completed';
        }catch(error){job.status=controller.signal.aborted?'cancelled':'failed';job.error=String(error.message).slice(0,4000);}
        finally{clearTimeout(deadline);job.finishedAt=new Date().toISOString();await table.put(id,job);}
      })();
      void execution.catch(error=>ctx.logger?.error?.('Security scan persistence failed: %s',error.message)).finally(()=>{running.delete(workspace.id);settle();});
      return scanSummary(job);
    }catch(error){clearTimeout(deadline);running.delete(workspace.id);settle();throw error;}
  }
  async function invoke(raw,workspace,fromUI=false){
    const a=request.parse(raw);if(['start','validate'].includes(a.operation)&&!fromUI)throw Error('Start/validation require the authenticated Security panel; agents cannot authorize inference');if(a.operation==='workspaces')return ctx.workspaceRegistry.list().map(w=>({id:w.id,title:w.title,path:w.path}));if(!workspace)throw Error('Registered workspace required');
    switch(a.operation){
      case 'status':{
        const catalog=await modelCatalog(ctx.sessionController);
        return {runtimeRevision:import.meta.url.match(/runtime-([a-f0-9]+)\.mjs/)?.[1]??'source',engine:'@openai/codex-security@0.2.0',image,...catalog,active:running.has(workspace.id),routing:'harness-llm',authentication:'configured-provider',network:'none',reportOnly:true};
      }
      case 'list':return [...table.entries()].map(([,r])=>r).filter(r=>r.workspaceId===workspace.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,100).map(scanSummary);
      case 'get':{const row=ownedScan(table,workspace.id,a.id);const live=running.get(workspace.id)?.record;return live?.id===row.id?{...live}:row;}
      case 'start':return start(workspace,a);
      case 'validate':return start(workspace,a,'validate');
      case 'cancel':{const row=ownedScan(table,workspace.id,a.id);if(row.status!=='running')return scanSummary(row);const task=running.get(workspace.id);if(task?.record?.id===row.id){task.controller.abort();await task.done;}return scanSummary(ownedScan(table,workspace.id,a.id));}
      case 'export':{
        const row=ownedScan(table,workspace.id,a.id);if(row.status!=='completed'||row.operation!=='scan')throw Error('Only completed scans can be exported');
        if(closing)throw Error('Plugin is stopping');
        const controller=new AbortController();let settle;const task={id:newId(),controller,done:new Promise(resolve=>{settle=resolve;})};exportsPending.add(task);
        try{const paths=await privateState(root,workspace.path);controller.signal.throwIfAborted();
          return await runEngine({subprocess:ctx.subprocess,docker,image,repo:paths.repo,state:row.state,job:{id:task.id,operation:'export',model:row.model,format:a.format??'json'},signal:AbortSignal.any([controller.signal,AbortSignal.timeout(60000)]),lease});
        }finally{exportsPending.delete(task);settle();}
      }
    }
  }
  ctx.tools.register(defineTool({name:'security_scan',description:'Workspace-scoped security scan reports and configured Harness model metadata. Start/validation require the authenticated Security panel and human consent; agents cannot authorize inference. get/list read reports, cancel stops a scan, export returns JSON/CSV/SARIF. No patching, publication or provider/model fallback. Workspace is derived from the execution session.',parameters:{operation:{type:'string',required:true,enum:['status','list','get','cancel','export']},id:{type:'string'},format:{type:'string',enum:['json','csv','sarif']}},output:{schema:{type:'json'},render:(_a,v)=>[{type:'text',text:JSON.stringify(v).slice(0,64000)}]},execute(a,exec){exec.signal.throwIfAborted();return invoke(a,ctx.workspaceRegistry.list().find(w=>w.sessionIds.includes(exec.agent?.id)));}}));
  ctx.effect(()=>ctx.webServer.register({kind:'exact',path:'/dsh-security/api',async handler(req,res){
    res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
    try {
      const rejection=ctx.connection.requestRejection(req);if(rejection||!localRequestAllowed(req)){res.statusCode=rejection??403;res.end(JSON.stringify({error:'Authenticated local same-origin request required'}));return;}
      let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>32000)throw Error('Request too large');}
      const args=request.parse(JSON.parse(body));const workspace=ctx.workspaceRegistry.get(args.workspaceId);
      const paid=['start','validate'].includes(args.operation);if(paid&&req.headers.origin!==`http://${req.headers.host}`)throw Error('Inference must be authorized from the same-origin Security panel');
      res.end(JSON.stringify({result:await invoke(args,workspace,true)}));
    }catch(error){res.statusCode=400;res.end(JSON.stringify({error:error.message}));}
  }}),'security API');
}
