import {z} from 'zod';
import {defineDomain,domainTable} from '@deepseek-ai/dsh-storage-domain';
import {defineTool} from '@deepseek-ai/dsh-tools';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import os from 'node:os';import path from 'node:path';
import {ownedScan,privateState,newId,scanSummary,localRequestAllowed,newPanelToken,panelTokenAllowed,retainDiagnostic,DIAGNOSTIC_LIMIT} from './core-0fc22475e7860865.mjs';
import {runEngine,reconcileContainerLease,ENGINE_FAILURE_HINTS,OPERATION_DEADLINE_MESSAGE} from './transport-0fc22475e7860865.mjs';
import {modelCatalog,resolveSelection} from './models-0fc22475e7860865.mjs';
import {createHarnessGateway,DIAGNOSTIC_CODES,PROTOCOL_INVARIANTS,PROVIDER_CODES,REJECTED_PARAMETERS,REJECTION_HINTS,REPLAY_ITEM_TYPES,REPLAY_MISMATCHES} from './harness-gateway-0fc22475e7860865.mjs';
export const name='dsh-security';
export const inject=['storageDomain','workspaceRegistry','tools','llm','sessionController','subprocess','webServer','connection'];
const identity=z.string().min(1).max(512);
const counter=z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const diagnostic=z.object({kind:z.enum(['gateway','engine']),at:z.string().datetime(),requestId:z.string().uuid().optional(),
  stage:z.enum(['translate','prepare','dispatch','iterate','assemble','complete','create','start','frames','cleanup']),outcome:z.enum(['completed','failed','cancelled']),
  code:z.enum(DIAGNOSTIC_CODES),reason:z.enum(['complete','abort','protocol_rejection','adapter_failure','size_rejection','request_rejected','ambiguous_request_rejection','engine_failure']),
  elapsedMs:counter.max(86400000),upstreamStatus:z.number().int().min(100).max(599).optional(),
  protocolInvariant:z.enum(PROTOCOL_INVARIANTS).optional(),replayMismatch:z.enum(REPLAY_MISMATCHES).optional(),replayExpectedType:z.enum(REPLAY_ITEM_TYPES).optional(),replayObservedType:z.enum(REPLAY_ITEM_TYPES).optional(),replayGroupOffset:counter.optional(),replayMismatchPosition:counter.optional(),replayExpectedItems:counter.optional(),replayAvailableItems:counter.optional(),replayArgumentsEquivalent:z.boolean().optional(),diagnosticVersion:z.literal(2).optional(),engineFailureHint:z.enum(ENGINE_FAILURE_HINTS).optional(),reportedHttpStatus:z.number().int().min(400).max(599).optional(),
  messageAvailable:z.boolean().optional(),providerMessageChars:counter.optional(),inspectedMessageChars:counter.optional(),providerMessageTruncated:z.boolean().optional(),
  providerErrorCode:z.enum(PROVIDER_CODES).optional(),providerErrorType:z.enum(PROVIDER_CODES).optional(),
  rejectedParameter:z.enum(REJECTED_PARAMETERS).optional(),rejectedToolIndex:counter.max(999999).optional(),rejectionHints:z.array(z.enum(REJECTION_HINTS)).max(REJECTION_HINTS.length).optional(),
  requestBytes:counter.optional(),inputMessages:counter.optional(),inputTextChars:counter.optional(),systemChars:counter.optional(),toolCount:counter.optional(),historyToolCount:counter.optional(),toolSchemaBytes:counter.optional(),
  chunkCount:counter.optional(),blockCount:counter.optional(),replyBytes:counter.optional(),requestCount:counter.optional(),peakActive:counter.optional(),queuedRequests:counter.max(100).optional(),peakQueued:counter.max(16).optional(),peakQueuedBytes:counter.max(64*1024*1024).optional(),maxQueueWaitMs:counter.max(86400000).optional(),
  stream:z.boolean().optional(),schemaFormat:z.boolean().optional(),requestedMaxTokens:z.boolean().optional(),requestedTemperature:z.boolean().optional(),hasReasoningEffort:z.boolean().optional(),
  maxTokens:counter.optional(),temperature:z.number().min(0).max(100).optional(),contextWindow:counter.optional()}).strict();
const record=z.object({id:z.string().uuid(),workspaceId:z.string(),operation:z.enum(['scan','validate']),parentId:z.string().optional(),provider:identity.optional(),model:identity,reasoningEffort:identity.optional(),contextWindow:z.number().int().positive().optional(),mode:z.enum(['standard','deep']),minutes:z.number(),state:z.string(),status:z.enum(['running','completed','failed','cancelled','interrupted']),createdAt:z.string(),finishedAt:z.string().optional(),error:z.string().optional(),events:z.array(z.string()),diagnostics:z.array(diagnostic).max(DIAGNOSTIC_LIMIT).optional(),diagnosticsDropped:counter.optional(),privateErrorCapture:z.enum(['armed','saved','failed','unavailable','empty']).optional(),result:z.unknown().optional()}).strict();
const leaseRecord=z.object({id:z.string().uuid(),name:z.string(),image:z.string(),state:z.string(),phase:z.enum(['creating','created']),createdAt:z.string()}).strict();
const spec=defineDomain({name:'security_scans',version:1,tables:{scans:domainTable(record),leases:domainTable(leaseRecord)}});
const request=z.object({operation:z.enum(['workspaces','status','list','get','start','cancel','validate','export','clear_failed']),ids:z.array(z.string().uuid()).min(1).max(100).optional(),workspaceId:z.string().optional(),id:z.string().uuid().optional(),provider:identity.optional(),model:identity.optional(),reasoningEffort:identity.optional(),mode:z.enum(['standard','deep']).optional(),minutes:z.number().int().min(1).max(120).optional(),format:z.enum(['json','csv','sarif']).optional(),findingIndex:z.number().int().min(0).optional(),userRequested:z.boolean().optional(),capturePrivateError:z.boolean().optional()}).strict();
export async function apply(ctx){
  const domain=await ctx.storageDomain.open(spec),table=domain.table('scans'),leases=domain.table('leases');
  const panelToken=newPanelToken();
  const running=new Map(),exportsPending=new Set();let closing=false,recoveryTimer,recoveryTask;
  ctx.effect(()=>async()=>{closing=true;clearInterval(recoveryTimer);const tasks=[...running.values(),...exportsPending];for(const task of tasks)task.controller.abort();await Promise.allSettled([...tasks.map(t=>t.done),recoveryTask]);await domain.close();},'security scan shutdown');
  const image=(JSON.parse(await readFile(new URL('./image-0fc22475e7860865.json',import.meta.url),'utf8'))).image;
  const root=path.join(os.homedir(),'.dsh','security-scans');
  const docker=await ctx.subprocess.resolveExecutable(process.env.DSH_SECURITY_DOCKER??'docker');
  const lease={acquire:row=>leases.put(row.id,row),created:async id=>{const row=leases.get(id);await leases.put(id,{...row,phase:'created'});},release:id=>leases.delete(id)};
  async function recover(){for(const [id,row]of leases.entries()){
    if([...running.values()].some(t=>t.record?.id===id)||[...exportsPending].some(t=>t.id===id))continue;
    if(await reconcileContainerLease({subprocess:ctx.subprocess,docker,lease:row}))await leases.delete(id);
  }}
  await recover();
  for(const [id,row]of table.entries())if(row.status==='running')await table.put(id,{...row,status:'interrupted',finishedAt:new Date().toISOString(),error:'Runtime stopped; scans are not resumed automatically'});
  recoveryTimer=setInterval(()=>{if(closing||recoveryTask)return;recoveryTask=recover().catch(error=>ctx.logger?.error?.('Security orphan reconciliation failed; cleanup will retry')).finally(()=>{recoveryTask=undefined;});},30000);recoveryTimer.unref?.();
  async function start(workspace,args,operation='scan'){
    if(args.userRequested!==true)throw Error('Explicit user authorization to send workspace source to the selected Harness provider is required');
    if(closing||running.has(workspace.id))throw Error('A scan is already active for this workspace, or the plugin is stopping');
    const controller=new AbortController();let settle;const task={controller,done:new Promise(resolve=>{settle=resolve;})};running.set(workspace.id,task);
    const deadline=setTimeout(()=>controller.abort(Error(OPERATION_DEADLINE_MESSAGE)),(args.minutes??30)*60000);
    try {
      const parent=operation==='validate'?ownedScan(table,workspace.id,args.id):undefined;
      const finding=parent?.result?.findings?.findings?.[args.findingIndex];
      if(operation==='validate'&&(!finding||parent.status!=='completed'||parent.operation!=='scan'))throw Error('Select an existing finding from a completed scan');
      const selection=await resolveSelection(ctx.llm,{provider:args.provider,model:args.model,...(args.reasoningEffort!==undefined?{reasoningEffort:args.reasoningEffort}:{})},AbortSignal.any([controller.signal,AbortSignal.timeout(15000)]),ctx.sessionController);
      const paths=await privateState(root,workspace.path);
      const id=newId(),state=path.join(paths.root,id);await mkdir(state,{mode:0o700});
      controller.signal.throwIfAborted();if(closing)throw Error('Plugin is stopping');
      const job=record.parse({id,workspaceId:workspace.id,operation,...(parent?{parentId:parent.id}:{}),...selection,mode:args.mode??'standard',minutes:args.minutes??30,state,status:'running',createdAt:new Date().toISOString(),events:[],diagnostics:[],diagnosticsDropped:0,...(args.capturePrivateError===true?{privateErrorCapture:'armed'}:{})});
      await table.put(id,job);task.record=job;
      let privateCapture,protocolFailure;
      const onPrivateError=args.capturePrivateError===true?snapshot=>{
        if(privateCapture||job.privateErrorCapture!=='armed')return;
        if(!snapshot.message&&!snapshot.nestedMessage){job.privateErrorCapture='unavailable';return;}
        // First rejection only. Sibling of the mounted state, outside Git and
        // inaccessible to the scanner. Never retain this text in the scan table.
        privateCapture=writeFile(path.join(paths.root,id+'.provider-error.json'),JSON.stringify({...snapshot,scanId:id},null,2),{mode:0o600,flag:'wx'})
          .then(()=>{job.privateErrorCapture='saved';},()=>{job.privateErrorCapture='failed';});
        return privateCapture;
      }:undefined;
      const execution=(async()=>{
        try {
          const onDiagnostic=value=>{const parsed=diagnostic.safeParse(value);if(!parsed.success)return;
            const entry=parsed.data;if(entry.kind==='gateway'&&entry.outcome==='failed'&&entry.protocolInvariant)protocolFailure=entry;if(!retainDiagnostic(job,entry))return;
            // Diagnostics never fail or change inference. Logger failures are isolated.
            try{const level=entry.outcome==='failed'?'warn':'info';ctx.logger?.[level]?.('Security diagnostic: %s',JSON.stringify({scanId:job.id,...entry}));}catch{}
          };
          const gateway=createHarnessGateway({llm:ctx.llm,sessionId:job.id,selection:{provider:job.provider,model:job.model,contextWindow:job.contextWindow,...(job.reasoningEffort!==undefined?{reasoningEffort:job.reasoningEffort}:{})},onDiagnostic,onPrivateError});
          const result=await runEngine({subprocess:ctx.subprocess,docker,image,repo:paths.repo,state,job:{...job,...(finding?{finding}: {})},signal:controller.signal,gateway,lease,onDiagnostic,
            onEvent:event=>{job.events.push(JSON.stringify(event).slice(0,2000));job.events=job.events.slice(-50);}});
          job.result=result;job.status='completed';
        }catch(error){job.status=controller.signal.aborted?'cancelled':'failed';job.error=protocolFailure&&error.message==='Harness model request failed; no fallback attempted'?`Harness protocol translation failed (${protocolFailure.protocolInvariant}, stage ${protocolFailure.stage}); no fallback attempted`:String(error.message).slice(0,4000);}
        finally{await privateCapture;if(job.privateErrorCapture==='armed')job.privateErrorCapture='empty';clearTimeout(deadline);job.finishedAt=new Date().toISOString();await table.put(id,job);}
      })();
      void execution.catch(error=>ctx.logger?.error?.('Security scan persistence failed')).finally(()=>{running.delete(workspace.id);settle();});
      return scanSummary(job);
    }catch(error){clearTimeout(deadline);running.delete(workspace.id);settle();throw error;}
  }
  async function invoke(raw,workspace,fromUI=false){
    const a=request.parse(raw);if(['start','validate','clear_failed'].includes(a.operation)&&!fromUI)throw Error('This action requires the authenticated Security panel; agents cannot authorize inference or clear history');if(a.operation==='workspaces')return ctx.workspaceRegistry.list().map(w=>({id:w.id,title:w.title,path:w.path}));if(!workspace)throw Error('Registered workspace required');
    switch(a.operation){
      case 'status':{
        const catalog=await modelCatalog(ctx.sessionController);
        return {runtimeRevision:import.meta.url.match(/runtime-([a-f0-9]+)\.mjs/)?.[1]??'source',engine:'@openai/codex-security@0.2.0',image,...catalog,active:running.has(workspace.id),routing:'harness-llm',authentication:'configured-provider',network:'none',reportOnly:true};
      }
      case 'list':return [...table.entries()].map(([,r])=>r).filter(r=>r.workspaceId===workspace.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,100).map(scanSummary);
      case 'get':{const row=ownedScan(table,workspace.id,a.id);const live=running.get(workspace.id)?.record;return live?.id===row.id?{...live}:row;}
      case 'clear_failed':{
        if(a.userRequested!==true||!a.ids?.length)throw Error('Confirm the failed scans to remove');
        const ids=[...new Set(a.ids)];
        // Validate the entire snapshot before deleting anything. New failures are
        // not implicitly included, and private engine files are never touched.
        for(const id of ids){const row=ownedScan(table,workspace.id,id);
          if(row.status!=='failed')throw Error('Only failed scans can be removed');
          if(running.get(workspace.id)?.record?.id===id||leases.get(id))throw Error('Scan cleanup is still pending; try again after cleanup');
        }
        const removed=[];for(const id of ids)if(await table.delete(id))removed.push(id);
        return {removed};
      }
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
      const requiresPanelToken=['start','validate','clear_failed'].includes(args.operation);if(requiresPanelToken&&!panelTokenAllowed(req,panelToken)){res.statusCode=403;res.end(JSON.stringify({error:'Security panel authorization is missing or expired. Refresh the page and try again.'}));return;}
      const value=await invoke(args,workspace,true);
      const result=args.operation==='status'?{...value,panelAuthorizationVerified:panelTokenAllowed(req,panelToken)}:value;
      res.end(JSON.stringify({result,...(['workspaces','status'].includes(args.operation)?{panelToken}:{})}));
    }catch(error){res.statusCode=400;res.end(JSON.stringify({error:error.message}));}
  }}),'security API');
}
