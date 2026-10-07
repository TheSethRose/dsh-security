import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('../client.js',import.meta.url),'utf8');
const workspaces=[{id:'workspace-a',title:'A',path:'/a'},{id:'workspace-b',title:'B',path:'/b'}];
const status={models:[{provider:'deepseek',id:'deepseek-v4-pro',name:'DeepSeek Pro',providerName:'DeepSeek'},{provider:'other',id:'custom-model',name:'Custom model',providerName:'Other adapter'}],defaultSelection:{provider:'deepseek',model:'deepseek-v4-pro'},authentication:'configured-provider',routing:'harness-llm',active:false,panelAuthorizationVerified:true};
const selectionValue=(provider,model)=>JSON.stringify({provider,model});
const completed={id:'scan-a',workspaceId:'workspace-a',operation:'scan',model:'deepseek-v4-pro',status:'completed',createdAt:'2026-10-06T00:00:00Z',findings:1,result:{findings:{findings:[{findingId:'finding-a',severity:'high',title:'Unsafe SQL',summary:'<script>not markup</script>',evidence:{file:'example.py',line:7}}]},report:'Validation evidence',threatModel:{summary:'Threat model fixture'},coverage:{files:1}},events:['scan done']};
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};}
// Stateful hooks, effect dependency changes/cleanup, manual timers and real Blob;
// no network, DOM innerHTML, paid inference or plugin activation are involved.
function mount({route,catalog=status,history=[],panelToken='test-only-panel-token'}={}){
 const components=new Map(),requests=[],state=[],hooks=[],effectSlots=[],intervals=new Map(),timeouts=new Map(),downloads=[],blobs=[],revoked=[],disposers=[];
 let cursor=0,pending=true,tree=null,unmounted=false,nextTimer=1,afterUnmount=0;
 const React={createElement:(type,props,...children)=>({type,props:{...props,children}}),useState(initial){const index=cursor++;if(!(index in state))state[index]=typeof initial==='function'?initial():initial;return[state[index],value=>{if(unmounted){afterUnmount++;return;}state[index]=typeof value==='function'?value(state[index]):value;pending=true;}];},useRef(initial){const index=cursor++;return hooks[index]??={current:initial};},useEffect(fn,deps){const index=cursor++,old=effectSlots[index];if(!old||deps.some((value,i)=>!Object.is(value,old.deps[i])))effectSlots[index]={fn,deps:[...deps],cleanup:old?.cleanup,run:true};}};
 const fetch=async(url,options)=>{const args=JSON.parse(options.body);requests.push({url,options,args});const custom=route?.(args);const result=custom!==undefined?await custom:args.operation==='workspaces'?workspaces:args.operation==='status'?catalog:args.operation==='list'?history:args.operation==='get'?completed:args.operation==='start'?{id:'scan-new'}:args.operation==='validate'?{id:'validation-new'}:args.operation==='export'?{export:'export fixture'}:completed;return{ok:true,json:async()=>({result,...(['workspaces','status'].includes(args.operation)?{panelToken}:{})})};};
 let plugin;const window={__ModuleLoader__:{load(entry){assert.equal(entry.id,'dsh-security');plugin=entry.factory(name=>{assert.equal(name,'react');return React;});}}};
 const document={head:{appendChild(){}},createElement(type){return type==='a'?{click(){downloads.push({href:this.href,download:this.download});}}:{remove(){}};}};
 class BlobCapture extends Blob{constructor(parts,options){super(parts,options);blobs.push(this);}}
 vm.runInNewContext(source,{window,document,fetch,Blob:BlobCapture,URL:{createObjectURL:()=>`blob:fixture-${blobs.length}`,revokeObjectURL:url=>revoked.push(url)},setInterval(fn,ms){const id=nextTimer++;intervals.set(id,{fn,ms});return id;},clearInterval:id=>intervals.delete(id),setTimeout(fn,ms){const id=nextTimer++;timeouts.set(id,{fn,ms});return id;},console});
 plugin.apply({get:key=>{assert.equal(key,'slots');return{inject(_name,callback){callback();},register(spec,component){components.set(spec.name+':'+(spec.id??spec.key),component);}};},effect(callback){disposers.push(callback());}});
 const Panel=components.get('main:dsh-security');assert.ok(Panel);assert.ok(components.has('sidebar.panellist:dsh-security'));
 function draw(){let count=0;while(pending&&!unmounted){assert.ok(++count<30,'effect/setState loop');pending=false;cursor=0;tree=Panel();for(const effect of effectSlots.filter(Boolean)){if(effect.run){effect.run=false;effect.cleanup?.();effect.cleanup=effect.fn();}}}}
 function nodes(value,out=[]){if(value==null||typeof value==='boolean')return out;if(Array.isArray(value)){value.forEach(v=>nodes(v,out));return out;}if(typeof value!=='object'){out.push(value);return out;}if(typeof value.type==='function')return nodes(value.type(value.props),out);out.push(value);return nodes(value.props.children,out);}
 const text=value=>nodes(value).filter(v=>typeof v==='string'||typeof v==='number').join('');
 const find=predicate=>nodes(tree).find(predicate),button=label=>find(n=>n.type==='button'&&text(n)===label),input=type=>find(n=>n.type==='input'&&n.props.type===type);
 const click=node=>{assert.ok(node,'button exists');assert.equal(node.props.disabled,false,'button must be enabled');node.props.onClick();draw();};
 const change=(node,value)=>{assert.ok(node,'input exists');node.props.onChange({target:{value,checked:value}});draw();};
 async function flush(){for(let i=0;i<5;i++){await new Promise(resolve=>setImmediate(resolve));draw();}}
 function unmount(){unmounted=true;for(const effect of effectSlots.filter(Boolean))effect.cleanup?.();for(const cleanup of disposers)cleanup?.();}
 draw();return{requests,find,text:()=>text(tree),button,input,click,change,flush,unmount,intervals,timeouts,downloads,blobs,revoked,get afterUnmount(){return afterUnmount;},get tree(){return tree;},tick(){for(const timer of [...intervals.values()])timer.fn();},runTimeouts(){for(const [id,timer]of [...timeouts]){timeouts.delete(id);timer.fn();}}};
}
const historyButton=p=>p.find(n=>n.type==='button'&&n.props.children[0]?.includes?.('2026-10-06'));
const workspaceSelect=p=>p.find(n=>n.type==='select');
const privateCheckbox=p=>p.find(n=>n.type==='input'&&n.props['aria-label']==='Capture private provider error');
test('private capture defaults off, never authorizes inference, and is consumed per scan',async()=>{
 const p=mount();await p.flush();assert.equal(privateCheckbox(p).props.checked,false);p.change(privateCheckbox(p),true);assert.equal(p.button('Start scan').props.disabled,true);assert.ok(!p.requests.some(r=>r.args.operation==='start'));p.change(p.input('checkbox'),true);p.click(p.button('Start scan'));assert.equal(privateCheckbox(p).props.checked,false);await p.flush();const request=p.requests.find(r=>r.args.operation==='start');assert.equal(request.args.capturePrivateError,true);assert.equal(request.options.headers['X-DSH-Security-CSRF'],'test-only-panel-token');p.unmount();
});
test('workspace and model changes clear private capture authorization',async()=>{
 const p=mount();await p.flush();p.change(privateCheckbox(p),true);p.change(workspaceSelect(p),'workspace-b');assert.equal(privateCheckbox(p).props.checked,false);await p.flush();p.change(privateCheckbox(p),true);const model=p.find(n=>n.type==='select'&&n.props.value===selectionValue('deepseek','deepseek-v4-pro'));p.change(model,selectionValue('other','custom-model'));assert.equal(privateCheckbox(p).props.checked,false);p.unmount();
});
test('private capture path is visible but raw errors never enter diagnostics downloads',async()=>{
 const row={...completed,status:'failed',state:'/private/security-scans/scan-a',privateErrorCapture:'saved',diagnostics:[{kind:'gateway',outcome:'failed',code:'INVALID_REQUEST'}]},p=mount({history:[row],route:a=>a.operation==='get'?row:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.match(p.text(),/Exact provider error saved locally/);assert.match(p.text(),/\/private\/security-scans\/scan-a\.provider-error\.json/);p.click(p.button('Download diagnostics'));const download=JSON.parse(await p.blobs[0].text());assert.equal(download.privateErrorCapture,undefined);assert.ok(!JSON.stringify(download).includes('provider-error.json'));assert.ok(!p.requests.some(r=>r.args.operation==='private_error'));p.unmount();
});
test('registered workspace fetch is authenticated local API; consent defaults unchecked; existing configured adapter is recognized',async()=>{
 const p=mount();await p.flush();assert.deepEqual(p.requests[0].args,{operation:'workspaces'});assert.equal(p.requests[0].url,'/dsh-security/api');assert.equal(p.requests[0].options.method,'POST');assert.equal(p.requests[0].options.mode,'same-origin');assert.equal(p.requests[0].options.credentials,'same-origin');assert.equal(p.requests[0].options.headers['X-DSH-Security'],'1');assert.equal(p.input('checkbox').props.checked,false);assert.equal(p.button('Start scan').props.disabled,true);assert.doesNotMatch(p.text(),/DEEPSEEK_API_KEY|api\.deepseek\.com|DeepSeek-only/);assert.match(p.text(),/Harness provider/);assert.ok(p.requests.some(r=>r.args.operation==='status'&&r.args.workspaceId==='workspace-a'));assert.ok(!p.requests.some(r=>r.args.operation==='start'));p.unmount();
});
test('missing panel token never dispatches Start even with checked consent',async()=>{const p=mount({panelToken:null,catalog:{...status,panelAuthorizationVerified:false}});await p.flush();p.change(p.input('checkbox'),true);assert.equal(p.button('Start scan').props.disabled,true);assert.equal(p.requests.some(r=>r.args.operation==='start'),false);p.unmount();});
test('paid API fails closed when an unverified client claims readiness without a bootstrap token',async()=>{const p=mount({panelToken:null});await p.flush();p.change(p.input('checkbox'),true);p.click(p.button('Start scan'));await p.flush();assert.equal(p.requests.some(r=>r.args.operation==='start'),false);assert.match(p.text(),/Security authorization is not ready/);assert.equal(p.input('checkbox').props.checked,false);p.unmount();});
test('status preflight sends the UI bootstrap token without starting inference',async()=>{const p=mount();await p.flush();const request=p.requests.find(r=>r.args.operation==='status');assert.equal(request.options.headers['X-DSH-Security-CSRF'],'test-only-panel-token');assert.equal(p.requests.some(r=>['start','validate'].includes(r.args.operation)),false);p.unmount();});
test('unavailable catalog disables Start without a separate credential prompt',async()=>{const p=mount({catalog:{...status,models:[]}});await p.flush();p.change(p.input('checkbox'),true);assert.equal(p.button('Start scan').props.disabled,true);assert.doesNotMatch(p.text(),/DEEPSEEK_API_KEY/);p.unmount();});
test('start requires checked consent and consumes authorization exactly once',async()=>{
 const p=mount({route:a=>a.operation==='get'?{...completed,id:'scan-new',status:'running'}:undefined});await p.flush();p.change(p.input('checkbox'),true);p.click(p.button('Start scan'));assert.equal(p.input('checkbox').props.checked,false);await p.flush();const starts=p.requests.filter(r=>r.args.operation==='start');assert.equal(starts.length,1);assert.equal(starts[0].options.headers['X-DSH-Security-CSRF'],'test-only-panel-token');assert.deepEqual(starts[0].args,{workspaceId:'workspace-a',operation:'start',provider:'deepseek',model:'deepseek-v4-pro',mode:'standard',minutes:30,requestLimit:100,userRequested:true});assert.match(p.text(),/scan · running/);assert.ok(p.button('Cancel scan'));p.unmount();
});
const budgetInput=p=>p.find(n=>n.type==='input'&&n.props['aria-label']==='Model-request ceiling');
test('request ceiling defaults to 100, changes clear consent, and 500 is sent once',async()=>{
 const p=mount();await p.flush();assert.equal(budgetInput(p).props.value,100);assert.equal(budgetInput(p).props.max,500);p.change(p.input('checkbox'),true);p.change(privateCheckbox(p),true);p.change(budgetInput(p),500);assert.equal(p.input('checkbox').props.checked,false);assert.equal(privateCheckbox(p).props.checked,false);assert.equal(p.button('Start scan').props.disabled,true);p.change(p.input('checkbox'),true);p.click(p.button('Start scan'));await p.flush();const starts=p.requests.filter(r=>r.args.operation==='start');assert.equal(starts.length,1);assert.equal(starts[0].args.requestLimit,500);assert.equal(starts[0].args.capturePrivateError,undefined);p.unmount();
});
test('invalid request ceilings disable paid Start and Validate',async()=>{
 const p=mount({history:[completed]});await p.flush();p.click(historyButton(p));await p.flush();for(const limit of [0,-1,501,1.5,NaN]){p.change(budgetInput(p),limit);p.change(p.input('checkbox'),true);assert.equal(p.button('Start scan').props.disabled,true);assert.equal(p.button('Validate finding').props.disabled,true);}assert.equal(p.requests.some(r=>['start','validate'].includes(r.args.operation)),false);p.unmount();
});
test('validation sends the newly authorized request ceiling and detail displays actual budget',async()=>{
 const row={...completed,requestLimit:500,gatewayOutcomes:{completed:450,failed:0,cancelled:0},diagnostics:[{kind:'engine',outcome:'completed'}]},p=mount({history:[row],route:a=>a.operation==='get'?row:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.match(p.text(),/Request ceiling: 500/);assert.match(p.text(),/450 completed/);p.click(p.button('Download diagnostics'));const snapshot=JSON.parse(await p.blobs.at(-1).text());assert.equal(snapshot.requestLimit,500);assert.deepEqual(snapshot.gatewayOutcomes,{completed:450,failed:0,cancelled:0});p.change(budgetInput(p),200);p.change(p.input('checkbox'),true);p.click(p.button('Validate finding'));await p.flush();assert.equal(p.requests.find(r=>r.args.operation==='validate').args.requestLimit,200);p.unmount();
});
test('changing workspace resets consent and discards late old-scope status/history responses',async()=>{
 const oldStatus=deferred(),oldList=deferred(),p=mount({route:a=>a.workspaceId==='workspace-a'&&a.operation==='status'?oldStatus.promise:a.workspaceId==='workspace-a'&&a.operation==='list'?oldList.promise:undefined});await p.flush();p.change(p.input('checkbox'),true);p.change(workspaceSelect(p),'workspace-b');await p.flush();assert.equal(p.input('checkbox').props.checked,false);oldStatus.resolve({...status,active:true});oldList.resolve([{...completed,id:'old-scope-secret'}]);await p.flush();assert.doesNotMatch(p.text(),/old-scope-secret/);assert.equal(p.button('Start scan').props.disabled,true);p.unmount();
});
test('late get from an old workspace never shows its finding',async()=>{
 const get=deferred(),p=mount({history:[completed],route:a=>a.operation==='get'?get.promise:undefined});await p.flush();p.click(historyButton(p));p.change(workspaceSelect(p),'workspace-b');await p.flush();get.resolve({...completed,result:{report:'PRIVATE-OLD-WORKSPACE'}});await p.flush();assert.doesNotMatch(p.text(),/PRIVATE-OLD-WORKSPACE/);p.unmount();
});
test('finding evidence renders as text; validation needs fresh consent and an existing finding index',async()=>{
 const p=mount({history:[completed],route:a=>a.operation==='get'&&a.id==='validation-new'?{...completed,id:'validation-new',operation:'validate',result:{report:'Validated fixture'}}:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.match(p.text(),/Unsafe SQL/);assert.match(p.text(),/<script>not markup<\/script>/);assert.ok(!p.find(n=>n.type==='script'));assert.equal(p.button('Validate finding').props.disabled,true);p.change(p.input('checkbox'),true);p.click(p.button('Validate finding'));await p.flush();assert.deepEqual(p.requests.find(r=>r.args.operation==='validate').args,{workspaceId:'workspace-a',operation:'validate',id:'scan-a',findingIndex:0,userRequested:true,minutes:30,requestLimit:100,provider:'deepseek',model:'deepseek-v4-pro'});assert.equal(p.input('checkbox').props.checked,false);assert.match(p.text(),/Validated fixture/);p.unmount();
});
test('JSON/CSV/SARIF exports download exact text Blob and revoke object URLs',async()=>{
 const exports={json:'{"findings":[]}',csv:'title,severity\nfixture,high\n',sarif:'{"version":"2.1.0"}'};const p=mount({history:[completed],route:a=>a.operation==='export'?{export:exports[a.format]}:undefined});await p.flush();p.click(historyButton(p));await p.flush();for(const format of Object.keys(exports)){p.click(p.button('Export '+format.toUpperCase()));await p.flush();assert.equal(await p.blobs.at(-1).text(),exports[format]);assert.equal(p.downloads.at(-1).download,`security-scan-a.${format}`);}p.runTimeouts();assert.equal(p.revoked.length,3);assert.equal(p.requests.filter(r=>r.args.operation==='export').length,3);p.unmount();
});
test('status and running-scan polling dispose on unmount and ignore pending replies',async()=>{
 const delayed=deferred();let poll=false;const p=mount({history:[completed],route:a=>a.operation==='get'?poll?delayed.promise:{...completed,status:'running'}:undefined});await p.flush();assert.equal(p.intervals.size,1);p.click(historyButton(p));await p.flush();assert.equal(p.intervals.size,2);poll=true;p.tick();p.unmount();assert.equal(p.intervals.size,0);delayed.resolve(completed);await p.flush();assert.equal(p.afterUnmount,0);
});
test('switching away and back invalidates a delayed action from the previous visit',async()=>{
 const delayed=deferred(),p=mount({history:[completed],route:a=>a.operation==='get'?delayed.promise:undefined});await p.flush();p.click(historyButton(p));p.change(workspaceSelect(p),'workspace-b');await p.flush();p.change(workspaceSelect(p),'workspace-a');await p.flush();delayed.resolve({...completed,result:{report:'STALE-PRIOR-VISIT'}});await p.flush();assert.doesNotMatch(p.text(),/STALE-PRIOR-VISIT/);p.unmount();
});
test('pending manual action cannot update state or download after panel disposal',async()=>{
 const delayed=deferred(),p=mount({history:[completed],route:a=>a.operation==='get'?delayed.promise:undefined});await p.flush();p.click(historyButton(p));p.unmount();delayed.resolve(completed);await p.flush();assert.equal(p.afterUnmount,0);assert.equal(p.downloads.length,0);
});
test('pending export cannot create Blob/download after panel disposal',async()=>{
 const delayed=deferred(),p=mount({history:[completed],route:a=>a.operation==='export'?delayed.promise:undefined});await p.flush();p.click(historyButton(p));await p.flush();p.click(p.button('Export JSON'));p.unmount();delayed.resolve({export:'NEVER-DOWNLOAD'});await p.flush();assert.equal(p.afterUnmount,0);assert.equal(p.downloads.length,0);assert.equal(p.blobs.length,0);
});
test('cancel is an explicit read-only control and does not consume billable consent',async()=>{
 const p=mount({history:[completed],route:a=>a.operation==='get'?{...completed,status:'running'}:undefined});await p.flush();p.click(historyButton(p));await p.flush();p.click(p.button('Cancel scan'));await p.flush();assert.deepEqual(p.requests.find(r=>r.args.operation==='cancel').args,{workspaceId:'workspace-a',operation:'cancel',id:'scan-a'});assert.equal(p.requests.filter(r=>['start','validate'].includes(r.args.operation)).length,0);p.unmount();
});
test('active scan disables paid start and validation even with consent',async()=>{
 const p=mount({history:[completed],route:a=>a.operation==='status'?{...status,active:true}:undefined});await p.flush();p.click(historyButton(p));await p.flush();p.change(p.input('checkbox'),true);assert.equal(p.button('Scan running').props.disabled,true);assert.equal(p.button('Validate finding').props.disabled,true);assert.equal(p.requests.filter(r=>['start','validate'].includes(r.args.operation)).length,0);p.unmount();
});
test('slow status/history updates do not overlap successive poll ticks',async()=>{
 const statusReply=deferred(),rows=deferred(),p=mount({route:a=>a.operation==='status'?statusReply.promise:a.operation==='list'?rows.promise:undefined});await p.flush();p.tick();p.tick();await p.flush();assert.equal(p.requests.filter(r=>r.args.operation==='status').length,1);assert.equal(p.requests.filter(r=>r.args.operation==='list').length,1);statusReply.resolve(status);rows.resolve([]);await p.flush();p.tick();await p.flush();assert.equal(p.requests.filter(r=>r.args.operation==='status').length,2);p.unmount();
});
test('completion stops selected-scan polling but retains workspace status polling',async()=>{
 let done=false;const p=mount({history:[completed],route:a=>a.operation==='get'?{...completed,status:done?'completed':'running'}:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.equal(p.intervals.size,2);done=true;p.tick();await p.flush();assert.equal(p.intervals.size,1);assert.match(p.text(),/scan · completed/);p.unmount();
});
test('invalid deadlines block start and the selected model/mode/deadline go to the Host',async()=>{
 const p=mount();await p.flush();p.change(p.input('checkbox'),true);for(const value of [0,121,1.5]){p.change(p.input('number'),value);assert.equal(p.button('Start scan').props.disabled,true);}p.change(p.input('number'),5);p.change(p.find(n=>n.type==='select'&&n.props.value===selectionValue('deepseek','deepseek-v4-pro')),selectionValue('other','custom-model'));p.change(p.find(n=>n.type==='select'&&n.props.value==='standard'),'deep');assert.equal(p.input('checkbox').props.checked,false);p.change(p.input('checkbox'),true);p.click(p.button('Start scan'));await p.flush();const args=p.requests.find(r=>r.args.operation==='start').args;assert.equal(args.provider,'other');assert.equal(args.model,'custom-model');assert.equal(args.mode,'deep');assert.equal(args.minutes,5);p.unmount();
});
test('workspace enumeration response arriving after unmount cannot set any state',async()=>{
 const list=deferred(),p=mount({route:a=>a.operation==='workspaces'?list.promise:undefined});assert.equal(p.button('Start scan').props.disabled,true);p.unmount();list.resolve(workspaces);await p.flush();assert.equal(p.afterUnmount,0);assert.equal(p.requests.length,1);
});
test('a late action from another workspace cannot release the new workspace busy state',async()=>{
 const old=deferred(),fresh=deferred();let calls=0;const p=mount({history:[completed],route:a=>a.operation==='get'?(++calls===1?old.promise:fresh.promise):undefined});await p.flush();p.click(historyButton(p));p.change(workspaceSelect(p),'workspace-b');await p.flush();p.click(historyButton(p));old.resolve(completed);await p.flush();assert.equal(historyButton(p).props.disabled,true);fresh.resolve({...completed,workspaceId:'workspace-b'});await p.flush();assert.equal(historyButton(p).props.disabled,false);p.unmount();
});

const modelSelect=p=>p.find(n=>n.type==='select'&&n.props.children.some(child=>child?.type==='option'&&child.props.value===selectionValue('other','custom-model')));
test('default tuple must exist in catalog; no absent default silently selects the first model',async()=>{
 for(const catalog of [{...status,defaultSelection:undefined},{...status,defaultSelection:{provider:'unknown',model:'deepseek-v4-pro'}},{...status,defaultSelection:{provider:'deepseek',model:'absent'}},{...status,models:undefined}]){
  const p=mount({catalog});await p.flush();p.change(p.input('checkbox'),true);assert.equal(p.button('Start scan').props.disabled,true);if(catalog.models)assert.equal(modelSelect(p).props.value,'');assert.equal(p.requests.filter(r=>r.args.operation==='start').length,0);p.unmount();
 }
});
test('model options encode provider/model tuples from status and non-DeepSeek validation preserves selection',async()=>{
 const p=mount({history:[completed]});await p.flush();const select=modelSelect(p);assert.ok(select);assert.equal(select.props.value,selectionValue('deepseek','deepseek-v4-pro'));assert.match(p.text(),/Other adapter/);p.change(select,selectionValue('other','custom-model'));p.click(historyButton(p));await p.flush();p.change(p.input('checkbox'),true);p.click(p.button('Validate finding'));await p.flush();const args=p.requests.find(r=>r.args.operation==='validate').args;assert.equal(args.provider,'other');assert.equal(args.model,'custom-model');assert.equal(Object.hasOwn(args,'reasoningEffort'),false);p.unmount();
});
test('default reasoning effort applies only to matching tuple on start and validation',async()=>{
 for(const operation of ['start','validate'])for(const switched of [false,true]){
  const p=mount({history:[completed],catalog:{...status,defaultSelection:{...status.defaultSelection,reasoningEffort:'high'}}});await p.flush();if(switched)p.change(modelSelect(p),selectionValue('other','custom-model'));if(operation==='validate'){p.click(historyButton(p));await p.flush();}p.change(p.input('checkbox'),true);p.click(p.button(operation==='start'?'Start scan':'Validate finding'));await p.flush();const args=p.requests.find(r=>r.args.operation===operation).args;assert.equal(args.reasoningEffort,switched?undefined:'high');assert.equal(args.provider,switched?'other':'deepseek');p.unmount();
 }
});
test('invalid or removed tuple disables Start instead of falling back',async()=>{
 const p=mount();await p.flush();p.change(modelSelect(p),selectionValue('unknown','custom-model'));p.change(p.input('checkbox'),true);assert.equal(p.button('Start scan').props.disabled,true);assert.equal(p.requests.filter(r=>r.args.operation==='start').length,0);p.unmount();
});

const failedScan={...completed,id:'failed-a',status:'failed',findings:0,result:undefined,error:'INVALID_REQUEST',diagnostics:[{kind:'gateway',at:'2026-10-06T00:00:00Z',requestId:'local-request',stage:'iterate',outcome:'failed',code:'INVALID_REQUEST',reason:'ambiguous_request_rejection',requestBytes:2048}]};
test('bulk and row removal are visible, explicitly confirmed, snapshot-scoped and clear stale detail',async()=>{
 let rows=[failedScan,completed];const p=mount({route:a=>a.operation==='list'?rows:a.operation==='get'?failedScan:a.operation==='clear_failed'?(rows=rows.filter(row=>!a.ids.includes(row.id)),{removed:a.ids}):undefined});await p.flush();
 assert.ok(p.button('Remove'));p.click(historyButton(p));await p.flush();assert.ok(p.button('Remove failed scan'));
 p.click(p.button('Clear failed scans (1)'));assert.ok(p.button('Keep scans'));assert.match(p.text(),/Private engine files on disk are retained/);assert.equal(p.requests.some(r=>r.args.operation==='clear_failed'),false);p.click(p.button('Keep scans'));assert.equal(p.button('Remove failed scans'),undefined);
 p.click(p.button('Remove failed scan'));rows=[...rows,{...failedScan,id:'new-failure'}];p.click(p.button('Remove failed scans'));await p.flush();
 const req=p.requests.find(r=>r.args.operation==='clear_failed');assert.deepEqual(req.args,{operation:'clear_failed',workspaceId:'workspace-a',ids:['failed-a'],userRequested:true});assert.equal(req.options.headers['X-DSH-Security-CSRF'],'test-only-panel-token');assert.match(p.text(),/Removed 1 failed scan from history/);assert.ok(p.text().includes('new-failure')===false);assert.equal(p.button('Download diagnostics'),undefined,'deleted selected detail cleared');assert.ok(p.button('Clear failed scans (1)'),'new failure retained');assert.ok(p.text().includes('completed'));
 p.click(p.button('Remove'));assert.ok(p.button('Remove failed scans'));p.change(workspaceSelect(p),'workspace-b');assert.equal(p.button('Remove failed scans'),undefined);p.unmount();
});

test('empty history after clearing cannot be resurrected by an older poll',async()=>{
 const old=deferred();let lists=0,removed=false;const p=mount({route:a=>a.operation==='list'?(++lists===2?old.promise:removed?[]:[failedScan]):a.operation==='get'?failedScan:a.operation==='clear_failed'?(removed=true,{removed:a.ids}):undefined});await p.flush();p.click(historyButton(p));await p.flush();p.tick();await p.flush();p.click(p.button('Clear failed scans (1)'));p.click(p.button('Remove failed scans'));await p.flush();assert.match(p.text(),/No scans for this workspace/);
 old.resolve([failedScan]);await p.flush();assert.match(p.text(),/No scans for this workspace/);assert.equal(p.button('Clear failed scans (1)'),undefined);assert.equal(p.button('Download diagnostics'),undefined);p.unmount();
});

test('removal displays pending and retryable error states without clearing entries or consent',async()=>{
 const pending=deferred();const p=mount({history:[failedScan],route:a=>a.operation==='clear_failed'?pending.promise:undefined});await p.flush();p.change(p.input('checkbox'),true);p.click(p.button('Remove'));p.click(p.button('Remove failed scans'));assert.match(p.text(),/Removing failed scans/);assert.equal(p.button('Remove failed scans').props.disabled,true);pending.reject(Error('Scan cleanup is still pending'));await p.flush();assert.match(p.text(),/Scan cleanup is still pending/);assert.equal(p.button('Remove failed scans').props.disabled,false);assert.equal(p.input('checkbox').props.checked,true);assert.ok(p.button('Remove'));p.unmount();
});

test('partial deletion error refreshes remaining history, detail and confirmation snapshot',async()=>{
 let rows=[failedScan,{...failedScan,id:'failed-b'}];const p=mount({route:a=>a.operation==='list'?rows:a.operation==='get'?failedScan:a.operation==='clear_failed'?(rows=rows.slice(1),Promise.reject(Error('storage unavailable'))):undefined});await p.flush();p.click(historyButton(p));await p.flush();p.click(p.button('Clear failed scans (2)'));p.click(p.button('Remove failed scans'));await p.flush();assert.match(p.text(),/storage unavailable/);assert.match(p.text(),/Remove 1 failed scan\?/);assert.equal(p.button('Download diagnostics'),undefined);assert.ok(p.button('Clear failed scans (1)'));p.unmount();
});

test('selected running poll cannot restore a failed detail deleted before effect cleanup',async()=>{
 const old=deferred();let gets=0,removed=false;const running={...failedScan,status:'running'};
 const p=mount({route:a=>a.operation==='list'?(removed?(old.resolve(failedScan),[]):[failedScan]):a.operation==='get'?(++gets===1?running:old.promise):a.operation==='clear_failed'?(removed=true,{removed:a.ids}):undefined});await p.flush();p.click(historyButton(p));await p.flush();p.tick();await p.flush();
 p.click(p.button('Clear failed scans (1)'));p.click(p.button('Remove failed scans'));await p.flush();assert.equal(p.button('Download diagnostics'),undefined);assert.equal(p.button('Cancel scan'),undefined);assert.match(p.text(),/No scans for this workspace/);p.unmount();
});

test('adapter rejection evidence is visible without opening raw diagnostic details',async()=>{
 const row={...failedScan,diagnostics:[{kind:'gateway',outcome:'failed',diagnosticVersion:2,reportedHttpStatus:400,providerErrorCode:'invalid_function_parameters',providerErrorType:'invalid_request_error',rejectedParameter:'tools',rejectedToolIndex:12,rejectionHints:['tool_schema_invalid','schema_additional_properties','schema_required'],messageAvailable:true,providerMessageTruncated:true}]};const p=mount({history:[row],route:a=>a.operation==='get'?row:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.match(p.text(),/Adapter failure details/);assert.match(p.text(),/400 \(message evidence, not structured transport metadata\)/);assert.match(p.text(),/Rejected parameter: tools · tool index 12/);assert.match(p.text(),/additionalProperties schema requirement/);assert.match(p.text(),/required-fields schema mismatch/);assert.match(p.text(),/not proof/);assert.match(p.text(),/limited to 32,768 characters/);assert.equal(p.requests.some(r=>['start','validate'].includes(r.args.operation)),false);p.unmount();
});

test('diagnostic downloads include only sanitized log data, not report/error/progress or authorization',async()=>{
 const secret='TEST-ONLY-SOURCE-CREDENTIAL-CANARY',row={...failedScan,error:secret,events:[secret],result:{report:secret},diagnosticsDropped:2};const p=mount({history:[row],route:a=>a.operation==='get'?row:undefined});await p.flush();p.click(historyButton(p));await p.flush();assert.match(p.text(),/Diagnostic log \(1\)/);p.click(p.button('Download diagnostics'));await p.flush();const blob=await p.blobs[0].text();assert.deepEqual(JSON.parse(blob),{version:1,scanId:row.id,diagnosticsDropped:2,diagnostics:row.diagnostics});assert.ok(!blob.includes(secret));assert.ok(!blob.includes('test-only-panel-token'));assert.equal(p.downloads[0].download,'security-failed-a-diagnostics.json');p.runTimeouts();assert.equal(p.revoked.length,1);assert.equal(p.requests.some(r=>['start','validate','export'].includes(r.args.operation)),false);p.unmount();
});
