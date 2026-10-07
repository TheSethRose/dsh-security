window.__ModuleLoader__.load({id:'dsh-security',factory:require=>{
 const React=require('react'),h=React.createElement;
 const css='.dsh-sec{height:100%;overflow:auto;padding:24px;font:14px/1.5 var(--dsw-font-family);color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-base)}.dsh-sec h1{font-size:22px}.dsh-sec h2{font-size:17px}.dsh-sec .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.dsh-sec .card{padding:16px;margin:16px 0;border-radius:var(--dsw-radius-lg);background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l2)}.dsh-sec button,.dsh-sec select,.dsh-sec input[type=number]{font:inherit;padding:6px 12px;background:var(--dsw-alias-bg-layer-1);color:inherit;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md)}.dsh-sec button{cursor:pointer}.dsh-sec button:disabled{opacity:.45;cursor:not-allowed}.dsh-sec pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.dsh-sec .error{color:var(--dsw-alias-state-error-primary)}.dsh-sec .muted{color:var(--dsw-alias-label-secondary)}.dsh-sec label{display:flex;gap:6px;align-items:center}.dsh-sec :focus-visible{outline:2px solid var(--dsw-alias-brand-primary)}';
 const key=model=>JSON.stringify({provider:model.provider,model:model.id});
 let panelToken;
 async function api(args){const paid=['start','validate'].includes(args.operation);if(paid&&!panelToken)throw Error('Security authorization is not ready. Refresh the page and try again.');const r=await fetch('/dsh-security/api',{method:'POST',mode:'same-origin',credentials:'same-origin',headers:{'Content-Type':'application/json','X-DSH-Security':'1',...(panelToken?{'X-DSH-Security-CSRF':panelToken}:{})},body:JSON.stringify(args)}),data=await r.json();if(!r.ok||data.error)throw Error(data.error??'Security API failed');if(typeof data.panelToken==='string')panelToken=data.panelToken;return data.result;}
 function apply(ctx){
  const slots=ctx.get('slots');ctx.effect(()=>{const style=document.createElement('style');style.textContent=css;document.head.appendChild(style);return()=>style.remove();});
  function Panel(){
   const [workspaces,setWorkspaces]=React.useState([]),[wid,setWid]=React.useState(''),[status,setStatus]=React.useState(null),[history,setHistory]=React.useState([]),[selected,setSelected]=React.useState(null),[error,setError]=React.useState(''),[busy,setBusy]=React.useState(''),[consent,setConsent]=React.useState(false),[model,setModel]=React.useState(''),[mode,setMode]=React.useState('standard'),[minutes,setMinutes]=React.useState(30);
   const current=React.useRef({wid}),initialized=React.useRef(false),active=React.useRef(true);if(current.current?.wid!==wid)current.current={wid};
   React.useEffect(()=>{active.current=true;api({operation:'workspaces'}).then(rows=>{if(active.current){setWorkspaces(rows);setWid(rows[0]?.id??'');}}).catch(e=>{if(active.current)setError(e.message);});return()=>{active.current=false;current.current=null;};},[]);
   React.useEffect(()=>{const visit=current.current??(current.current={wid});setStatus(null);setHistory([]);setSelected(null);setConsent(false);setError('');setBusy('');let disposed=false,pending=false;
    const refresh=async()=>{if(!wid||pending||disposed)return;pending=true;try{const [s,rows]=await Promise.all([api({operation:'status',workspaceId:wid}),api({operation:'list',workspaceId:wid})]);if(!disposed&&current.current===visit){setStatus(s);setHistory(rows);}}catch(e){if(!disposed&&current.current===visit)setError(e.message);}finally{pending=false;}};
    void refresh();const timer=setInterval(refresh,3000);return()=>{disposed=true;if(current.current===visit)current.current=null;clearInterval(timer);};
   },[wid]);
   React.useEffect(()=>{if(!wid||selected?.status!=='running')return;const visit=current.current;let disposed=false,pending=false;
    const timer=setInterval(async()=>{if(pending||disposed)return;pending=true;try{const row=await api({operation:'get',workspaceId:wid,id:selected.id});if(!disposed&&current.current===visit)setSelected(row);}catch(e){if(!disposed&&current.current===visit)setError(e.message);}finally{pending=false;}},3000);
    return()=>{disposed=true;clearInterval(timer);};
   },[wid,selected?.id,selected?.status]);
   React.useEffect(()=>{
    if(!status?.models)return;
    if(!initialized.current){const d=status.defaultSelection,m=status.models.find(m=>m.provider===d?.provider&&m.id===d?.model);if(m){initialized.current=true;setModel(key(m));}return;}
    if(model&&!status.models.some(m=>key(m)===model)){setModel('');setConsent(false);}
   },[status,model]);
   const chosen=status?.models?.find(m=>key(m)===model),d=status?.defaultSelection;
   const selection=chosen?{provider:chosen.provider,model:chosen.id,...(d?.provider===chosen.provider&&d?.model===chosen.id&&d.reasoningEffort!==undefined?{reasoningEffort:d.reasoningEffort}:{})}:{};
   const validDeadline=Number.isInteger(minutes)&&minutes>=1&&minutes<=120;
   async function act(operation,args={}){const visit=current.current;if(!visit||visit.wid!==wid)return;setBusy(operation);setError('');try{const value=await api({operation,workspaceId:wid,...args});if(current.current!==visit)return;
    if(operation==='export'){const blob=new Blob([value.export],{type:args.format==='csv'?'text/csv':'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`security-${args.id}.${args.format}`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    else if(operation==='get')setSelected(value);
    else{const [s,rows]=await Promise.all([api({operation:'status',workspaceId:wid}),api({operation:'list',workspaceId:wid})]);if(current.current!==visit)return;setStatus(s);setHistory(rows);if(value?.id){const detail=await api({operation:'get',workspaceId:wid,id:value.id});if(current.current===visit)setSelected(detail);}}
   }catch(e){if(current.current===visit)setError(e.message);}finally{if(current.current===visit)setBusy('');}}
   const button=(label,fn,disabled=false)=>h('button',{onClick:fn,disabled:disabled||!!busy},label);
   return h('section',{className:'dsh-sec'},h('h1',null,'Security'),h('p',{className:'muted'},'Isolated Codex Security · configured Harness model · report-only'),
    h('div',{className:'row'},h('label',null,'Workspace ',h('select',{value:wid,onChange:e=>setWid(e.target.value)},...workspaces.map(w=>h('option',{key:w.id,value:w.id},w.title))))),
    error&&h('p',{className:'error'},error),busy&&h('p',{className:'muted'},busy+'…'),
    h('div',{className:'card'},h('h2',null,'New scan'),h('div',{className:'row'},
     h('label',null,'Model ',h('select',{value:model,onChange:e=>{initialized.current=true;setModel(e.target.value);setConsent(false);}},h('option',{value:''},'Choose a configured model'),...(status?.models??[]).map(m=>h('option',{key:key(m),value:key(m)},m.name+' · '+m.providerName)))),
     h('label',null,'Mode ',h('select',{value:mode,onChange:e=>setMode(e.target.value)},h('option',{value:'standard'},'Standard'),h('option',{value:'deep'},'Deep (higher cost)'))),
     h('label',null,'Deadline (minutes)',h('input',{type:'number',min:1,max:120,value:minutes,onChange:e=>setMinutes(Number(e.target.value))}))),
     h('p',null,'Source code and findings are sent through the selected Harness provider using its existing authentication. Inference may be billable; the deadline and 100-request ceiling are not a dollar budget. No fixes or publication are performed.'),
     h('label',null,h('input',{type:'checkbox',checked:consent,onChange:e=>setConsent(e.target.checked)}),'I authorize source transmission and inference through the selected Harness provider for this workspace.'),
     status&&!status.panelAuthorizationVerified&&h('p',{className:'error'},'Security panel authorization is refreshing. If this persists, reload the page.'),
      status&&!status.models?.length&&h('p',{className:'muted'},'No configured models are available. Configure a provider/model in Harness Settings.'),
     ...(status?.modelErrors??[]).map(e=>h('p',{key:e.provider,className:'muted'},e.provider+': '+e.message)),
     button(status?.active?'Scan running':'Start scan',()=>{setConsent(false);void act('start',{...selection,mode,minutes,userRequested:true});},!wid||!chosen||!consent||!status?.panelAuthorizationVerified||status?.active||!validDeadline)),
    h('div',{className:'card'},h('h2',null,'History'),history.length?history.map(row=>h('div',{key:row.id,className:'row'},button(`${row.createdAt} · ${row.operation} · ${row.status} · ${row.findings} findings`,()=>act('get',{id:row.id})))):h('p',{className:'muted'},'No scans for this workspace.')),
    selected&&h('div',{className:'card'},h('h2',null,`${selected.operation} · ${selected.status}`),h('p',null,[selected.provider,selected.model,selected.id].filter(Boolean).join(' · ')),selected.error&&h('p',{className:'error'},selected.error),
     selected.status==='running'&&button('Cancel scan',()=>act('cancel',{id:selected.id})),
     selected.status==='completed'&&selected.operation==='scan'&&h('div',{className:'row'},...['json','csv','sarif'].map(format=>button('Export '+format.toUpperCase(),()=>act('export',{id:selected.id,format})))),
     ...(selected.result?.findings?.findings??[]).map((f,index)=>h('details',{key:f.findingId??index,className:'card'},h('summary',null,`${f.severity?.level??f.severity??'unknown'} · ${f.title}`),h('pre',null,JSON.stringify(f,null,2)),button('Validate finding',()=>{setConsent(false);void act('validate',{...selection,id:selected.id,findingIndex:index,userRequested:true,minutes});},!consent||!chosen||!status?.panelAuthorizationVerified||status?.active||!validDeadline))),
     selected.result?.report&&h('details',null,h('summary',null,'Report / validation evidence'),h('pre',null,selected.result.report)),
     selected.result?.threatModel&&h('details',null,h('summary',null,'Threat model'),h('pre',null,JSON.stringify(selected.result.threatModel,null,2))),
     selected.result?.coverage&&h('details',null,h('summary',null,'Coverage'),h('pre',null,JSON.stringify(selected.result.coverage,null,2))),
     selected.events?.length>0&&h('details',null,h('summary',null,'Progress and warnings'),h('pre',null,selected.events.join('\n')))));
  }
  slots.inject('main',()=>slots.register({name:'main',key:'dsh-security'},Panel));
  slots.inject('sidebar.panellist',()=>slots.register({name:'sidebar.panellist',id:'dsh-security',order:20,label:'Security'},()=>h('span',{'aria-hidden':true},'◇')));
 }
 return {apply,inject:['slots']};
}});
