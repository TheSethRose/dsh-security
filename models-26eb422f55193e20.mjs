import {abortable} from './transport-26eb422f55193e20.mjs';
const identity=value=>typeof value==='string'&&value.length>0&&value.length<=512&&!/[\x00-\x1f\x7f]/.test(value);
export async function modelCatalog(controller,signal=AbortSignal.timeout(10000)){
  try{
    const catalog=await abortable(controller.modelCatalog(),signal);
    const models=catalog.groups.flatMap(group=>group.models.filter(m=>identity(group.id)&&identity(m.id)).map(m=>({provider:group.id,id:m.id,name:m.name,providerName:group.name})));
    const modelErrors=catalog.failures.map(f=>({provider:f.id,message:'Configured provider model catalog is unavailable'}));
    const d=catalog.default;
    const defaultSelection=identity(d?.provider)&&identity(d?.model)?{provider:d.provider,model:d.model,...(identity(d.reasoningEffort)?{reasoningEffort:d.reasoningEffort}:{})}:undefined;
    return {models,modelErrors,...(defaultSelection?{defaultSelection}:{})};
  }catch{
    if(signal?.aborted)throw new DOMException('Request aborted','AbortError');
    return {models:[],modelErrors:[{provider:'catalog',message:'Harness native model catalog is unavailable'}]};
  }
}
export async function resolveSelection(llm,selection,signal,controller){
  if(!identity(selection.provider)||!identity(selection.model))throw Error('Choose a configured Harness provider and model');
  let providers;try{providers=llm.listProviders();}catch{throw Error('Harness provider catalog is unavailable');}
  if(!providers.some(p=>p.id===selection.provider))throw Error('Selected Harness provider is not configured');
  const catalog=await modelCatalog(controller,signal);
  if(!catalog.models.some(m=>m.provider===selection.provider&&m.id===selection.model))throw Error('Selected model is not in the configured Harness catalog');
  let info;try{info=await abortable(llm.resolveModelInfo(selection.provider,selection.model,signal),signal);}catch{
    if(signal?.aborted)throw new DOMException('Request aborted','AbortError');
    throw Error('Selected Harness model metadata is unavailable');
  }
  if(info.provider!==selection.provider||info.id!==selection.model)throw Error('Model mismatch: fallback is prohibited');
  if(selection.reasoningEffort!==undefined&&!info.reasoning?.efforts?.some(e=>e.id===selection.reasoningEffort))throw Error('Selected reasoning effort is not supported by this model');
  const contextWindow=info.context?.contextWindow;
  return {...selection,...(Number.isSafeInteger(contextWindow)&&contextWindow>0&&contextWindow<=4194304?{contextWindow}:{})};
}
