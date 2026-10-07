import {spawn} from 'node:child_process';
import {abortable} from '../transport.mjs';
// Test-only adapter: manages the direct Docker CLI child, not a production
// process-group implementation. Container lifetime is owned by runEngine.
export const subprocess={spawn(spec){
 const child=spawn(spec.argv[0],spec.argv.slice(1),{cwd:spec.cwd,env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:process.env.HOME},stdio:[spec.stdio.stdin==='pipe'?'pipe':'ignore','pipe','pipe']});
 const streams={};for(const name of ['stdout','stderr'])if(typeof spec.stdio[name]==='object'){let value='';child[name].on('data',data=>{value=(value+data).slice(-spec.stdio[name].maxBytes);});streams[name]={readFrom:()=>({text:value})};}
 let exited=false,killTimer;
 const done=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(exitCode,signal)=>{exited=true;resolve({exitCode,signal});});});
 const terminate=()=>{if(exited)return;child.kill('SIGTERM');if(!killTimer){killTimer=setTimeout(()=>{if(!exited)child.kill('SIGKILL');},spec.graceMs??1000);killTimer.unref?.();}};
 const cleanup=()=>{clearTimeout(killTimer);spec.signal?.removeEventListener('abort',terminate);};void done.then(cleanup,cleanup);
 spec.signal?.addEventListener('abort',terminate,{once:true});if(spec.signal?.aborted)terminate();
 return {stdin:child.stdin,stdout:child.stdout,stderr:child.stderr,collected:streams,done,terminate,waitForExit:async signal=>{await abortable(done,signal);return true;}};
}};
