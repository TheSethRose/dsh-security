import test from 'node:test';import assert from 'node:assert/strict';import os from 'node:os';import path from 'node:path';import {readFile,writeFile,mkdtemp,mkdir,symlink,readdir} from 'node:fs/promises';import {pathToFileURL,fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
test('cache-safe builds revision-copy every helper, image and sandbox policy and load real Host dependencies',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'security-build-'));const inputs=['build.mjs','build-engine.mjs','engine/.dockerignore','host.mjs','core.mjs','transport.mjs','models.mjs','harness-gateway.mjs','image.json','client.js','engine/Dockerfile','engine/runner.mjs','engine/token.mjs','engine/models.json','engine/seccomp.json','engine/package.json','engine/package-lock.json'];
 await mkdir(path.join(dir,'engine'));await symlink(path.join(root,'node_modules'),path.join(dir,'node_modules'));
 for(const name of inputs)await writeFile(path.join(dir,name),await readFile(path.join(root,name),'utf8'));
 const core=await readFile(path.join(dir,'core.mjs'),'utf8');await writeFile(path.join(dir,'core.mjs'),core+'\nexport const testRevision=1;\n');
 await import(pathToFileURL(path.join(dir,'build.mjs')).href+'?first');
 const first=(await readFile(path.join(dir,'cordis.patch.yml'),'utf8')).match(/runtime-([a-f0-9]+)\.mjs/)[1];const firstCore=await import(pathToFileURL(path.join(dir,`core-${first}.mjs`)).href);assert.equal(firstCore.testRevision,1);
 assert.equal((await import(pathToFileURL(path.join(dir,`runtime-${first}.mjs`)).href)).name,'dsh-security');
 await writeFile(path.join(dir,'core.mjs'),core+'\nexport const testRevision=2;\n');const changedImage=JSON.stringify({image:'sha256:'+'1'.repeat(64)});await writeFile(path.join(dir,'image.json'),changedImage);
 await import(pathToFileURL(path.join(dir,'build.mjs')).href+'?second');
 const second=(await readFile(path.join(dir,'cordis.patch.yml'),'utf8')).match(/runtime-([a-f0-9]+)\.mjs/)[1];assert.notEqual(first,second);const secondCore=await import(pathToFileURL(path.join(dir,`core-${second}.mjs`)).href);assert.equal(secondCore.testRevision,2);assert.equal(firstCore.testRevision,1);
 const transport=await readFile(path.join(dir,`transport-${second}.mjs`),'utf8');assert.ok(transport.includes(`core-${second}.mjs`));assert.equal(await readFile(path.join(dir,`image-${second}.json`),'utf8'),changedImage);assert.equal(await readFile(path.join(dir,`seccomp-${second}.json`),'utf8'),await readFile(path.join(dir,'engine/seccomp.json'),'utf8'));
 for(const helper of ['models','harness-gateway']){assert.ok((await readFile(path.join(dir,`runtime-${second}.mjs`),'utf8')).includes(`${helper}-${second}.mjs`));assert.ok((await readFile(path.join(dir,`${helper}-${second}.mjs`),'utf8')).length>0);}
 assert.ok((await readFile(path.join(dir,`models-${second}.mjs`),'utf8')).includes(`transport-${second}.mjs`));
 assert.ok((await readFile(path.join(dir,`core-${second}.mjs`),'utf8')).includes(`seccomp-${second}.json`));assert.equal((await import(pathToFileURL(path.join(dir,`runtime-${second}.mjs`)).href)).name,'dsh-security');
 let previous=second;for(const helper of ['models','harness-gateway']){const file=path.join(dir,`${helper}.mjs`),text=await readFile(file,'utf8');await writeFile(file,text+'\n// revision probe\n');await import(pathToFileURL(path.join(dir,'build.mjs')).href+'?'+helper);const revision=(await readFile(path.join(dir,'cordis.patch.yml'),'utf8')).match(/runtime-([a-f0-9]+)\.mjs/)[1];assert.notEqual(revision,previous);assert.equal(await readFile(path.join(dir,`${helper}-${revision}.mjs`),'utf8'),(text+'\n// revision probe\n').replace("'./transport.mjs'",`'./transport-${revision}.mjs'`));previous=revision;}
});
