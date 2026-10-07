import {readFile,writeFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
const inputs=['build.mjs','build-engine.mjs','engine/.dockerignore','host.mjs','core.mjs','transport.mjs','models.mjs','harness-gateway.mjs','image.json','client.js','engine/Dockerfile','engine/runner.mjs','engine/token.mjs','engine/models.json','engine/seccomp.json','engine/package.json','engine/package-lock.json'];
const files=Object.fromEntries(await Promise.all(inputs.map(async f=>[f,await readFile(new URL(f,import.meta.url),'utf8')])));
const hash=createHash('sha256');for(const f of inputs)hash.update(f+'\0'+files[f]);const revision=hash.digest('hex').slice(0,16);
const output={
 [`core-${revision}.mjs`]:files['core.mjs'].replace("'./engine/seccomp.json'",`'./seccomp-${revision}.json'`),
 [`seccomp-${revision}.json`]:files['engine/seccomp.json'],
 [`transport-${revision}.mjs`]:files['transport.mjs'].replace("'./core.mjs'",`'./core-${revision}.mjs'`),
 [`models-${revision}.mjs`]:files['models.mjs'].replace("'./transport.mjs'",`'./transport-${revision}.mjs'`),
 [`harness-gateway-${revision}.mjs`]:files['harness-gateway.mjs'],
 [`image-${revision}.json`]:files['image.json'],
 [`runtime-${revision}.mjs`]:files['host.mjs'].replace("'./core.mjs'",`'./core-${revision}.mjs'`).replace("'./transport.mjs'",`'./transport-${revision}.mjs'`).replace("'./models.mjs'",`'./models-${revision}.mjs'`).replace("'./harness-gateway.mjs'",`'./harness-gateway-${revision}.mjs'`).replace("'./image.json'",`'./image-${revision}.json'`),
 'cordis.patch.yml':`- insert:\n    - id: dsh-security\n      name: ./runtime-${revision}.mjs\n`
};
for(const [name,content] of Object.entries(output))await writeFile(new URL(name,import.meta.url),content);
console.log(revision);
