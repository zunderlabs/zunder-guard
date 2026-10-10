/** Fresh no-secret hosted build. Historical generated files are never inputs. */
import fs from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const need=(v)=>{if(!v)throw new Error('Closed hosted bundle build refused');};
const hash=(v)=>createHash('sha256').update(v).digest('hex');
const relative=(v)=>typeof v==='string'&&v.length>0&&v.length<=1024&&/^[A-Za-z0-9_./+@-]+$/.test(v)&&!v.startsWith('/')&&v.split('/').every(p=>p!==''&&p!=='.'&&p!=='..');
const canonical=(v)=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b,'en'))):x);
const root=process.argv[2];
need(process.argv.length===3&&root==='/var/lib/zunder-hosted-ordinary/runtime/website/source'&&await fs.realpath(root)===root);
need(process.platform==='linux'&&process.arch==='x64'&&process.getuid()===0&&process.version==='v26.8.1');
const esbuild=await import(pathToFileURL(path.join(root,'web/site/node_modules/esbuild/lib/main.js')).href);
need(esbuild.version==='0.28.2');
const options={entryPoints:['web/testnet-journey/wallet-extension/private-journey-entry.ts'],bundle:true,
  platform:'node',format:'esm',target:'node26',metafile:true,write:false,outfile:'private-journey.mjs'};
const result=await esbuild.build({...options,absWorkingDir:root,nodePaths:[path.join(root,'web/site/node_modules')],logLevel:'silent'});
need(result.errors.length===0&&result.outputFiles.length===1&&result.outputFiles[0].path===path.join(root,'private-journey.mjs'));
const bindings=[];
for(const [name,input] of Object.entries(result.metafile.inputs).sort(([a],[b])=>a.localeCompare(b,'en'))){
  need(relative(name)&&input.bytes>=0&&input.bytes<=16777216&&!name.startsWith('artifacts/'));
  const file=path.join(root,name);need(await fs.realpath(file)===file);
  const fd=await fs.open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const before=await fd.stat();need(before.isFile()&&before.nlink===1&&before.uid===0&&before.size===input.bytes);
    const raw=await fd.readFile();const after=await fd.stat(),current=await fs.lstat(file);
    need(raw.length===before.size&&after.dev===before.dev&&after.ino===before.ino&&after.size===before.size&&
      after.mtimeMs===before.mtimeMs&&after.ctimeMs===before.ctimeMs&&current.dev===before.dev&&current.ino===before.ino);
    bindings.push({metafileInput:name,path:name,size:raw.length,sha256:hash(raw)});
  }finally{await fd.close();}
}
need(bindings.length>0&&bindings.length<=1000&&Object.keys(result.metafile.outputs).join(',')==='private-journey.mjs');
const output=path.join(root,'artifacts/private-journey');await fs.mkdir(output,{recursive:true,mode:0o700});
const bytes=result.outputFiles[0].contents;
const products={'private-journey.mjs':bytes,'private-journey.metafile.json':Buffer.from(canonical(result.metafile)),
  'build-options.json':Buffer.from(canonical({...options,esbuildVersion:esbuild.version})),
  'input-bindings.json':Buffer.from(canonical(bindings))};
for(const [name,raw] of Object.entries(products)){
  const fd=await fs.open(path.join(output,name),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await fd.writeFile(raw);await fd.sync();}finally{await fd.close();}
}
const metadata={schema:1,purpose:'actual-no-secret-free-hosted-bundle-build',node:process.version,
  esbuild:esbuild.version,inputCount:bindings.length,inputsSha256:hash(products['input-bindings.json']),
  outputs:Object.fromEntries(Object.entries(products).map(([name,raw])=>[name,{bytes:raw.length,sha256:hash(raw)}])),
  historicalReceiptAdopted:false,privateInput:false,releaseReady:false};
const fd=await fs.open(path.join(output,'bundle-build.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
try{await fd.writeFile(canonical(metadata));await fd.sync();}finally{await fd.close();}
process.stdout.write(canonical({schema:1,inputCount:bindings.length,bundleSha256:hash(bytes),privateInput:false,releaseReady:false})+'\n');
