// Actual harmless anonymous OS pipes; public fixture bytes only. No keeper,
// source-authority credit, credentials, wallet generation or network operations.
import test from 'node:test';import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';import {readFileSync,realpathSync} from 'node:fs';import {createHash} from 'node:crypto';
const node=realpathSync(process.execPath),nodeSha=createHash('sha256').update(readFileSync(node)).digest('hex');
const moduleUrl=new URL('./completion-pipe.ts',import.meta.url).href,policyUrl=new URL('./policy.ts',import.meta.url).href;
const child=[
 "import fs from 'node:fs';import {performance}from'node:perf_hooks';",
 "import {readProtectedCompletionPipe}from"+JSON.stringify(moduleUrl)+";import{Admission}from"+JSON.stringify(policyUrl)+";",
 "const expected=JSON.parse(process.argv[1]),mode=process.argv[2];",
 "const start=Date.now(),a=new Admission(start+(mode==='expiry'?80:2000),Date.now,()=>performance.now());",
 "let outcome='rejected',frameMatches=false;try{const b=await readProtectedCompletionPipe(expected,a);outcome='accepted';frameMatches=b.equals(Buffer.from('{\"a\":1}\\n'));b.fill(0);}catch{}",
 "let foreignOpen=false;try{fs.fstatSync(3);foreignOpen=true;}catch{}",
 "let secondRefused=false;try{await readProtectedCompletionPipe(expected,a);}catch{secondRefused=true;}",
 "console.log(JSON.stringify({outcome,frameMatches,foreignOpen,secondRefused,unknown:a.status().unknown}));",
].join('\n');
const python=[
 "import os,sys,json,subprocess,threading,time,hashlib,socket",
 "node,digest,code,mode=sys.argv[1:]",
 "assert hashlib.sha256(open(node,'rb').read()).hexdigest()==digest",
 "writer=None;other=None",
 "if mode=='regular':",
 " import tempfile",
 " other=tempfile.TemporaryFile();r=other.fileno()",
 "elif mode=='socket':",
 " left,right=socket.socketpair();r=left.fileno();other=(left,right)",
 "else:r,writer=os.pipe()",
 "if r!=3:os.dup2(r,3)",
 "st=os.fstat(3);expected={'fd':3,'device':str(st.st_dev),'inode':str(st.st_ino),'uid':st.st_uid}",
 "if mode=='identity':expected['inode']=str(st.st_ino+1)",
 "if mode=='uid':expected['uid']=st.st_uid+1",
 "p=subprocess.Popen([node,'--input-type=module','-e',code,json.dumps(expected,separators=(',',':')),mode],pass_fds=(3,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)",
 "os.close(3)",
 "def send():",
 " try:",
 "  if mode=='split':",
 "   os.write(writer,b'{\"a\":');time.sleep(.2);os.write(writer,b'1}\\n')",
 "  elif mode=='trailing':",
 "   os.write(writer,b'{\"a\":1}\\n');time.sleep(.2);os.write(writer,b'{}\\n')",
 "  elif mode=='oversize':os.write(writer,b'{' + b'a'*8192 + b'}\\n')",
 "  elif mode=='missing-lf':os.write(writer,b'{\"a\":1}')",
 "  elif mode=='expiry':time.sleep(.35)",
 "  else:os.write(writer,b'{\"a\":1}\\n')",
 " except BrokenPipeError:pass",
 " finally:os.close(writer)",
 "thread=None",
 "if writer is not None:thread=threading.Thread(target=send);thread.start()",
 "out,err=p.communicate(timeout=5)",
 "if thread:thread.join(timeout=1)",
 "assert p.returncode==0,(p.returncode,err.decode())",
 "print(out.decode(),end='')",
].join('\n');
function run(mode:string){
 const result=spawnSync('/usr/bin/python3',['-I','-S','-B','-c',python,node,nodeSha,child,mode],{encoding:'utf8',timeout:10000,maxBuffer:16384});
 assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout.trim());
}
for(const mode of ['good','split'])test('actual anonymous pipe accepts one bounded frame after EOF: '+mode,()=>{
 const r=run(mode);assert.equal(r.outcome,'accepted');assert.equal(r.frameMatches,true);assert.equal(r.foreignOpen,false);assert.equal(r.secondRefused,true);
});
for(const mode of ['trailing','oversize','missing-lf','expiry'])test('actual anonymous pipe rejects '+mode+' and closes only owned fd',()=>{
 const r=run(mode);assert.equal(r.outcome,'rejected');assert.equal(r.foreignOpen,false);assert.equal(r.secondRefused,true);assert.equal(r.unknown,true);
});
for(const mode of ['identity','uid','regular','socket'])test('actual foreign '+mode+' descriptor is never closed and failed claim stays consumed',()=>{
 const r=run(mode);assert.equal(r.outcome,'rejected');assert.equal(r.foreignOpen,true);assert.equal(r.secondRefused,true);assert.equal(r.unknown,true);
});
