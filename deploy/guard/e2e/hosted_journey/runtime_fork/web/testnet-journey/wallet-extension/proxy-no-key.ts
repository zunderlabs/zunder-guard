// Public PREFLIGHT denial recognition only. This window cannot forward, admit
// TLS/private input, dispatch an upstream or grant kernel/source authority.
import path from 'node:path';
import {isIPv4} from 'node:net';
import type {Pin} from './driver-policy.ts';
export interface NoKeyBrowserProbeConfig {
  schema: 1; purpose: "no-key-boundary-probes"; runId: string;
  startedAt: number; deadline: number; authoritySha256: string;
  launcherSha256: string; probeLauncherSha256: string; profileMountPath: string;
  extensionId: string;
  controller: { pid: number; birth: string; anonymousFd: number; netnsFd: number; canarySha256: string };
  network: { proxyIpv4: string; proxyPort: number; deniedPort: 48731 };
}
export interface NoKeyBrowserProbeInputs {
  modulePin: Pin; contractPin: Pin; config: NoKeyBrowserProbeConfig;
}

import type {ProxyConfig} from './proxy-policy.ts';
const BROWSER='982fc8705c4ad125bd247a026ee8bb8fd22dc814ac6b67a81cbcf02d352a5cec';
const CONTRACT='41c2f715bf034fd1ab8dfca5fbbf1e82a279e748be63431c7287f9adeba634c8';
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const exact=(v:unknown,keys:readonly string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
 &&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
function refuse():never{throw new Error('Public no-key probe window refused');}
export interface NoKeyDenialRequest {
 kind:'connect'|'outer';method:string;target:string;rawHeaders:readonly string[];
 headLength:number;bodyLength:number;trailersLength:number;
}
type Scope=Pick<ProxyConfig,'runId'|'startedAt'|'deadline'|'extensionId'>;
type State='unopened'|'open'|'closing'|'closed';
export interface NoKeyDenialReceiptExpected {
 readonly instanceId:string;readonly runId:string;readonly startedAt:number;readonly deadline:number;
}
export interface NoKeyDenialReceipt extends NoKeyDenialReceiptExpected {
 readonly schema:1;readonly purpose:'no-key-proxy-denials-drained';readonly closed:true;readonly matchingDisabled:true;
 readonly sockets:0;readonly outstandingRequests:0;readonly total:number;readonly counts:readonly number[];
}
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max;
/** Pure public receipt binding only. Parsing cannot establish actual drain,
 * kernel/source admission or substitute for the native proxy's observation. */
export function validateNoKeyDenialReceipt(value:unknown,expected:NoKeyDenialReceiptExpected):Readonly<NoKeyDenialReceipt> {
 if(!exact(expected,['instanceId','runId','startedAt','deadline'])||!uuid(expected.instanceId)||!uuid(expected.runId)
  ||!integer(expected.startedAt,0,Number.MAX_SAFE_INTEGER)||!integer(expected.deadline,0,Number.MAX_SAFE_INTEGER)
  ||expected.deadline<=expected.startedAt||expected.deadline-expected.startedAt>1200000
  ||!exact(value,['schema','purpose','instanceId','runId','startedAt','deadline','closed','matchingDisabled','sockets','outstandingRequests','total','counts'])
  ||value.schema!==1||value.purpose!=='no-key-proxy-denials-drained'||value.instanceId!==expected.instanceId||value.runId!==expected.runId
  ||value.startedAt!==expected.startedAt||value.deadline!==expected.deadline||value.closed!==true||value.matchingDisabled!==true
  ||value.sockets!==0||value.outstandingRequests!==0||!integer(value.total,0,24)||!Array.isArray(value.counts)||value.counts.length!==6
  ||Object.keys(value.counts).length!==6||Array.from(value.counts).some(v=>!integer(v,0,4))
  ||value.counts.reduce((sum,v)=>sum+v,0)!==value.total)refuse();
 return Object.freeze({schema:1,purpose:'no-key-proxy-denials-drained',instanceId:expected.instanceId,runId:expected.runId,
  startedAt:expected.startedAt,deadline:expected.deadline,closed:true,matchingDisabled:true,sockets:0,outstandingRequests:0,
  total:value.total,counts:Object.freeze([...value.counts])});
}
const GET_HEADERS=new Set(['host','connection','proxy-connection','accept','accept-encoding','accept-language','user-agent',
 'origin','referer','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-fetch-user','sec-ch-ua','sec-ch-ua-mobile',
 'sec-ch-ua-platform','priority','cache-control','pragma']);
const CONNECT_HEADERS=new Set(['host','proxy-connection','user-agent']);
/** Uses only main's existing original public guard time. No clock, callbacks,
 * listener, connection, signing or reset facility exists in this primitive. */
export class NoKeyProbeWindow {
 private state:State='unopened';private scope:Scope;private endpoint:{ipv4:string;port:number};
 private targets:readonly string[]=[];private counts:number[]=[];private total=0;private lastNow:number;
 constructor(original:Scope,endpoint:{ipv4:string;port:number}){
  this.scope=structuredClone(original);this.endpoint=structuredClone(endpoint);this.lastNow=original.startedAt;
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(original.runId)
   ||!Number.isSafeInteger(original.startedAt)||original.startedAt<0||!Number.isSafeInteger(original.deadline)
   ||original.deadline<=original.startedAt||original.deadline-original.startedAt>1200000||!/^[a-p]{32}$/.test(original.extensionId)
   ||!isIPv4(endpoint.ipv4)||!endpoint.ipv4.startsWith('169.254.')||!Number.isInteger(endpoint.port)
   ||endpoint.port<1024||endpoint.port>65535||endpoint.port===48731)refuse();
 }
 private live(now:number){
  if(!Number.isSafeInteger(now)||now<this.lastNow||now<this.scope.startedAt||now>=this.scope.deadline){this.state='closed';refuse();}
  this.lastNow=now;
 }
 begin(input:NoKeyBrowserProbeInputs,now:number):void{
  if(this.state!=='unopened'){this.state='closed';refuse();}this.state='closing';
  try{
   this.live(now);
   if(!exact(input,['modulePin','contractPin','config']))refuse();
   for(const[key,name,digest]of[['modulePin','browser-probes.mjs',BROWSER],['contractPin','contract.mjs',CONTRACT]]as const){
    const p=input[key];if(!exact(p,['path','sha256'])||typeof p.path!=='string'||!p.path.startsWith('/opt/')
     ||!/^\/[A-Za-z0-9_./-]+$/.test(p.path)||path.posix.normalize(p.path)!==p.path||path.posix.basename(p.path)!==name||p.sha256!==digest)refuse();
   }
   if(path.posix.dirname(input.modulePin.path)!==path.posix.dirname(input.contractPin.path))refuse();
   const c=input.config;
   if(!exact(c,['schema','purpose','runId','startedAt','deadline','authoritySha256','launcherSha256','probeLauncherSha256','profileMountPath','extensionId','controller','network'])
    ||c.schema!==1||c.purpose!=='no-key-boundary-probes'||c.runId!==this.scope.runId||c.startedAt!==this.scope.startedAt
    ||c.deadline!==this.scope.deadline||c.extensionId!==this.scope.extensionId||!hash(c.authoritySha256)||!hash(c.launcherSha256)
    ||!hash(c.probeLauncherSha256)||c.profileMountPath!=='/run/zunder-wallet-'+this.scope.runId)refuse();
   const controller=c.controller;
   if(!exact(controller,['pid','birth','anonymousFd','netnsFd','canarySha256'])||!Number.isSafeInteger(controller.pid)||controller.pid<=1
    ||typeof controller.birth!=='string'||!/^\d+$/.test(controller.birth)||!hash(controller.canarySha256)
    ||![controller.anonymousFd,controller.netnsFd].every(fd=>Number.isInteger(fd)&&fd>=5&&fd<=1024)
    ||controller.anonymousFd===controller.netnsFd)refuse();
   if(!exact(c.network,['proxyIpv4','proxyPort','deniedPort'])||c.network.proxyIpv4!==this.endpoint.ipv4
    ||c.network.proxyPort!==this.endpoint.port||c.network.deniedPort!==48731)refuse();
   const port=':48731',suffix='/no-key/'+this.scope.runId;
   this.targets=Object.freeze([this.endpoint.ipv4+port,'no-key-'+this.scope.runId+'.invalid:443',
    'http://'+this.endpoint.ipv4+port+suffix,'http://127.0.0.1'+port+suffix,
    'http://[::1]'+port+suffix,'http://[2001:db8::1]'+port+suffix]);
   this.counts=Array(6).fill(0);this.state='open';
  }catch{this.state='closed';refuse();}
 }
 /** true means ONLY send the existing denial. Never forward or establish TLS.
  * false means main must take its ordinary irreversible HOLD path. */
 expectedDenial(request:NoKeyDenialRequest,now:number):boolean{
  try{
   this.live(now);if(this.state!=='open'||!exact(request,['kind','method','target','rawHeaders','headLength','bodyLength','trailersLength']))refuse();
   const connect=request.kind==='connect';
   if((!connect&&request.kind!=='outer')||request.method!==(connect?'CONNECT':'GET')
    ||request.headLength!==0||request.bodyLength!==0||request.trailersLength!==0)refuse();
   const index=this.targets.indexOf(request.target);
   if(index<0||(connect?index>=2:index<2))refuse();
   const raw=request.rawHeaders;
   if(!Array.isArray(raw)||raw.length>64||raw.length%2||raw.some(v=>typeof v!=='string')
    ||raw.reduce((n,v)=>n+Buffer.byteLength(v),0)>8192)refuse();
   const headers=new Map<string,string>(),allowed=connect?CONNECT_HEADERS:GET_HEADERS;
   for(let i=0;i<raw.length;i+=2){
    const key=raw[i]!.toLowerCase(),value=raw[i+1]!;
    if(!/^[a-z0-9-]+$/.test(key)||headers.has(key)||!allowed.has(key)||/[^\x20-\x7e]/.test(value))refuse();headers.set(key,value);
   }
   const authority=connect?request.target:request.target.slice(7,request.target.indexOf('/',7));
   if(headers.get('host')!==authority||(headers.has('proxy-connection')&&headers.get('proxy-connection')!=='keep-alive')
    ||(headers.has('connection')&&!['keep-alive','close'].includes(headers.get('connection')!)))refuse();
   if(headers.has('origin')&&!['https://staging.zunderlabs.com','chrome-extension://'+this.scope.extensionId].includes(headers.get('origin')!))refuse();
   if(headers.has('referer')&&headers.get('referer')!=='https://staging.zunderlabs.com/approve')refuse();
   const count=this.counts[index];if(this.total>=24||count===undefined||count>=4)refuse();
   this.total++;this.counts[index]=count+1;return true;
  }catch{this.state='closed';return false;}
 }
 beginClosing(now:number):void{try{this.live(now);if(this.state!=='open')refuse();this.state='closing';}catch{this.state='closed';refuse();}}
 finish(now:number){try{this.live(now);if(this.state!=='closing')refuse();this.state='closed';return this.snapshot();}catch{this.state='closed';refuse();}}
 close():void{this.state='closed';}
 snapshot(){return Object.freeze({state:this.state,total:this.total,counts:Object.freeze([...this.counts])});}
}
