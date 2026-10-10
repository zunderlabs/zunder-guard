// Root-native transport only; PrivateProxyPolicy admits every request before this call.
// No redirects, browser/global headers, proxy env, custom CA, retry or injectable transport.
import https from 'node:https';import type {Socket} from 'node:net';
import {PolicyError,STAGING_HOST,type Transport,type UpstreamRequest} from './proxy-policy.ts';
import type {CanonicalProxyAccess} from './proxy-access.ts';
export function makeRootUpstream(sockets:Set<Socket>,state:{active:number},access:CanonicalProxyAccess):Transport{
 return nativeTransport(sockets,state,access,()=>({}));
}
/** Closed root-only backend ABI. Never accepts URLs or a caller header bag. */
export type ProtectedStagingRequest =
 | {kind:'asset';path:string}
 | {kind:'status'}
 | {kind:'customer';action:'quote'|'order'|'check';body:Buffer}
 | {kind:'issuer-jobs';token:Buffer}
 | {kind:'issuer-deliver';token:Buffer;order:string;body:Buffer}
 | {kind:'inbox';token:Buffer;body:Buffer};
export function makeProtectedStagingUpstream(sockets:Set<Socket>,state:{active:number},access:CanonicalProxyAccess){
 return async(input:ProtectedStagingRequest,signal:AbortSignal,max:number)=>{
  const keys=Object.keys(input).sort().join(',');let path:string,method:'GET'|'POST',body:Buffer|undefined;
  const headers:Record<string,string>={};
  switch(input.kind){
   case 'asset':
    if(keys!=='kind,path'||!/^\/(?:[A-Za-z0-9_./-]*)$/.test(input.path)||input.path.includes('..')||input.path.includes('//')||input.path.startsWith('/api/'))throw new PolicyError('request');
    path=input.path;method='GET';break;
   case 'status':if(keys!=='kind')throw new PolicyError('request');path='/api/licence/status';method='GET';break;
   case 'customer':
    if(keys!=='action,body,kind'||!['quote','order','check'].includes(input.action))throw new PolicyError('request');
    path=input.action==='check'?'/api/licence/order/check':'/api/licence/'+input.action;method='POST';body=input.body;
    headers.origin='https://'+STAGING_HOST;headers['content-type']='application/json';break;
   case 'issuer-jobs':
   case 'issuer-deliver':
   case 'inbox':{
    const expected=input.kind==='issuer-jobs'?'kind,token':input.kind==='issuer-deliver'?'body,kind,order,token':'body,kind,token';
    if(keys!==expected||!Buffer.isBuffer(input.token)||!/^[A-Za-z0-9_-]{43,128}$/.test(input.token.toString('ascii'))||!Buffer.from(input.token.toString('ascii')).equals(input.token))throw new PolicyError('request');
    headers.authorization='Bearer '+input.token.toString('ascii');
    if(input.kind==='issuer-jobs'){path='/api/licence/testnet-issuer/jobs';method='GET';}
    else if(input.kind==='issuer-deliver'){
     if(!/^ZL-\d{4}-\d{6}$/.test(input.order))throw new PolicyError('request');
     path='/api/licence/testnet-issuer/deliver?order='+input.order;method='POST';body=input.body;headers['content-type']='text/plain';
    }else{path='/api/testnet-inbox/messages';method='POST';body=input.body;headers['content-type']='application/json';}
    break;
   }
   default:throw new PolicyError('request');
  }
  if(body!==undefined&&(!Buffer.isBuffer(body)||body.length<1||body.length>8192)||!Number.isInteger(max)||max<1||max>8*1024*1024)throw new PolicyError('request');
  return nativeTransport(sockets,state,access,()=>headers)({host:STAGING_HOST,path,method,...(body?{body}:{})},signal,max);
 };
}
function nativeTransport(sockets:Set<Socket>,state:{active:number},access:CanonicalProxyAccess,extra:(input:UpstreamRequest)=>Record<string,string>):Transport{
 return async(input,signal,max)=>{
  state.active++;
  try{return await new Promise((resolve,reject)=>{
   let settled=false;
   const fail=()=>{if(!settled){settled=true;reject(new PolicyError('transport'));}};
   try{
    const request=https.request({
     hostname:input.host,servername:input.host,port:443,path:input.path,
     method:input.method,rejectUnauthorized:true,minVersion:'TLSv1.2',agent:false,signal,maxHeaderSize:8192,
     headers:{host:input.host,'accept-encoding':'identity',connection:'close',
      ...(input.method==='POST'?{'content-type':'application/json','content-length':String(input.body?.length??0)}:{}),
      ...extra(input),
      // Last synchronous option evaluation invokes original authority + frozen header admission.
      ...access.forUpstream({protocol:'https:',host:input.host,port:443}),
     },
    },response=>{
     const chunks:Buffer[]=[];let length=0;
     response.on('data',(chunk:Buffer)=>{length+=chunk.length;if(length>max){request.destroy();fail();return;}chunks.push(chunk);});
     response.once('aborted',fail);response.once('error',fail);
     response.once('end',()=>{if(settled)return;try{const body=Buffer.concat(chunks,length);if(input.host===STAGING_HOST)access.assertNoReflection(body);settled=true;resolve({status:response.statusCode??0,headers:response.headers,body});}catch{fail();}finally{chunks.length=0;}});
    });
    request.once('socket',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
    const timer=setTimeout(()=>{request.destroy();fail();},10_000);
    request.once('error',fail);request.once('close',()=>clearTimeout(timer));
    if(input.body)request.end(input.body);else request.end();
   }catch{fail();}
  });}finally{state.active--;}
 };
}
