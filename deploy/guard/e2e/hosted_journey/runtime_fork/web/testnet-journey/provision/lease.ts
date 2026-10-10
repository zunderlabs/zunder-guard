// New wrapper around frozen handlers: remote work stops even if the local controller dies.
export interface Lease { TESTNET_LEASE_START?: string; TESTNET_LEASE_END?: string }
export function leaseActive(env:Lease, now=Date.now()):boolean{
  if(!/^\d{13}$/.test(env.TESTNET_LEASE_START??'')||!/^\d{13}$/.test(env.TESTNET_LEASE_END??''))return false;
  const start=Number(env.TESTNET_LEASE_START),end=Number(env.TESTNET_LEASE_END);
  return Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&end>start&&end-start<=1200000&&now>=start&&now<end;
}
type Incoming={setReject(reason:string):void};
type Handler<E>={fetch?:(r:Request,e:E)=>Promise<Response>;email?:(m:Incoming,e:E)=>Promise<void>;scheduled?:(c:unknown,e:E,ctx:unknown)=>Promise<void>};
export function leased<E extends Lease>(handler:Handler<E>){return{
  async fetch(r:Request,e:E){return leaseActive(e)&&handler.fetch?handler.fetch(r,e):new Response('Rehearsal unavailable',{status:404,headers:{'cache-control':'no-store'}});},
  async email(m:Incoming,e:E){if(!leaseActive(e)||!handler.email){m.setReject('Rehearsal unavailable');return;}await handler.email(m,e);},
  async scheduled(c:unknown,e:E,ctx:unknown){if(leaseActive(e)&&handler.scheduled)await handler.scheduled(c,e,ctx);},
};}
