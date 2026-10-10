import handler from '../../waitlist/src/testnet-inbox.ts';
import {leaseActive,type Lease} from './lease.ts';
import type {InboxEnv} from '../../waitlist/src/testnet-inbox.ts';
export default{
 async fetch(r:Request,e:InboxEnv&Lease){return leaseActive(e)?handler.fetch(r,e):new Response('Rehearsal unavailable',{status:404});},
 async email(m:Parameters<typeof handler.email>[0],e:InboxEnv&Lease){if(leaseActive(e))await handler.email(m,e);else m.setReject('Rehearsal unavailable');},
 async scheduled(c:unknown,e:InboxEnv&Lease){if(leaseActive(e))await handler.scheduled(c,e);},
};
