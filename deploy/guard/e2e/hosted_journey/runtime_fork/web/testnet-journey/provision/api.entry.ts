import handler from '../../waitlist/src/testnet-index.ts';
import {leaseActive,type Lease} from './lease.ts';
import type {TestnetEnv} from '../../waitlist/src/testnet-journey.ts';
import type {ScheduledController,ExecutionContext} from '../../waitlist/src/platform.ts';
export default{
 async fetch(r:Request,e:TestnetEnv&Lease){return leaseActive(e)?handler.fetch(r,e):new Response('Rehearsal unavailable',{status:404});},
 async scheduled(c:ScheduledController,e:TestnetEnv&Lease,ctx:ExecutionContext){if(leaseActive(e))await handler.scheduled(c,e,ctx);},
};
