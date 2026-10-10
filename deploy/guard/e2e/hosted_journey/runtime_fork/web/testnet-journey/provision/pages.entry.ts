import handler,{type TestnetPagesEnv} from '../../waitlist/src/testnet-pages.ts';
import {leaseActive,type Lease} from './lease.ts';
export default{async fetch(r:Request,e:TestnetPagesEnv&Lease){return leaseActive(e)?handler.fetch(r,e):new Response('Rehearsal unavailable',{status:404});}};
