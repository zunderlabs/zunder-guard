import {handlePublicReboot} from './relay-worker.mjs';

// A dedicated receipt-only Worker. No customer route or signing authority.
export default {
  async fetch(request,environment) {
    const result=await handlePublicReboot(request,environment);
    return result ?? new Response('Not found',{status:404,headers:{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}});
  },
};
