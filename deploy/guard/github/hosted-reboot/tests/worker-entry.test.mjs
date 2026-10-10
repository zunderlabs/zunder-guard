import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker-entry.mjs';

test('standalone receipt Worker returns 404 outside its fixed prefix without any binding access',async()=>{
  const environment=new Proxy({}, {get(){throw new Error('Outside routes cannot access bindings');}});
  for(const path of ['/', '/api/waitlist/', '/api/customer', '/api/waitlist/ci-rebootish']) {
    const response=await worker.fetch(new Request('https://receipt-fixture.invalid'+path),environment);
    assert.equal(response.status,404);
  }
});
test('standalone receipt Worker missing scope refuses before receipt database access',async()=>{
  const response=await worker.fetch(new Request('https://receipt-fixture.invalid/api/waitlist/ci-reboot/scope'),{DB:{withSession(){throw new Error('Missing scope must not access DB');}}});
  assert.equal(response.status,409);
});
