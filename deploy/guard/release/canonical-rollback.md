# Proposed C2 canonical rollback operation

This extends storage publication without changing either signed schema or any release asset.
The parent release owner must incorporate this operation into C2 and request deployment of
both the public store implementation and the private publication proxy route.

Authenticated `POST /guard/restore` accepts exactly `expected` and `restore`, both lowercase
SHA256 strings. `expected` identifies the current canonical **withdrawn** capsule.
`restore` identifies the exact promoted canonical capsule replaced by that build's promotion.
The same `INSTALLER_PUBLISH_TOKEN` protects this route. Its body is capped at 1024 bytes.

The store archives every accepted capsule by predicate digest and records the prior canonical
promoted capsule at promotion. A restore atomically requires the exact channel CAS head,
that withdrawal's matching durable build head, its archived promoted predecessor, the recorded
prior canonical digest, and a prior target whose own durable build head remains promoted.
It returns HTTP 201 with that restored digest; stale CAS, arbitrary targets, replay,
unavailable targets and any attempt to restore before withdrawal return 409.

Restore serves the original prior predicate, bundle and loader bytes. The failed build's
withdrawn lifecycle and archive remain intact. This is a channel rollback, not a lifecycle
revision decrement. The target was authenticated at its original publication; restoration
admits no caller-supplied replacement capsule or loader. Consumers see the old authenticated
capsule's original `x-zunder-state-sha256` across all four canonical paths.

A first stable release has no prior promoted capsule: automatic rollback publishes its signed
withdrawal and keeps canonical loaders unavailable (HTTP 410). There is no null-head restore
and no fabricated fallback. HTTP uncertainty requires a fresh durable-head read before any
subsequent action; never blindly replay a publication or restore request.
