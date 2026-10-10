import { Admission, fail } from "./policy.ts";
/** Actual supervisor terminal transitions, with no custody material in this closure. */
export function createCustodySafety(
  admission: Admission,
  io: {
    hasChildren: () => boolean;
    cleanupComplete: () => boolean;
    stopChildren: () => Promise<void>;
    readEmpty: () => Promise<void>;
    readReturned: () => Promise<void>;
  },
) {
  let stopping = false,
    stopUncertain = false,
    pending: Promise<void> | undefined;
  return Object.freeze({
    hold(unknown = true) {
      admission.hold(unknown);
      if (unknown && io.hasChildren() && !stopping) {
        stopping = true;
        try {
          pending = io
            .stopChildren()
            .catch(() => {
              stopUncertain = true;
              admission.hold(true);
            })
            .finally(() => {
              stopping = false;
            });
        } catch {
          stopUncertain = true;
          stopping = false;
          admission.hold(true);
        }
      }
    },
    async proveEmpty() {
      admission.hold();
      if (io.hasChildren() || stopUncertain) fail();
      await io.readEmpty();
      if (io.hasChildren() || stopUncertain) fail();
    },
    async beforeDispose(returned: boolean) {
      admission.hold();
      if (pending) await pending;
      if (io.hasChildren() || stopUncertain || !io.cleanupComplete()) fail();
      await (returned ? io.readReturned() : io.readEmpty());
      if (io.hasChildren() || stopUncertain || !io.cleanupComplete()) fail();
    },
    status: () => ({ stopping, stopUncertain }),
  });
}
