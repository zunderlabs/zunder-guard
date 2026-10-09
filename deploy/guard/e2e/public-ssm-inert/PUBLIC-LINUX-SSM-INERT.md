# Public Linux Go transport gate

Run only the exact reviewed r5 Go test package on a free GitHub-hosted Linux
AMD64 runner. This source does not run on the Mac, compile Rust or run the
transport wrapper's `main`. No AWS/venue/SSM action, live socket, private input,
provider credential or user GitHub credential belongs in this gate.

The fixed source pins both Go files to r5 manifest6469d812584ab0d7ed0a2208b608c5969cd407d6bf8adabf038192567203df7e
and review798b4fe53d593a8042b64d0279014f74d877654a804636d12adbb642aca6e8c6.
All twelve test functions were read: public JSON/log/port/ACK/mux/clock fixtures,
fake sockets/dial, and same-test-binary refusal subprocesses. No TestMain,
actual network dial, live SDK client or wrapper main is invoked by those tests.
The runtime test child also has a Linux AMD64 seccomp filter that refuses
socket/socketpair creation, inherits across its refusal subprocess execs, rejects
other ABIs, and is installed without privilege. Failure to install it fails the
test stage. Only stdin null, bounded output pipes and the clean explicit Go
environment are inherited; private/provider homes and credentials are absent.

Only two public HTTPS downloads occur: fixed AWS plugin source commit7cde6748cc6cffbc69546b4de08e603cd39be6d8
from codeload.github.com and exact Go1.27.2 LinuxAMD64 from dl.google.com. Native
TLS verifies the fixed hosts; no proxy, auth, cookies, retries or redirects.
Exact SHA256/length pins and caps are checked before extraction. Compiler row
was verified against [official Go metadata](https://go.dev/dl/?mode=json):
70590635B, SHAecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5.

Safe extraction permits only regular files/directories beneath the exact archive
prefix, rejects traversal/links/devices/sparse/duplicates, caps entries and
logical bytes, ignores archive ownership, creates fresh exclusive files and
retains public inventory digests. Private owned scratch/tool/home/cache/temp
directories isolate the official compiler; existing global Go/cache paths stay
untouched. Exact SDK `vendor/src` compatibility is retained in GOPATH.
CGO0, GO111MODULEoff, GOPROXYoff, GOSUMDBoff, GOTOOLCHAINlocal, GOWORKoff and
two compiler processes are fixed. The compiler builds `go test -c`; only that
test binary runs. Each expected test must pass exactly once.

The standalone invocation has one original 15-minute UTC/monotonic/SIGALRM
budget covering download/extraction/compile/tests. The job maximum is20minutes.
Compile/test children are bounded, output is capped at4MiB, failures are generic
and public logs/receipt survive. Source-only checks in this author bank cover
Python syntax, tar attacks/caps, pinned Go files/test names, original clock
expiry and public BPF simulation. They do not execute seccomp, Go or SDK code.

The workflow template is intentionally unbound and cannot admit a run. Root must
register the exact source/candidate files, bind the reviewed script SHA, have
the complete rendered workflow independently
reviewed, then push/dispatch under the existing outward-action approvals.
Dispatch must supply the actual reviewed immutable control SHA; the first step
requires that exact event SHA before checkout/download. The default unbound
value refuses admission. This avoids a self-referential commit SHA in the source.
Default contents-read and checkout `persist-credentials:false`; no secrets,
OIDC, environments, AWS role or wallet setup. Artifact upload uses the standard
runner token outside the clean compiler/test environment. Actual workflow/run/
attempt/head/artifact/test receipt must be authenticated before accepting the
gate. This gate alone grants no full native or release acceptance.

## r2 original group cleanup repair

The command helper retains its original direct child unreaped with `waitid`
`WNOWAIT` until unconditional original process-group cleanup. The reserved
leader PID prevents reuse of that group identity before the single `SIGKILL`,
including successful or failed direct-parent exit ahead of descendants. It then
reaps the direct child and requires group disappearance within a fixed five-second
cleanup-only bound. Probe failure or surviving/unknown group state fails the gate.
The original UTC/monotonic command deadline is unchanged. Public harmless Python
fixtures exercise successful exit, failed exit and command expiry with a same-group
sleeper; they execute no Go/compiler/SDK/main, sockets, seccomp or credentials.
