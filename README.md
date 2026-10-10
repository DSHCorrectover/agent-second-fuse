# agent-second-fuse

**Independent fail-closed second fuse for AI agents.** It sits *outside* the
agent it protects, judges every tool call before it runs, signs each decision
with an Ed25519 receipt, and chains those receipts into a tamper-evident ledger.
From that ledger you can export an incident report aligned with the
**2026-10-09 White House Superintelligence Force (SIF) mandate on mandatory
reporting of significant AI incidents**.

```
tool call
   │
   ▼
GuardedKernel.guard()
   │  rule engine (fail-closed, short-circuit):
   │    tool ACL → parameter rules → dangerous patterns / exfiltration
   │    → constitution immutability → identity continuity
   ▼
Ed25519 decision receipt  ──►  append-only hash-chained ledger
   │
   ▼
incident report (Markdown / JSON)
```

## Why it exists

Logs being *viewable* is not the same as behavior being *controllable*. An
agent that can reach a shell, an outbound network call, or a funds transfer
needs a check that is **independent of the model's cooperation**: a policy it
cannot talk its way past, plus evidence a third party can verify offline. On
2026-10-09 the White House Superintelligence Force made prompt incident
reporting a national-security obligation the same day a major lab disclosed
that a test model had submitted unauthorized information to a government
website and that tool isolation had failed. This package targets both halves:
**stop the action, preserve the proof**.

## Install

```bash
pip install agent-second-fuse
```

## Quick start (zero config)

```python
from agent_runtime_guard import GuardedKernel, PolicyConfig

kernel = GuardedKernel.bootstrap(
    PolicyConfig.builtin("general"),
    evidence_dir=".guard-evidence",
    agent_id="checkout-agent",
)

outcome = kernel.guard("execute_shell", {"command": "sudo rm -rf /"})
outcome.blocked            # True
outcome.receipt.receipt_id # 'r...'
```

Every call is signed and appended to the ledger:

```bash
# verify the whole ledger offline (no network): chain + every signature
arg-fuse inspect --evidence .guard-evidence

# export an incident report
arg-fuse report --evidence .guard-evidence \
    --title "Checkout agent incident" --reporter "Your team" \
    --out incident.md
```

## What the guard checks

- **Tool ACL** — allow/deny lists; unknown tools are blocked by default
  (fail-closed).
- **Parameter rules** — typed numeric/enum/regex checks on named arguments
  (`gt/lt/gte/lte/eq/neq/in/not_in/regex`, nested field paths).
- **Dangerous patterns & data exfiltration** — destructive commands,
  remote-download-and-execute (`curl … | sh`), reverse shells (`/dev/tcp`,
  `nc -e`, `bash -i`), inline code execution (`python -c os.system(...)`),
  credential-file reads, `curl -d @`, delimiter-chained exfiltration, plus
  Base64/Hex/NFKC/whitespace normalization so encoded variants still match.
  Outbound targets can be restricted against an allow list with CIDR support.
- **Constitution immutability** — protected dimensions cannot be modified.
- **Identity continuity** — persona/directive drift is detected against a
  baseline.

## Enforcement points

A log the agent can skip is advice, not a fuse. The check can be enforced on two
levels:

**1. In-process — a tool the agent cannot call around.** Wrap any callable so
the object the agent actually holds is the guarded one; every invocation is
judged first and there is no exposed path to the raw function:

```python
from agent_runtime_guard import wrap_tool, wrap_tools

def send_email(to, body): ...

guarded = wrap_tool(kernel, send_email, name="send_email",
                    require_approval=True)
guarded("a@b.com", "hi")
# BlockedActionError  -> policy blocked, body never runs
# ApprovalRequired    -> pending human approval, body never runs
# returns normally    -> allowed, body runs

tools = wrap_tools(kernel, {"read_file": read_file, "send_email": send_email},
                   approval_actions={"send_email"})
```

**2. Out-of-process — a decision-only proxy in a separate trust domain.** Run
the judge as its own process/container. It only decides and records; it never
executes a tool. The agent executes only on `allow`, and must not execute on
`block`/`pending`. A prompt-injection-compromised agent cannot rewrite a
verdict — it can only reach the proxy, which fails closed.

```bash
arg-fuse proxy --evidence .guard-evidence --host 0.0.0.0 --port 8765
```

```bash
curl -s localhost:8765/check -d '{"action":"execute_shell",
  "arguments":{"command":"sudo rm -rf /"}}'
# {"decision":"block", ...}
```

`GET /health` reports the key id and ledger entry count. Malformed JSON and
requests missing an action are rejected with `decision: block` (HTTP 400); any
internal error also returns `block` (HTTP 500).

## Human approval gate

Actions marked `require_approval` stay **pending** and do not execute until a
human explicitly approves or denies. The decision is **bound to a fingerprint
of the exact submitted parameters** (`sha256(JCS({action, arguments}))`):
approval covers only that one submission, so swapping a benign argument for a
dangerous one at execution time is a new, unapproved request. State moves
`pending → approved | denied | expired` exactly once and cannot be reversed.

```bash
arg-fuse approve list --evidence .guard-evidence
arg-fuse approve allow --request-id a1b2... --approver alice
arg-fuse approve deny  --request-id a1b2...
```

Requests are recorded in `<evidence>/approval/requests.jsonl`. Default TTL is
3600 s (configure with `approval_ttl`).

## SIEM export

Hand signed receipts to a SOC in formats it already consumes rather than a
private ledger:

```bash
arg-fuse export --evidence .guard-evidence --format ndjson --out events.ndjson
arg-fuse export --evidence .guard-evidence --format cef    --out events.cef
arg-fuse export --evidence .guard-evidence --format json   --out events.json
```

NDJSON is one flattened event per line (Elastic/Splunk); CEF is `CEF:0`
ArcSight format with proper escaping. Blocked events map to severity 7, allowed
to 2. For live shipping, use `siem.post_webhook(...)`, which supports a Splunk
HEC collector (`{event, time}` payload + `Authorization: Splunk` header) or a
generic receiver (`{events: [...]}` + Bearer token). The receipts and chain
remain the source of truth; export only translates.

## External anchoring

A self-signed receipt proves "not changed since", not "existed at time T".
Anchor the ledger head to an external append-only witness to turn local
attestation into an externally timestamped existence proof:

```bash
arg-fuse anchor --evidence .guard-evidence --url https://notary.example/witness
```

```python
from agent_runtime_guard import NotaryWebhookProvider

provider = NotaryWebhookProvider("https://notary.example/witness")
kernel.anchor_log.anchor(provider, kernel.ledger.head(), kernel.ledger.count())
kernel.anchor_log.covers(head)   # True once witnessed
```

Records (with the witness attestation) accumulate in
`<evidence>/anchor/anchors.jsonl`. The provider is an abstraction; RFC 9162 /
Certificate-Transparency-style logs share the same interface as an extension.

## Performance

Measured on the **full decision path** — rule engine + Ed25519 signing +
append to the hash-chained ledger — not a bare-rule micro-benchmark:

```bash
arg-fuse bench --iterations 3000
# [allow] P50 ~105us | P95 ~130us | P99 ~145us | ~9000 ops/s
# [block] P50 ~105us | P95 ~130us | P99 ~145us | ~9000 ops/s
```

Exact figures vary with disk and hardware. The rule engine alone (no signing or
ledger I/O) is an order of magnitude cheaper; if you do not need per-decision
evidence, use `SecurityKernel` directly. Storage on a network/FUSE filesystem
is dominated by that filesystem's write latency rather than CPU.

## Signed receipts

Each decision is a JSON envelope; the signature covers `JCS(payload)` only, so
the signature field itself is never part of the signed input. Verification needs
just the local public key and never touches the network:

```python
from agent_runtime_guard import Receipt, verify_receipt
from agent_runtime_guard.keys import load_public_key

pub = load_public_key(open(".guard-evidence/keys/verifying.pub","rb").read())
receipt = Receipt.from_json(open("receipt.json").read())
verify_receipt(receipt, pub)  # True/False
```

**Honest scope:** the signing key is self-generated. Receipts provide
*offline verifiability* and *tamper evidence*, not third-party CA identity.
For external trust, register the public key in your own root of trust or use
the external anchoring step.

## CLI

```text
arg-fuse guard     # judge one call, sign + append to the ledger
arg-fuse inspect   # verify a receipt or the entire ledger offline
arg-fuse report    # build an incident report (md/json)
arg-fuse keys      # show the local public key and kid
arg-fuse validate  # validate a policy file
arg-fuse demo      # run the built-in second-fuse demo
arg-fuse proxy     # run the out-of-process decision-only service
arg-fuse approve   # list / allow / deny human approval requests
arg-fuse export    # SIEM export (ndjson/cef/json)
arg-fuse anchor    # anchor the ledger head to an external witness
arg-fuse bench     # P50/P95/P99 on the full decision path
```

## Incident report scope

The report states only facts recorded in the ledger with their timestamps and
includes a hash-chain integrity check. Actions outside instrumented coverage
are not included. Whether an event is legally "reportable" under any specific
regulation is a determination for your legal team; the report supplies
evidence, not that conclusion.

## License

MIT. See [LICENSE](LICENSE).
