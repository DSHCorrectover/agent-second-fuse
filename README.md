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
  `curl -d @`, `nc`, `/dev/tcp`, delimiter-chained exfiltration, plus
  Base64/Hex/NFKC/whitespace normalization so encoded variants still match.
  Outbound targets can be restricted against an allow list with CIDR support.
- **Constitution immutability** — protected dimensions cannot be modified.
- **Identity continuity** — persona/directive drift is detected against a
  baseline.

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
For external trust, register the public key in your own root of trust.

## CLI

```text
arg-fuse guard     # judge one call, sign + append to the ledger
arg-fuse inspect   # verify a receipt or the entire ledger offline
arg-fuse report    # build an incident report (md/json)
arg-fuse keys      # show the local public key and kid
arg-fuse validate  # validate a policy file
arg-fuse demo      # run the built-in second-fuse demo
```

## Incident report scope

The report states only facts recorded in the ledger with their timestamps and
includes a hash-chain integrity check. Actions outside instrumented coverage
are not included. Whether an event is legally "reportable" under any specific
regulation is a determination for your legal team; the report supplies
evidence, not that conclusion.

## License

MIT. See [LICENSE](LICENSE).
