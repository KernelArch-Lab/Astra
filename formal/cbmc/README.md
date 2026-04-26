# formal/cbmc — capability monotonicity proof

CBMC bounded model check that the central security invariant of M-01's
`CapabilityManager::derive()` holds: a derived token's permissions are
always a subset of its parent's.

This is the formal-verification "partial" claim in the public
[Astra comparison table](https://kernelarch.com/#/astra). It's also
the only proof obligation Paper 1 (USENIX ATC 2027) commits to landing
before submission.

## Run it

```
cd formal/cbmc
make verify
```

Requires CBMC ≥ 5:
- Fedora: `sudo dnf install cbmc`
- Ubuntu: `sudo apt install cbmc`

Expected output:
```
[CBMC] proving capability monotonicity...
... CBMC progress messages ...
VERIFICATION SUCCESSFUL
[CBMC] PASS — capability monotonicity holds.
```

If the proof fails:
```
make verify-trace
```
will dump a counterexample trace showing the input that breaks the
invariant. Any failure means either the C model has drifted from
[src/core/capability.cpp](../../src/core/capability.cpp), or the
production code has a real bug.

## What's proven

Three properties, on a C-flat model of `derive()` that mirrors the
arithmetic in [`capability.cpp:191-260`](../../src/core/capability.cpp#L191):

1. **Subset on success.** For any parent and any requested perms, if
   `derive()` returns `OK`, then `(child.permissions & ~parent.permissions) == 0`.
2. **Rejection iff escalation or invalid parent.** No other rejection
   paths exist in the model; CBMC will find one if the model drifts
   from production code.
3. **No recovery through a chain.** A two-step derivation root → B → C
   cannot recover any permission bit dropped at the first step.

For each property, CBMC enumerates every reachable execution within
the configured loop unwinding (4) and exploration depth (50,000) and
checks that no `__CPROVER_assert` fires.

## What's NOT proven

- **The C++ implementation matches the C model.** The harness proves
  the model is sound; ensuring `capability.cpp` keeps the same
  arithmetic is the developer's responsibility. CI must re-run
  `make verify` on every PR that touches `src/core/capability.cpp`.
- **Spinlock / slot-pool correctness.** The model strips those for
  tractability; they're orthogonal to the monotonicity property and
  belong to a separate proof obligation if we ever pursue one.
- **Cascading revocation soundness.** Revocation is epoch-based, not
  derivation-tree-walking, so the model would need to grow a clock
  for that. Out of scope for Paper 1.

## CI gate

Once CI runs against the Fedora x86_64 image we use for the rest of
the test matrix, this proof should be wired into the same workflow
as the C++ tests:

```yaml
- name: CBMC proofs
  run: cd formal/cbmc && make verify
```

The job is fast (well under a minute on the proof above); making it a
required check keeps the formal-verification claim defensible.
