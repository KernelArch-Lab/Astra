# formal/cbmc — bounded model checking

Reserved scaffolding. **No proofs yet.**

The first real proof landing here will be `capability_monotonicity.c` —
a CBMC bounded-model-check that derived capability tokens never carry
more permissions than their parent. This is on the critical path for
Paper 1 (USENIX ATC 2027); see
[../../docs/PUBLICATION_STRATEGY.md](../../docs/PUBLICATION_STRATEGY.md).

Any broader "formal verification" claim that depends on this directory
should be treated as future work, not a capability of the current
codebase.
