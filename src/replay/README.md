# M-05 Replay

Reserved scaffolding. **No implementation yet.**

This directory will hold M-05 (Replay), scheduled for Phase 5 of
the Astra roadmap (deterministic byte-for-byte replay of a checkpointed
process). The single-thread, IPC-only slice of M-05 is on the critical
path for Paper 3 (AgentGuard); see
[docs/PUBLICATION_STRATEGY.md](../../docs/PUBLICATION_STRATEGY.md).

Any "deterministic replay" claim that depends on this module should be
treated as future work, not a capability of the current codebase.
