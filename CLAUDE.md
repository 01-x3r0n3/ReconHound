# CLAUDE.md — ReconHound Operating Rules

This file defines **how** Claude Code works on this repository. For **what**
ReconHound is (architecture, modules, data model, design principles, build
order, current status), see `context.md` — the authoritative architectural
reference. Do not duplicate its contents here; consult it directly.

## Working rules

1. Read and respect `context.md` before making any substantive ReconHound
   change.
2. Treat the architecture in `context.md` as the current project design.
   Do not arbitrarily redesign, replace, simplify, or add architectural
   components.
3. Work incrementally: implement **one module at a time**, following the
   build order in `context.md`.
4. Test the current module and verify its behavior before moving to the
   next one.
5. Do not modify unrelated modules or files merely for convenience.
6. Preserve ReconHound's core philosophy: correlation over isolated
   scanners.
7. Preserve the evidence, confidence, negative-result-memory,
   conflict-preservation, attack-surface-path, adaptive-discovery,
   decision-queue, and relationship-based-prioritization concepts whenever
   implementing functionality that touches them.
8. Preserve crash-safe persistence and meaningful error handling. Never
   silently discard important discoveries or failures.
9. Maintain strict target-scope enforcement. ReconHound is for authorized
   reconnaissance only.
10. Keep reconnaissance distinct from exploitation. Never add exploitation
    functionality.
11. Prefer maintainable, modular Python consistent with the existing
    architecture over unnecessary dependencies or complexity.
12. Do not invent requirements because they seem useful. If a proposed
    change would materially alter the architecture, module responsibilities,
    data model, build order, or project scope: stop, explain the problem,
    the proposed change, and its consequences, and get approval before
    making it.
13. When implementing a specific module, focus on that module. Only touch
    other files when genuinely required for integration or correctness.
14. Clearly distinguish planned vs. implemented vs. tested functionality vs.
    known limitations. Never claim something works without verification.
15. Keep documentation synchronized with meaningful implementation changes
    when appropriate, but don't rewrite docs unnecessarily.
16. Never expose, hardcode, or commit secrets, API keys, credentials,
    tokens, or other sensitive material.
17. When uncertain about an architectural decision, consult `context.md`
    first. If it's undefined there and the decision could materially affect
    the architecture, ask before proceeding.
18. These rules are boundaries, not a reason to refuse legitimate work. Once
    a specific implementation task is given, execute it normally within
    these boundaries.
