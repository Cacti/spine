# Copilot instructions for Spine

Read and follow the existing [Spine coding instructions](instructions/instructions.md)
for language, build, process execution, testing, and contribution requirements.
The following rules also apply when fixing defects.

## Maintenance fix scope

Keep maintenance fixes focused on the reported defect and preserve branch compatibility.

- Before adding persistent caches, staging tables, locks, shutdown handlers, or invalidation hooks across APIs, show why the existing mechanism cannot support the fix. Use a concrete failure case from the target branch's implementation and its callers.
- Identify the authoritative data, the derived result, and the exact operations that can change that result. Add invalidation hooks only for those operations. A component that reads or combines existing data does not automatically own its lifecycle.
- If a cache design requires hooks across unrelated subsystems, reconsider the cache design before expanding the patch. Do not use dependencies introduced by the proposed design as proof that the original bug requires that scope.
- Keep architectural changes in a separate proposal unless required for correctness. Before expanding a focused fix across unrelated subsystems, explain the dependency with a concrete example and the smallest viable alternative. Continue work already within scope.
- Tests must validate intended product behavior and realistic failures. Passing tests or tests that require every proposed hook do not establish that the design or expanded scope is necessary.
- For maintenance branches such as `1.2.x`, prefer the smallest compatible fix. Avoid unrelated refactors, new dependencies, and expanded CI requirements.
