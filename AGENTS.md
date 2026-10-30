# Mandatory operating instructions for every agent

**STOP: Read this file before inspecting, editing, testing, reviewing, or proposing changes.**

1. Read the canonical [NGL shared Ralph-style operating protocol](https://github.com/ngl-damien/No-Gas-Labs-Alpha-1/blob/main/docs/operations/RALPH_SHARED_HOURLY_SCHEDULER_PROTOCOL.md) in full. If unavailable, stop and report the blocker.
2. Inspect this repository's README and relevant local documentation before acting. For relay work, read `integration/relay/README.md` and inspect its source/tests.
3. Preserve the evidence distinction between recovered artifacts, extracted source, executable bridge, tests, and a complete Android runtime. This checkout is not thereby a full Android rebuild or full mesh runtime.
4. Preserve the distinction between UUID artifact identity and SHA-256 content hashes. Do not silently replace one with the other or claim a hash proves truth, safety, authorship, or authority.
5. Rehydrate from current branches, open PRs, tests, and the latest durable checkpoint. Inspect other NGL workers' latest results when accessible; avoid duplicate work and leave concrete handoffs.
6. Make bounded changes on a dedicated branch. Prefer reuse over copying. Keep additional cost at $0 unless Damien explicitly authorizes otherwise.
7. Verify the exact changed commit with relevant tests and hosted checks. Report exact commands, commit, results, limitations, and unknowns. A model assertion is not evidence.
8. Do not merge, release, deploy, publish externally, spend, change secrets/credentials/permissions, or take destructive/irreversible actions without explicit authorization from Damien Featherstone.
9. Preserve failed attempts and uncertainty. Before finishing, leave a durable factual record and next action.

## If instructions conflict
This file and the canonical NGL protocol govern evidence, safety, coordination, and founder authority. More specific local documentation may add technical constraints but cannot weaken them.
