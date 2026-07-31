# EVM Evidence-Lattice Workflow

This workflow turns source inventory into security conclusions without treating
pattern matches as vulnerabilities. It is designed for independent reasoning
passes followed by adversarial challenge and mandatory reporting.

## Evidence levels

| Level | Requirement | Allowed classification |
| --- | --- | --- |
| E0 | Pattern match, intuition, or unsupported hypothesis | Candidate only |
| E1 | Property plus source-connected reachable path | Observation |
| E2 | Complete call/state trace showing a property violation | Finding |
| E3 | Reproducible test, fuzz counterexample, symbolic result, or formal proof | Confirmed finding |

Evidence levels describe support, not severity. A catastrophic-sounding E0 item
is still only a candidate. A source-complete E2 trace may be sufficient when the
semantics are explicit and do not depend on runtime configuration.

## Required system model

Before hunting issues, record:

1. assets and liabilities;
2. privileged and unprivileged actors;
3. trust boundaries and external dependencies;
4. initialization, upgrade, migration, pause, and recovery paths;
5. state machines, sentinels, default mapping values, and one-shot latches;
6. entry-point-to-state read/write relationships;
7. external calls, callbacks, delegatecalls, and token transfers.

For every sentinel or default value, ask whether the same value can also denote
a valid configured state. For every initializer parameter, ask whether the code
rejects values that collapse two security states into one.

For each sentinel/default candidate, enumerate every write site and every read
site before choosing an attack trace. Start from each public/external entry point
that consumes the value and test the shortest path to impact. A reviewer may not
reject the candidate by disproving one proposed path when another consumer can
reach the same security decision without that path.

## Candidate format

Every independent lane emits candidates in this form:

```text
ID: C-<lane>-<number>
Property: <security property that should always hold>
Location: <file:line and function(s)>
Preconditions: <attacker capabilities and state>
Trace: <ordered calls and state transitions, or unresolved step>
Impact: <specific consequence>
Evidence: E0 | E1 | E2 | E3
Disconfirmers: <guards, reverts, authorization, assumptions to verify>
```

## Challenge protocol

The challenger must attempt to reject each proposed finding by checking, in
order:

1. all relevant read sites and the shortest reachability path from an
	attacker-controlled entry point;
2. authorization in modifiers, function bodies, inherited code, and signatures;
3. earlier reverts and state-machine preconditions;
4. checks-effects-interactions ordering and rollback semantics;
5. concrete value movement or security impact;
6. assumptions about deployment, governance, tokens, or external contracts.

Record the blocking evidence when rejecting a candidate. If a precondition
cannot be resolved, demote to an observation rather than guessing.

For default-value and sentinel candidates, the challenge is incomplete until it
lists all security decisions that consume the value. Disproving a proof,
calculation, or setter path does not reject a direct consumer path.

## Completeness gate

The final report is complete only when:

- every state-changing public/external entry point is in the access map;
- every scanner flag and reasoning candidate has one ledger disposition;
- each Critical/High finding has an independent challenge result;
- each finding states the violated property, trace, impact, fix, and validation;
- each unexecuted dynamic check is listed as a limitation;
- `No findings` is supported by completed lanes, not by zero scanner flags.
