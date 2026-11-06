---
title: The Bill Comes After the Body
description: An investigation of four Klever Go VM findings where gas metering failed to bound allocations, repeated copies, and state snapshots.
slug: the-bill-comes-after-the-body
published: 2026-10-26
updated: 2026-11-05
tags:
  - Go
  - Virtual machines
  - Blockchain security
  - Vulnerability research
featured: true
findings:
  - name: MBufferSetRandom
    severity: High
    score: CVSS 7.7
    advisory: GHSA-cg9c-gcgh-qgc3
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3
  - name: readKDATransfers
    severity: High
    score: CVSS 7.5
    advisory: GHSA-3xw3-gjh2-5j94
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94
  - name: BigIntShl
    severity: High
    score: CVSS 8.6
    advisory: GHSA-r2gq-244g-h8p2
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2
  - name: PushState
    severity: Moderate
    score: CVSS 5.3
    advisory: GHSA-gjm9-w2m6-rmp9
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9
---

The largest non-negative shift accepted by `BigIntShl` turns the integer `1` into a 256 MiB result. I ran that call against the production VM host with one million gas available. The shift completed; only afterward did the hook record the result-size gas.

In the reproduction, the meter ended at 268,435,458,002 gas. I set `CopyPerByteForTooBig` to 1,000 in the test so the expected charge was easy to inspect. That figure demonstrates the ordering bug; it is not a quote for a mainnet transaction. Klever reproduced the issue on a live node and agreed with the High rating.

That result is easy to summarize: the host built a huge integer before the meter could reject the cost. It was one of four Klever Go VM findings where resource work escaped an effective gas limit. The code paths differed. `BigIntShl` charged for its result after the shift. `MBufferSetRandom` recorded a charge before allocating, but the charge could not stop it. `readKDATransfers` cloned the same buffer repeatedly before its unbounded charge. `PushState` charged nothing for the deep copy.

Those distinctions matter. If every issue is described as “the charge came after the work,” the description is wrong for two of them. The shared question is whether the VM could refuse the work before the host had to perform it.

The interface boundary is easy to miss when reading a hook in isolation. A contract does not allocate a Go slice or call `big.Int.Lsh` directly. It passes a length, an integer handle, or a vector of handles into an imported VM function. The hook resolves those handles in the host's managed-type context, and the host does the allocation, copy, or decode. The gas meter is the contract's budget, but the memory allocator and CPU belong to the node process.

That makes the timing of a charge part of the security boundary. If a hook computes an amount and passes it to a helper that only increments a counter, the final transaction can still fail as out of gas. That failure does not undo a slice allocation or return the CPU time spent constructing a number. A bounded charge has to run before the work and has to be allowed to reject it.

## What the gas meter could—and could not—do

Klever's VM exposes host functions to contracts. The contract passes handles and lengths; Go code behind a hook allocates buffers, creates `big.Int` values, decodes vectors, and snapshots managed state. Gas is supposed to limit the amount of that work. But not every helper named `UseGas` actually checks the remaining budget.

Some helpers record or trace a gas amount and return no error. They are useful for accounting once work has been done, but a hook cannot use them to stop before an expensive operation. A bounded charge such as `UseGasBounded` has different behavior: it checks `GasLeft`, returns `ErrNotEnoughGas` when the caller cannot cover the work, and lets the hook exit before allocating or copying.

That difference is the center of these reports. The bug was not simply that an operation had a high cost. In three cases, the code had a cost calculation that did not bound the work. In the fourth, the snapshot was not charged at all.

## BigIntShl built the result before charging for its size

`BigIntShl` accepts a source handle and a signed 32-bit shift count. The hook checks that the input integer and shift count are non-negative. It also accounts for copying the input. It does not put a useful ceiling on a large positive shift.

With a source value of `1` and `bits = 0x7fffffff`, the result has 2,147,483,648 bits. Divide by eight and the host has to build 268,435,456 bytes—exactly 256 MiB—for this one operation.

The relevant sequence in the affected revision is short:

```go
dest.Lsh(a, uint(bits))
managedType.ConsumeGasForBigIntCopy(dest)
```

The second line looks like a result-size charge, and it is. But it runs after `Lsh` has allocated and computed the result. The copy-cost path eventually calls `UseAndTraceGas`, which records gas use but has no error return. When the result is too expensive, the hook still finishes the shift and only then overdraws the meter.

The proof of concept used the real `VMHost`, `VMHooksImpl`, and managed-bigint handles. It set the `BigIntShl` base cost to 2,000 and `CopyPerByteForTooBig` to 1,000, then supplied one million gas. Those values were explicit test settings, chosen to make the size charge deterministic. The test checked the result's bit length as well as the gas total; it did not substitute a mock shift.

The output made two separate claims visible: the result existed, and the gas meter had been overdrawn.

```text
result_bytes=268435456
provided_gas=1000000
gas_used=268435458002
alloc_delta_bytes=268449432
```

The allocation delta varies by Go version and machine because it includes runtime bookkeeping. The result bit length and the result-size gas calculation are deterministic for this input and test schedule. I wanted the test to prove that the real hook completed the shift before the accounting path returned, not merely that `Lsh` could allocate a large integer in a standalone benchmark.

There was a useful comparison nearby. `BigIntPow` estimates its output size and calls a bounded helper before `Exp`. It can return `ErrNotEnoughGas` before doing the expensive work. A shift's output size is even simpler to estimate: for a non-zero value, it is the input bit length plus the shift count. The vulnerable hook already had the ingredients to follow the safer pattern, but did not use them.

The `FixAuditChangesV6` path now computes that byte length, applies the bounded charge, and only then calls `Lsh`. If the caller cannot pay, no 256 MiB result is built. This was my September 14 report, [GHSA-r2gq-244g-h8p2](https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2), rated High.

## MBufferSetRandom had a charge, but no effective limit

`MBufferSetRandom` takes a managed-buffer destination and a caller-controlled `int32` length. Before the fix, it rejected non-positive lengths and had no upper bound for positive ones. A contract could request a length near `math.MaxInt32`.

The hook calculates a base gas amount plus a per-byte component, then calls `UseGasAndAddTracedGas`. That call happens before `make`, but it does not check whether enough gas remains and does not return an error. The hook carries on: it allocates the requested byte slice, fills it from the random source, and passes it to `SetBytes`. `SetBytes` copies the contents into the managed-type store, so the host handles the huge buffer twice.

At the largest positive `int32` length, the first allocation is roughly 2 GiB and the store operation performs a second full-size copy. The caller's chosen length controls the work. A gas record before `make` does not help if the record cannot refuse the request.

This hook was the sharpest instance in a larger managed-buffer cluster. Nineteen hooks used charging helpers that could not fail; four of the nineteen had no per-byte charge. `MBufferStorageLoadFromAddress` had no metering at all. The cluster included buffer construction and copying, byte-slice access, append operations, conversions to big numbers, and storage paths. Six structurally similar neighbors were also fixed during remediation.

I reported `MBufferSetRandom` on September 16. CertiK had already identified the broader family in its KLR-50 review, and a private fix was merged before my report arrived. The published advisory credits CertiK for the cluster and credits me as an independent reporter for this hook. That detail matters: this article is about four GHSA records, but it does not claim I was first to find every pattern.

The remediation moved the size-dependent charge before the work and made it bounded. It also added a 16,000,000-byte ceiling to hooks that accept caller-supplied lengths. The cap is defense in depth: even if a gas schedule priced a byte too cheaply, the hook would still reject a multi-gigabyte request. The change was gated by `FixAuditChangesV5`, which activated September 18. The advisory is [GHSA-cg9c-gcgh-qgc3](https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3), High severity.

The point of showing `MBufferSetRandom` is not that it has the same instruction order as `BigIntShl`. It doesn't. Its call sequence was effectively:

```go
metering.UseGasAndAddTracedGas(name, gasToUse)
buffer := make([]byte, length)
randomizer.Read(buffer)
managedType.SetBytes(destinationHandle, buffer)
```

The charge call comes first. The defect is that this helper has no bounded failure path. It records use and returns; execution moves directly into the allocation. Replacing it with a bounded charge would close the immediate gas-ordering gap, but a cap is still useful because it sets a maximum amount of work independent of a future gas schedule.

`MBufferSetRandom` was the report I filed, not the whole discovery credit for the hook family. CertiK's KLR-50 work covered the broader pattern and a private fix already existed. The advisory credits CertiK for that cluster and recognizes my independent report on this specific function.

## A 128 KiB vector described 2 GiB of copies

`readKDATransfers` decodes a byte vector into KDA transfer objects. Each record is 16 bytes: a four-byte token-identifier handle, an eight-byte nonce, and a four-byte bigint handle. The vector stores references to managed objects; it does not contain the token identifiers themselves.

That distinction created the amplification. The record format does not require unique handles. `GetBytes` returns a fresh copy each time it is called. If 8,192 records all name one 262,144-byte token identifier, the vector is only 131,072 bytes—128 KiB—but decoding those entries copies the token identifier 8,192 times. The predicted copy traffic is 2 GiB.

The construction is small. Start with one token-identifier buffer, double it until it is 262,144 bytes, then place that same handle in every 16-byte record. The records differ only in their position in the vector; they all resolve to the same source bytes. The vector's encoded size stays proportional to the number of records, while the decoder's temporary copies scale with record count multiplied by the referenced buffer size.

| Input | Value |
| --- | ---: |
| Token identifier | 262,144 bytes |
| Transfer records | 8,192 |
| Encoded vector | 131,072 bytes (128 KiB) |
| Token identifier copy traffic | 2,147,483,648 bytes (2 GiB) |
| Measured RSS increase | 2,052 MB |
| Elapsed time | 0.25 seconds |

The decoder also copies the vector itself and charges for that copy afterward. For each record, it loads the token identifier and bigint, then records the corresponding copy costs. Those helpers were unbounded: they could add gas to the meter but could not stop the next allocation or reject the call before the repeated copies occurred. The attacker did not need 8,192 different buffers. Reusing one handle was the point.

The published reproduction used a local network with three validators and two observers, the production gas schedule, and all fork flags active. At 8,192 records, the sampled node's RSS increased by about 2,052 MB in a quarter of a second. The transaction was ultimately rejected for insufficient gas. The host had already done the expensive decoding work by then.

There is an important boundary on that measurement: the reproduction drove the hook through `/transaction/send`, which runs a VM simulation and made it convenient to sample memory. The advisory's consensus-path argument is separate. Block validity checks do not simulate the contract before execution; validators executing a block reach the same decoder. The report describes the reproduction and that reachability argument separately, and the article should too.

The RSS sample proves what the production hook does when the input reaches it. The consensus claim depends on the transaction path: validity checks price the submitted transaction without first simulating all contract execution, then nodes execute transactions from the block. A funded attacker can submit a contract call that is later rejected for insufficient gas; every validator still reaches the decoder while executing it. This is a liveness cost, not a state-confusion bug. The advisory describes the risk as validator memory exhaustion and execution delay, not consensus divergence.

The affected entry point, `ManagedMultiTransferKDANFTExecute`, is categorized as a fast hook. Fast hooks run inline rather than in an interruptible goroutine. The VM timeout therefore cannot stop this decoding loop halfway through; it can only act after the hook returns. That implementation detail helps explain why a quarter-second allocation burst matters even though the transaction ultimately runs out of gas.

The advisory credits three finders, including me, and says maintainers found the path on September 20 while reviewing the sibling managed-vector decoder. The accepted credit is real; the article does not turn that into a solo-discovery story. See [GHSA-3xw3-gjh2-5j94](https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94), rated High.

The `FixAuditChangesV6` repair caps the vector, calculates the cost of the token identifiers using their stored lengths, and applies a bounded charge before cloning them. It rejects a vector that cannot afford its transfers before constructing the decoded records. This closes the amplification at the point where the host would otherwise begin copying.

The transfer decoder has a sibling with the same ordering mistake but a different input format. `ReadManagedVecOfManagedBuffers` reads four-byte managed-buffer handles and clones each referenced byte slice before charging for it. Repeating one handle is enough: the advisory's real-WASM reproduction used 1,024 references to a 64 KiB buffer and measured about 64 MiB of clone traffic. The managed write-log hook then charged for topic and data bytes again, so the observed gas total includes both the decoder's unbounded record and the hook-level charge. This separate report is [GHSA-qqr9-92pp-89p7](https://github.com/klever-io/klever-go/security/advisories/GHSA-qqr9-92pp-89p7); GitHub credits me as a Reporter. It belongs in the same resource-accounting family, though the four findings above are the ones examined in depth here.

## PushState copied 199,000 handles for zero gas

The previous three findings involve attacker-controlled output size or repeated copies. `PushState` was different: it copied a collection that the contract had already populated.

Managed bigints live in a map keyed by `int32` handles. `BigIntNew` creates a handle and charges for that call, but the context had no explicit cap on the number of handles. When a contract makes a nested call with `ExecuteOnDestContext` or `ExecuteOnSameContext`, the host calls `PushState` to preserve the parent state. The old implementation cloned the map and deep-copied each `big.Int` with `Set`.

The charge for `BigIntNew` covered creating each entry. It did not also pay for copying all entries at every nested execution boundary. `PushState` added no gas for the map allocation or the bigint copies. A large handle set could therefore make each nested call take a snapshot for zero additional gas.

My reproduction used 199,000 distinct handles created through the exported `BigIntNew` hook. At 2,000 gas per call, the setup consumed 398 million of the 400 million gas provided. I then measured the real production `PushState` operation: the gas delta was zero, while the call allocated about 11 MB and took about 36 milliseconds on my machine. Those timing and allocator figures vary by machine; the zero gas delta is the key result.

The test called `PushState` directly rather than building a child contract to reach it. That isolated the exact production operation used at the nested-execution boundary, without adding unrelated contract setup to the measurement. Klever then evaluated the handle set against its own copy-cost model: the setup cost around 78% of a transaction's gas budget and enabled roughly 83 MiB of snapshot allocation, about 250 times underpriced by that model.

This was my September 14 report, [GHSA-gjm9-w2m6-rmp9](https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9), accepted at Moderate severity. The lower rating reflects an important limit: the attacker spends substantial gas creating the handles. It is not comparable to a single huge shift that runs before its result-size charge.

The fix removed the deep clone. `pushStateByMove` puts the parent's managed-type maps onto the stack, initializes fresh maps for the nested call, and restores the parent's state when that call returns. No map snapshot means the host no longer does the unmetered copy. The fix shipped behind `FixAuditChangesV6`.

The reproduction isolates the copy from the work needed to construct the handle set. It supplied 400 million gas, set `BigIntNew` to 2,000 gas, and called the real hook 199,000 times. That setup used 398 million gas. It then took a memory snapshot, invoked `host.ManagedTypes().PushState()`, and read gas again. The important output was:

```text
handles=199000
gas_before_push=398000000
gas_after_push=398000000
push_gas_delta=0
alloc_delta_bytes=11097808
elapsed=36.391704ms
```

This direct call is narrower than a full nested-contract reproduction, but it answers the specific question: does the production `PushState` clone consume gas? It does not. The nested-execution functions call this same state operation, so the clone cost is on their path. The test does not claim that 11 MB is the maximum possible map or that every machine will take 36 milliseconds.

Klever's 83 MiB and 250x estimate answers a different question from my allocation sample. It applies the project's own copy-cost model to the handle count that could be built within the transaction budget. Both measurements point to the same underpricing, but one is a local allocator delta and the other is a protocol cost estimate; they should not be presented as if they measured the same quantity.

## How the reports came together

The two reports I filed on September 14 were `BigIntShl` and `PushState`. They were accepted at different severities because the resource models differ: one lets a single operation build an enormous result before its size-based charge, while the other requires spending gas to create a large handle set before the free snapshot. The first report is High; the second is Moderate.

I reported `MBufferSetRandom` on September 16, after CertiK's private review had already identified the wider managed-buffer family and the fix had been merged. My credit is for an independent report on that hook. The KDA transfer-vector issue followed another route: the published advisory says maintainers identified it on September 20 while reviewing the sibling managed-vector decoder, and credits three finders, including me.

Those histories are part of the technical record. A credited finder, an independent reporter, and the team that first spotted a broader pattern are not interchangeable roles. The host-work boundary connects the four reports; each advisory records its own chronology and credits.

## The common point: work outside the gas bound

The connection is resource accounting at the VM boundary. The hook can charge for bytes, but that only protects a validator if it can reject the work before those bytes are allocated or copied. `UseAndTraceGas`, `UseGasAndAddTracedGas`, and the `ConsumeGasForBytes` and `ConsumeGasForBigIntCopy` paths used in these findings do not all provide that guarantee. A bounded pre-charge does.

The fixes had to match their individual mechanisms:

- `BigIntShl` predicts the result size and charges before shifting.
- `MBufferSetRandom` uses a bounded per-byte charge and a hard length cap before allocation.
- `readKDATransfers` bounds the vector and charges for each referenced buffer before cloning it.
- `PushState` moves the parent maps instead of cloning them.

Three paths performed work under an unbounded or late charge. The fourth never charged for the copy. For each one, the review question is the same: what resource does this host operation consume, and can the gas meter stop it before it consumes that resource?

The bill came after the body most literally in `BigIntShl`: the result existed before its size-based cost was recorded. `PushState` had no bill; `MBufferSetRandom` recorded a cost it could not enforce; and the vector decoder multiplied copies before its unbounded accounting could stop them. The advisories document the individual severities, credits, reproduction details, and fixes: [MBufferSetRandom](https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3), [readKDATransfers](https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94), [PushState](https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9), and [BigIntShl](https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2).
