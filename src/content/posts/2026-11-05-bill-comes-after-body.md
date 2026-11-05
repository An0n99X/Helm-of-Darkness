---
title: The Bill Comes After the Body
description: An investigation of four Klever Go VM findings where gas metering failed to bound allocations, repeated copies, and state snapshots.
slug: the-bill-comes-after-the-body
published: 2026-11-05
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
    score: CVSS 7.5
    advisory: GHSA-cg9c-gcgh-qgc3
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3
  - name: readKDATransfers
    severity: High
    score: CVSS 7.5
    advisory: GHSA-3xw3-gjh2-5j94
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94
  - name: PushState
    severity: Moderate
    score: CVSS 5.3
    advisory: GHSA-gjm9-w2m6-rmp9
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9
  - name: BigIntShl
    severity: High
    score: CVSS 8.6
    advisory: GHSA-r2gq-244g-h8p2
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2
---

I passed `BigIntShl` the largest non-negative shift its API accepts. The input was the integer `1`; the result was 256 MiB. The VM built that result before recording the size-based gas cost.

In my VMHost reproduction, the meter ended at 268,435,458,002 gas against 1,000,000 supplied. I set the per-byte copy rate in the test to make the expected charge visible, so that total demonstrates the ordering bug; it is not a claim about the cost of a mainnet transaction. Klever reproduced the issue on a live node and accepted the High rating.

That is the cleanest example of a broader problem in Klever's Go VM: host work could happen without a gas check capable of stopping it first. The four advisories below do not describe the same code defect. Three involve allocations or copies made without an effective size-based limit; `PushState` deep-copied state without charging for the copy at all.

## BigIntShl built the result before charging for its size

The hook accepts a signed 32-bit shift count. It rejected negative values, but had no limit on a large positive shift. With a value of `1` and `bits = 0x7fffffff`, Go's `big.Int.Lsh` builds a 2,147,483,648-bit integer: 268,435,456 bytes.

The relevant order was:

```go
dest.Lsh(a, uint(bits))
managedType.ConsumeGasForBigIntCopy(dest)
```

The second call eventually used `UseAndTraceGas`, which records gas use but cannot return `ErrNotEnoughGas` and stop the hook. `BigIntPow` in the same file already predicted the result size and used a bounded charge before doing the expensive operation. `BigIntShl` did not.

The fix, gated by `FixAuditChangesV6`, estimates the shifted result's byte length, calls the bounded charge, and shifts only if gas remains. The report is [GHSA-r2gq-244g-h8p2](https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2).

## A short vector caused gigabytes of copies

`readKDATransfers` decodes a vector of 16-byte records. Each record contains a handle for a token identifier and a handle for a bigint. The format does not require handles to be unique, and `GetBytes` returns a copy. Repeating the same token-identifier handle therefore makes the decoder copy the same buffer once per record.

In the published reproduction, one 262,144-byte token identifier was referenced by 8,192 records. The vector itself was 128 KiB; the predicted token-identifier copy traffic was 2 GiB. A local five-node network showed about 2,052 MB of RSS growth over 0.25 seconds before the transaction was rejected for insufficient gas.

That measurement came from a local network and a transaction simulation. The advisory separately explains why the same decoder is reachable during block execution: block validity checking does not simulate the contract first. The report is [GHSA-3xw3-gjh2-5j94](https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94). The published advisory says maintainers found this path while reviewing the sibling vector decoder and credits three finders, including me.

The fix caps the vector, checks whether gas can cover the token identifiers before cloning them, and rejects the vector before building its decoded records. It shipped in 1.7.22 behind `FixAuditChangesV6`.

## MBufferSetRandom could allocate almost 2 GiB

`MBufferSetRandom` accepted a caller-provided positive `int32` length without an upper bound. Its gas helper recorded a length-dependent cost, then the hook allocated a slice of that length, filled it with random bytes, and passed it to `SetBytes`, which copied it into managed storage. At the largest positive `int32` length, that means two roughly 2 GiB buffers in one call.

The larger audit finding covered nineteen managed-buffer hooks with gas helpers that could not fail. Four charged no per-byte gas at all. The remediation added bounded charges before the work and a 16,000,000-byte limit for hooks that accept a caller-supplied length.

I reported `MBufferSetRandom` on September 16. CertiK had already identified the broader hook family during its review, and the private fix had been merged before my report. The published advisory credits CertiK for the cluster and me as an independent reporter on this hook: [GHSA-cg9c-gcgh-qgc3](https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3). The fix was gated by `FixAuditChangesV5`, which activated on September 18.

## PushState copied every bigint without a gas charge

Nested contract execution calls `PushState` to preserve the parent's managed types. Before the fix, that operation deep-copied every bigint in a map. A contract could create many handles with individually metered `BigIntNew` calls, then make a nested call that copied the whole map.

I tested `PushState` directly with 199,000 bigint handles. The setup used 398 million gas; the snapshot added no gas. On my run, it allocated about 11 MB in 36 milliseconds. Klever measured the case against its own copy-cost model and estimated about 83 MiB of allocation for the gas spent constructing the handles—roughly 250 times underpriced.

This was not a late charge. There was no charge for the snapshot. The fix avoids the deep clone: parent state moves onto a stack, the nested call receives fresh maps, and the original state is restored when it returns. Details are in [GHSA-gjm9-w2m6-rmp9](https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9), reported September 14 and accepted at Moderate severity.

## What the four fixes have in common

For each hook, the question was whether gas could refuse the work before the host performed it. An unbounded recorder could report an overrun after the allocation; a clone with no charge could not report one at all. Neither protected the node's CPU or memory budget.

The remedies followed the code. The managed-buffer hooks gained limits and bounded pre-charges. The vector decoder checks the cost before cloning. `BigIntShl` predicts and charges for its result before shifting. `PushState` stops cloning the bigint map.

The reports were not all discovered in the same way or by the same people. Their advisories preserve the individual severity, credits, disclosure details, and fixes; use those for the full record. This article follows one technical thread through them: making VM gas bound the work a node actually does.
