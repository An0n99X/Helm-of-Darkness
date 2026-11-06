---
title: The Bigger the Theft, the Smaller the Number
description: Three managed-buffer imports added attacker-controlled int32 offsets before widening them, turning an invalid slice into a host panic and a full-gas loss.
slug: the-addition-overflowed-before-the-bounds-check
published: 2026-09-21
updated: 2026-11-05
tags:
  - Go
  - Integer overflow
  - Virtual machines
  - Vulnerability research
featured: false
findings:
  - name: MBufferCopyByteSlice
    severity: High
    score: CVSS 7.5
    advisory: GHSA-2m22-3m34-2qxf
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-2m22-3m34-2qxf
  - name: MBufferGetByteSlice
    severity: High
    score: CVSS 7.5
    advisory: GHSA-vxf6-vgpv-822h
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-vxf6-vgpv-822h
  - name: MBufferSetByteSlice
    severity: High
    score: CVSS 7.5
    advisory: GHSA-wjrx-39g9-j97q
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-wjrx-39g9-j97q
---

The bounds check was there. It checked for negative values and compared the requested end position with the source length. The problem was the order of operations: two signed 32-bit values were added first, and only the wrapped result was converted to the host's `int` type.

At the managed-buffer boundary, that distinction decides whether the VM returns an ordinary error or the Go runtime panics. A contract cannot write a Go slice expression itself, but it can pass an offset and a length to a host import. The import resolves the managed handle and performs the slice. If the guard is fooled, the panic happens in node code.

The three reports cover the same arithmetic mistake in separate operations: copying a byte slice out of a managed buffer, reading a byte slice into VM memory, and writing a byte slice into a managed buffer. They are related, but they are not one finding repeated three times. Each WASM import has its own route to the vulnerable check, and each needed its own regression coverage.

## The cast happened after the overflow

In `MBufferCopyByteSlice`, the vulnerable condition was equivalent to:

```go
if startingPosition < 0 || sliceLength < 0 ||
    int(startingPosition+sliceLength) > len(sourceBytes) {
    return 1
}

slice := sourceBytes[startingPosition : startingPosition+sliceLength]
```

Both operands are `int32`. Go evaluates `startingPosition + sliceLength` as an `int32` expression; wrapping can occur before `int(...)` runs. Converting the wrapped result to a wider type does not restore the original mathematical sum.

For `startingPosition = 1` and `sliceLength = math.MaxInt32`, the signed 32-bit sum wraps to `math.MinInt32`, or `-2147483648`. The check sees a negative end value, which is not greater than the byte slice length. It passes the guard and reaches a slice expression whose end is negative. The runtime panics with a slice-bounds error.

`MBufferGetByteSlice` had the same shape on the read path. It fetched the managed bytes, checked the offset and requested length using the narrow addition, then sliced the source before copying into the VM's linear memory. `MBufferCopyByteSlice` and `MBufferGetByteSlice` therefore failed at related points in two different imports.

The write path needed one extra detail. `MBufferSetByteSlice` had a 16 MiB cap on `dataLength` under the active `FixAuditChangesV4` rules. That cap limited the size of the input, but it did not limit `startingPosition`. With a start position of `math.MaxInt32` and a length of `1`, the end position still wrapped. A length ceiling cannot make an unchecked offset safe.

The operations also reached the check through different helper paths. `MBufferCopyByteSlice` is exposed through the `w2_mBufferCopyByteSlice` import and implemented by `ManagedBufferCopyByteSliceWithHost`. `MBufferGetByteSlice` reads from a managed buffer and then writes the selected bytes into the VM's linear memory at `resultOffset`. `MBufferSetByteSlice` reaches `managedTypesContext.SetByteSlice` through the host's set-byte-slice helpers. The common arithmetic expression made them look nearly identical in review; the source and destination state they touched were still different.

That difference matters for regression tests. A single helper-level check can protect two call sites if they truly share the helper, but it will not prove that the third import is safe. Each import needs a case that exercises its real exported path with values that overflow at 32 bits. For `CopyByteSlice` and `GetByteSlice`, the report uses `start = 1` and `length = math.MaxInt32`. For `SetByteSlice`, the active length cap means the useful case is `start = math.MaxInt32` and `length = 1`.

## Why a panic mattered to a contract caller

These imports were registered as fast VM hooks. Their ordinary failure path was meant to return a status through `WithFault`; a Go panic is outside that mechanism. The panic unwound to the recovery around smart-contract execution, which returned `ErrExecutionPanicked` with no useful VM output. The transaction processor then consumed the caller's gas limit.

That made the consequence concrete: the malformed slice did not just make one hook fail. A caller could lose the full gas allocation for the transaction. The same shape could be reached by a contract written to make the call directly, or by an existing contract that forwarded an untrusted offset and length without validating them first. There was no race or timing window to hit.

This is a useful distinction when describing VM panics. The Go runtime recovery prevented an uncontrolled process crash in this path, but it did not turn the operation into a normal contract error. The transaction still failed at a coarse boundary and paid the entire gas limit. Recovery kept the host alive; it did not preserve the caller's execution budget.

## One arithmetic rule for all three imports

The safer pattern is to prove the start is within the buffer, then prove the requested length fits in the remaining suffix. In abstract form:

```go
if start < 0 || start > len(buffer) || length < 0 ||
    length > len(buffer)-start {
    return invalidRange
}
```

The subtraction is evaluated only after `start` is known to be no greater than the buffer length. That avoids forming the potentially overflowing `start + length` expression. Another valid design widens each operand before adding and still checks the range before creating a slice. The important property is that validation and slicing use the same safe arithmetic.

The cap on `MBufferSetByteSlice` is useful defense in depth, but it answers a different question: how many bytes may be copied? It does not answer whether the starting position points into the buffer. A small write at a huge offset can be just as invalid as a huge write at a small offset.

There was also a timing issue in the older cap logic. The `FixAuditChangesV4` path capped the resulting slice length only after evaluating the slice expression. A cap checked after `buffer[start:end]` cannot protect the expression that has already panicked. Validation has to happen before slicing, and it has to validate the end without first constructing an overflowing end.

The host panic was not merely a bypass of the cap. It exposed a mismatch between two error models. The VM hook expected failures to travel through a returned status or `WithFault`; Go's slice operation signals an invalid range with a panic. Once the input reached that expression, the normal managed-buffer error behavior was no longer in control. The transaction-level recovery did catch the panic, but it reported an execution panic and the processor charged the full gas limit. In other words, the fix had to restore both memory safety and the intended failure semantics.

The full-gas result also explains why “the process recovered” is an incomplete impact statement. Recovery is at the wrong level to preserve the caller's work: it converts the panic into a failed VM execution, and the transaction processor applies its configured failure accounting. For these reports, that path consumed the submitted gas limit. The validator survives, but the contract caller loses the budget and receives no useful output from the operation.

The test cases should include the exact wrap boundary, not just a very large valid range or a normal out-of-bounds range. Ordinary checks such as a small buffer with `start = len` and `length = 1` exercise the guard's intended behavior. They do not show that `start + length` can become negative before the comparison. A regression test must make the intermediate sum overflow while keeping both individual inputs non-negative, then assert that the hook returns its normal failure result without panicking.

## The fix and the advisory record

All three advisories list `1.7.21-rc3` as the patched version. They describe the same underlying implementation mistake and the same execution consequence, while keeping the import-specific cases separate:

- [MBufferCopyByteSlice — GHSA-2m22-3m34-2qxf](https://github.com/klever-io/klever-go/security/advisories/GHSA-2m22-3m34-2qxf)
- [MBufferGetByteSlice — GHSA-vxf6-vgpv-822h](https://github.com/klever-io/klever-go/security/advisories/GHSA-vxf6-vgpv-822h)
- [MBufferSetByteSlice — GHSA-wjrx-39g9-j97q](https://github.com/klever-io/klever-go/security/advisories/GHSA-wjrx-39g9-j97q)

GitHub credits me as a Finder for the copy and set imports, and as a Reporter for the get import. The severity and credits belong to each GHSA record; grouping the code paths here does not collapse those records or change who found which one.

When a hook takes two `int32` values that jointly define a memory range, reviewing the comparison alone is not enough. Read the types through the addition, the cast, and the final slice expression. The bug lived in the gap between those three lines.
