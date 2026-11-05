---
title: The Work That Outlives the Request
description: "Three node-availability findings followed different lifetimes: a goroutine outlived its peer message, nested output outgrew its contract call, and a startup-time API request reached state that was not ready."
slug: the-work-that-outlives-the-request
published: 2026-11-05
updated: 2026-11-05
tags:
  - Node security
  - Availability
  - Peer-to-peer
  - Vulnerability research
featured: false
findings:
  - name: P2P direct stream read deadline
    severity: High
    score: CVSS 7.5
    advisory: GHSA-v8j2-98j2-rqv2
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-v8j2-98j2-rqv2
  - name: Nested DeletedAccounts growth
    severity: High
    score: CVSS 7.5
    advisory: GHSA-hw69-3fg8-wrmm
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-hw69-3fg8-wrmm
  - name: Available allowance query
    severity: Moderate
    score: CVSS 5.9
    advisory: GHSA-g797-9c85-644m
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-g797-9c85-644m
---

An availability failure does not always begin with a large packet or an expensive transaction. Sometimes the input is a stream that never sends its first byte. Sometimes one output entry is copied again and again as a contract makes nested calls. Sometimes an API request arrives while startup has exposed a route before the state it needs is ready.

These three Klever Go reports affect different subsystems and have different triggers. One pins a goroutine in the P2P layer. One makes VM output grow exponentially. One lets a nil block header panic in a helper goroutine and terminate the process. They belong together because each failure is about the lifetime of host work: what keeps it alive, how often it is copied, and whether the state it touches is initialized.

## An empty stream still occupies a goroutine

The direct-send P2P handler registered a callback for incoming streams. For each stream, it started a goroutine that repeatedly called `ReadMsg`. If a connected peer opened a stream and sent no data, the goroutine blocked waiting for the first message. There was no read deadline to make that wait expire.

The handler did not need a malformed message to get stuck. It did not need to pass through message processing or trigger a costly decode. It only needed to establish a peer connection and open the direct-send stream. Until the stream closed, the blocked read retained the goroutine and its associated stream resources. The advisory estimates roughly 8 KiB for the goroutine stack alone; repeated idle streams make the retained work accumulate.

The trigger still has a network precondition: the sender must connect as a peer and open the `DirectSendID` stream. This is not an HTTP request available to any address on the internet, and the report does not claim that a single silent stream kills a node. The risk is accumulation. Every accepted stream can leave its handler waiting, and the lifetime of that wait is controlled by the remote peer unless the node sets a deadline or closes the stream itself.

This is different from the sibling report about unbounded goroutine creation before antiflood admission. That issue concerns spawning too many message-handler goroutines. This report concerns a goroutine that is already attached to a stream and never leaves because the blocking read has no deadline. A limit on how many streams may be opened can constrain the number, but it does not reclaim the idle streams already holding resources.

The remedy is to give the stream an explicit lifetime: set a read deadline, clear or refresh it according to the protocol's message rules, and close or reset the stream when the deadline expires. The P2P library cannot infer the application's expected idle period. That responsibility belongs to the handler that owns the stream.

The advisory is [GHSA-v8j2-98j2-rqv2](https://github.com/klever-io/klever-go/security/advisories/GHSA-v8j2-98j2-rqv2), rated High and patched in `1.7.21-rc2`. GitHub credits me as a Reporter.

## A child call copied its parent's deletion list

The VM output finding takes a different route. A smart contract performs nested calls, and the VM host preserves and restores output state around those calls. The child output is supposed to contain the effects produced by that child.

`CensorVMOutput()` cleared several inherited fields before a nested `ExecuteOnDestContext` call, including return data, logs, gas remaining, and return status. It did not clear `DeletedAccounts`. A successful child therefore inherited the parent's deletion list. During `PopMergeActiveState()`, the merge code appended the child's full list to the saved parent list—even though the child's entries were just the inherited parent entries.

After one deletion, a successful sibling call doubled the list: one entry became two, then four, then eight. The advisory's compiled-WASM reproduction executed one deletion followed by 20 successful sibling calls and produced 1,048,576 `DeletedAccounts` entries. At 24 bytes per slice header on a 64-bit Go runtime, the outer array alone was about 24 MiB. That measurement does not include every referenced allocation or claim a maximum; it demonstrates the repeated-copy shape.

There are two separate merge operations to follow when reading this code. `PushState()` first saves a copy of the active VM output. The nested call then runs after `CensorVMOutput()` prepares what should be fresh child-visible output. On return, `PopMergeActiveState()` combines the saved parent and child output. Because `DeletedAccounts` survived the censor step, the merge treated the inherited list as child additions. Each successful sibling call repeated the mistake against the now larger list. The number of calls grows linearly; the amount of copied state grows exponentially.

This is not the same as a contract legitimately deleting a million distinct accounts. The list grows because the output merge treats inherited state as new child output. A narrow fix has to preserve what the child actually added, or reset the inherited list before the child runs, rather than blindly append all entries from both snapshots.

The report, [GHSA-hw69-3fg8-wrmm](https://github.com/klever-io/klever-go/security/advisories/GHSA-hw69-3fg8-wrmm), is rated High and lists `1.7.22` as patched. GitHub credits me as a Reporter.

## A route reached the node before its header existed

The allowance-list crash was a startup-state problem. `GetAvailableClaim` called `GetCurrentBlockHeader()` and immediately used the returned value to read the epoch and timestamp. The blockchain implementation returns `nil` when no current header has been set.

The affected route, `/address/{address}/allowance/list`, ran that claim lookup in a goroutine spawned by the request handler. On a clean genesis start, the REST service could become available before the current block header was initialized. A request during that interval reached the nil value and panicked.

The goroutine boundary changed the impact. Gin's recovery middleware catches panics unwinding through the request goroutine; it cannot catch a panic in a separate goroutine created by application code. An unrecovered panic in that helper goroutine terminates the process. The report reproduced the crash on clean startup and identified a secondary path involving corrupted or restored chain state.

This is a narrower claim than “the allowance endpoint always crashes.” It requires the current header to be nil when the query runs. The exposure depends on startup or recovery ordering and on whether the REST endpoint is reachable in that state. The fix is to handle the missing header as an ordinary unavailable-state result before dereferencing it, and to make sure asynchronous helpers have a recovery and error-reporting path appropriate to their ownership.

This report also illustrates why HTTP middleware is not process-wide panic containment. Middleware wraps the request's call stack. Once the handler starts another goroutine and returns or waits on it, that goroutine has its own stack and failure path. A recovery wrapper must be installed in the goroutine that can panic, or the operation must return an error instead. The nil check is still the direct fix for the missing header; the goroutine boundary determines whether an unexpected panic is isolated or fatal.

The advisory, [GHSA-g797-9c85-644m](https://github.com/klever-io/klever-go/security/advisories/GHSA-g797-9c85-644m), is rated Moderate and lists `1.7.21-rc3` as patched. GitHub credits me as a Reporter.

## Give every unit of work a bounded lifetime

The three reports suggest different review questions:

- For a network stream, what event makes the read stop if the peer remains connected but silent?
- For nested execution, which output entries belong to the child, and how many times can a parent entry be copied?
- For startup-sensitive queries, can a route observe state before initialization completes, and what happens if a helper panics?

Each problem crossed a different boundary. A socket deadline cannot fix output merging. Clearing an inherited slice cannot initialize the block header. A nil guard does not stop a peer from holding streams open. The shared engineering task is to make the lifetime and ownership rules explicit at the layer that allocates, waits, or dereferences.

All three advisories retain their own severity, patch version, and credit history. The P2P read deadline and output amplification were rated High; the startup-time nil dereference was Moderate. Their patched versions are `1.7.21-rc2`, `1.7.22`, and `1.7.21-rc3`, respectively. The links above are the source of record for those details.
