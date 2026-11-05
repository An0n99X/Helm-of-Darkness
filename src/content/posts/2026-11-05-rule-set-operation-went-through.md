---
title: Smuggled Through the Storefront While the Border Guards Slept
description: Five Klever Go findings show how balance-moving and asset-update paths bypassed policies enforced by their neighboring operations.
slug: the-rule-was-set-the-operation-still-went-through
published: 2026-11-05
updated: 2026-11-05
tags:
  - Blockchain security
  - Business logic
  - Asset policy
  - Vulnerability research
featured: false
findings:
  - name: Marketplace Buy and settlement
    severity: Moderate
    score: CVSS 4.3
    advisory: GHSA-3rvr-m2w2-ggqj
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-3rvr-m2w2-ggqj
  - name: ITO purchases
    severity: Moderate
    score: CVSS 4.3
    advisory: GHSA-vjj9-8392-w5hw
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-vjj9-8392-w5hw
  - name: FPR deposit and claim
    severity: Moderate
    score: CVSS 4.3
    advisory: GHSA-h45p-mxgj-59f8
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-h45p-mxgj-59f8
  - name: Royalty receiver updates
    severity: Moderate
    score: CVSS 6.5
    advisory: GHSA-344r-g6cw-g546
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-344r-g6cw-g546
  - name: SFT metadata updates
    severity: Moderate
    score: CVSS 6.5
    advisory: GHSA-54v2-fp39-5w66
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-54v2-fp39-5w66
---

A transfer restriction is only real if every path that moves a balance obeys it. A permanent stop flag is only permanent if every update path checks it. In Klever Go, the ordinary transfer and one branch of each asset update did the right thing. Several less direct paths did not.

The affected code sat in three parts of the application: marketplace settlement, initial token offerings (ITOs), and FPR staking. Each could move a currency by debiting and crediting account balances directly, without using the common transfer path that checks whether a token is paused or restricted. Two other paths accepted asset changes after the owner had invoked a stop control: royalty receiver changes and semi-fungible token metadata updates.

These are policy enforcement bugs, not cryptographic bypasses. The balance ledger did what those functions asked. The missing step was checking the rule that should have decided whether the operation was allowed.

## A transfer rule can disappear inside a settlement

The standard KDA transfer path checks currency attributes. It rejects a paused currency and applies `LimitTransfer` roles before moving the balance. The marketplace's `Buy` path did not use that policy-aware route for its settlement currency. It removed the bid from the buyer and credited the seller, prior bidder, referral address, and royalty recipients with direct balance operations.

The currency was selected for the order. `Sell` accepted a seller-chosen settlement currency without validating its transfer policy; `Buy` later performed the debit and settlement. In a BuyItNow path, the operation could debit and settle in one transaction. The report's production-path reproduction showed a paused or transfer-restricted currency moving even though a normal transfer of that same currency was rejected.

That is an important boundary: a marketplace should not become an alternate transfer primitive with fewer rules. A restriction attached to the currency has to apply when the marketplace moves it, regardless of whether the movement is called a transfer, a bid, a refund, or seller settlement.

The ITO path had a similar issue with a different route. `Buy` resolved the purchase price and currency, then debited the buyer and credited the ITO receiver directly. Percentage royalties and split recipients were also credited in that currency. The transaction path did not check `IsPaused` or the `LimitTransfer` rule. A recipient could configure an ITO priced in a restricted currency, and a holder could purchase through it even when the canonical transfer path refused that movement.

The issuer of the restricted currency did not have to participate in the purchase. A contract holding restricted balances could also reach the path through the `kleverBuy` builtin. The issue was not that an unauthorized account changed the currency's settings; it was that the purchase operation moved balances without consulting the settings already in force.

Those two policy checks answer different questions. `IsPaused` says whether a currency can move at all through the relevant transfer operation. `LimitTransfer` asks whether the sender and receiver satisfy the asset's transfer-role rule. A correct settlement needs both answers for its actual source and destination. Checking only the payer's balance, or validating the order when it was created, says nothing about whether this later movement is allowed.

## Staking made the route less obvious

The FPR finding is easier to miss because the deposit and reward claim happen at different times and can involve different accounts.

`Deposit` checked that the reward currency existed and that the sender had the deposit role on the staking asset. It did not check whether the reward currency was paused or had transfer restrictions. The deposit debited the depositor with a direct balance call. When rewards matured, the residual payment used direct credits as well.

The reported sequence used two accounts. Alice deposited a restricted currency into the next-epoch rewards of a self-created FPRI staking asset. Bob then staked that asset. A later freeze triggered the matured-reward claim and credited Bob. The normal Alice-to-Bob transfer was refused by the currency policy; the deposit-and-claim route moved the same balance anyway.

That sequence shows why checking only the first sender is insufficient. The policy belongs to the currency and the balance movement. It must be enforced when the deposit is collected and when matured funds are paid, even if staking changes the account and delays the second movement.

The three transfer-policy advisories cover separate application paths: [marketplace settlement](https://github.com/klever-io/klever-go/security/advisories/GHSA-3rvr-m2w2-ggqj), [ITO purchases](https://github.com/klever-io/klever-go/security/advisories/GHSA-vjj9-8392-w5hw), and [FPR deposits and claims](https://github.com/klever-io/klever-go/security/advisories/GHSA-h45p-mxgj-59f8). Each is rated Moderate and lists `1.7.22` as the patched version.

The PoCs for these paths were useful because they compared the exceptional route with the normal one using the same currency settings. A standard transfer failed with the paused or transfer-restricted result. The marketplace, ITO, and deposit/reward sequences nevertheless completed their own balance changes. That contrast isolates the policy gap: the asset flag was loaded and understood by the canonical route, but the alternate state transition did not ask it.

## Stop flags must reach every update branch

The other two findings involve a different kind of policy: an owner or admin can permanently stop a class of changes, but the stop check was not consistently applied.

For royalties, `StopRoyaltiesChange` sets `IsRoyaltiesChangeStopped`. Updates to royalty parameters checked that flag. The separate `updateRoyaltiesReceiver` path did not; after confirming the caller was the owner or admin, it rewrote `asset.Royalties.Address`. The same asset could therefore reject a royalty-parameter update and accept a recipient change after the stop had been set.

For metadata, `StopNFTMetadataChange` applies to nonce-bearing assets, including SFTs. The NFT update path checked the flag. The SFT dispatcher sent updates to `updateMetadataV2`, which wrote metadata without making the same check. An owner or admin could update SFT metadata after the stop, while an NFT update with the same flag was refused.

Neither finding says an unrelated user could take ownership or alter another party's asset. The caller still needed the owner or admin role. The failure was narrower: the control set by an authorized owner was enforced in one implementation branch and skipped in its sibling.

The distinction between authority and policy is worth preserving in the writeup. The owner or admin's role answers who may submit an update. `IsRoyaltiesChangeStopped` or `IsNFTMetadataChangeStopped` answers whether that kind of update remains permitted. Passing the first check cannot substitute for the second. The SFT case is especially easy to miss because the dispatcher divides NFT and SFT metadata into separate functions; a guard in `updateMetadataV1` does not protect `updateMetadataV2` merely because both are called “metadata update.”

These distinctions matter when writing the fix or the advisory summary. “Authorization bypass” would overstate the royalty and metadata reports. They are policy consistency failures. The signature and role checks still existed; the state transition ignored an additional rule that those checks were meant to coexist with.

The relevant records are [royalty receiver changes after StopRoyaltiesChange](https://github.com/klever-io/klever-go/security/advisories/GHSA-344r-g6cw-g546) and [SFT metadata changes after StopNFTMetadataChange](https://github.com/klever-io/klever-go/security/advisories/GHSA-54v2-fp39-5w66). Both list `1.7.22` as patched.

## Put the policy where the state changes

The common review question is not “does the transfer endpoint validate this?” or “does the NFT path check this flag?” It is: at the point where a balance or asset field changes, which invariant must still hold?

For currencies, direct balance primitives should either be private to a policy-aware operation or be preceded by the same transfer-policy check that canonical transfers use. For stopped asset controls, every branch that mutates the protected fields should share one guard or call one shared function. Duplicating the flag check in two neighboring functions is a warning sign: the next branch may omit it.

The advisory fixes are recorded in `1.7.22`. The reports are distinct, and their credits are distinct too: GitHub credits me as a Reporter on marketplace settlement, FPR rewards, royalty-receiver changes, and SFT metadata; the ITO finding credits me as a Finder. The full list and exact severities are in the published GHSA records above.

What joins them is not one faulty helper. It is the distance between a rule and the code path that finally changes state. Whenever a protocol has a canonical operation with policy checks, every shortcut, settlement, payout, and specialized asset update needs to preserve those same rules.
