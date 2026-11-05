---
title: "Death by Decimals: Bleeding a Chain One Fraction at a Time"
description: Validator fee shares and missed-slot penalties drifted by integer units when floating-point rounding was used for protocol accounting.
slug: overflow-rounding-and-a-cap-that-stopped-being-a-cap
published: 2026-11-05
updated: 2026-11-05
tags:
  - Go
  - Arithmetic
  - Consensus
  - Vulnerability research
featured: false
findings:
  - name: DecreaseAll penalty rounding
    severity: Moderate
    score: CVSS 4.8
    advisory: GHSA-w99g-8m9m-jrf7
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-w99g-8m9m-jrf7
  - name: Validator fee split
    severity: Low
    score: CVSS 3.7
    advisory: GHSA-x5mg-959h-f66v
    url: https://github.com/klever-io/klever-go/security/advisories/GHSA-x5mg-959h-f66v
---

Consensus software has to turn arithmetic into state. The values may be tiny—one fee unit or one rating decrement. The arithmetic still has to preserve the rule that gives those values meaning.

These two reports expose different ways to lose that guarantee. In validator rewards, floating-point conversion could give one fee unit to the wrong side of a split. In missed-slot accounting, an attempted floating-point ceiling could add a failure where the division was already exact.

The common theme is arithmetic at a state boundary. The consequences are not interchangeable: one redistributed integer fee units, and one added validator penalties. Treating them as one generic “rounding bug” would hide the actual risk in each.

## The Ceiling Tax

`DecreaseAll` calculates how many leader and validator failures to account for after missed slots. Its code aimed to implement ceiling division by calculating a floating-point ratio, adding `1 - math.SmallestNonzeroFloat64`, and converting the result to `uint32`.

`math.SmallestNonzeroFloat64` is a positive subnormal value around `5e-324`. At the ordinary magnitudes of these ratios, subtracting it does not change the floating-point value. For an exact integer ratio, the expression effectively becomes `ratio + 1`; converting to an integer then adds one failure instead of returning the exact quotient.

The advisory gives a concrete batch: 21 elected validators and 105 missed slots. The correct leader count is `ceil(105 / 21)`, or 5. The implementation produced 6. With an effective consensus group of 20, the expected validator count was 100, but the implementation produced 101. Each validator processed in the batch received an extra leader-failure and validator-failure decrement. If a validator was already near a rating or jailing threshold, an extra decrement could matter.

This path is reached when the validator-state processor handles a missed-slot interval that routes through `DecreaseAll`. It is not a floating-point glitch at random: exact divisibility is precisely where the attempted “just under one” adjustment fails, because the adjustment is too small to exist at that scale.

For integer inputs, ceiling division can be stated without an epsilon: divide to get the quotient, inspect the remainder, and add one only when the remainder is non-zero. That rule behaves correctly for both the 105/21 case and an interval such as 106/21. It also gives a direct test table: exact multiples must remain unchanged, while a non-zero remainder must advance to the next whole count. A magic tiny floating-point decrement has no such dependable meaning after rounding.

The advisory is [GHSA-w99g-8m9m-jrf7](https://github.com/klever-io/klever-go/security/advisories/GHSA-w99g-8m9m-jrf7), rated Moderate and patched in `1.7.22`. GitHub credits me as a Reporter.


## Loose Change

The validator-fee issue is narrower. After a successful block, `UpdateValidatorInfoOnSuccessfulBlock` apportions accumulated transaction fees between the block leader and the other successful signers. The per-validator amount was calculated using `float64`, converted to `int64`, and then multiplied across validator recipients. The leader received the remainder.

The total still added up. The problem was who received it.

In the published reproduction, the accumulated fees were 90, the leader share was 30%, and there were two signers. Exact integer allocation gives 27 to the leader and 63 to the validator. The source's floating-point result truncated the validator's share to 62, leaving 28 for the leader. One unit moved from the validator to the leader even though the total remained 90.

This was deterministic for the boundary values that exposed the representation error, not a universal one-unit loss in every block. The advisory notes that mainnet's configured 60/40 leader/validator split did not trigger the demonstrated case for the analyzed values. With multiple validator recipients, however, a truncated per-validator value can compound as the same share is applied repeatedly.

That distinction changes the impact description. This was not inflation: the arithmetic conserved the fee pool. It was a deterministic allocation error, with a low severity rating and a `1.7.22` patched version. The report is [GHSA-x5mg-959h-f66v](https://github.com/klever-io/klever-go/security/advisories/GHSA-x5mg-959h-f66v); GitHub credits me as a Reporter.

The arithmetic path runs after a successful block and uses the proposal parameter for the leader/validator reward percentage together with the number of successful signers. The advisory records that the demonstrated 30/70 split exposes the boundary, while the analyzed mainnet 60/40 setting did not produce that exact one-unit mismatch for its tested values. Keeping that condition attached to the result avoids implying that every fee distribution or every configured percentage was affected in the same way.

Integer accounting usually makes this easier to reason about. Calculate the share as an integer numerator divided by an integer denominator, define which side receives the remainder, and ensure that the resulting allocations sum to the original amount. The division and remainder then express the policy directly instead of routing it through a floating-point approximation.

## Arithmetic needs a stated invariant

The repairs for these cases should not be reduced to “use integers everywhere” or “avoid floats.” The useful question is what invariant the operation must preserve:

- A fee split must allocate exactly the amount collected, according to a documented remainder rule.
- A missed-slot count must implement mathematical ceiling division, including when the division is exact.

Those statements are small enough to write as tests: fee shares add back to the input and match the specified split; exact and non-exact quotients produce the intended penalty counts. The tests then pin the economic or protocol rule, rather than a particular intermediate formula.

Both advisories list `1.7.22` as patched. Their official severity, metrics, affected versions, and credits remain in the linked GHSAs. The fixes address distinct paths, but each protects the same thing: a numeric value must mean what the protocol says it means when it changes rewards or validator state.
