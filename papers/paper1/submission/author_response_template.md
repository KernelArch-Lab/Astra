# Author response template

> Use this skeleton during the rebuttal window. ATC typically gives
> 500–700 words. Don't fight every comment — pick the 3 highest-leverage.

---

We thank the reviewers for their detailed and constructive feedback.
Below we respond to the points that most affect the paper's standing,
in priority order.

## R1: [most important review concern]

**Concern.** [Short paraphrase, ≤2 sentences.]

**Response.** [≤120 words. State precisely what you will change in the
revision, not just defensiveness. If you ran an additional measurement
during rebuttal, lead with that.]

[If the reviewer's concern is wrong: explain WHY they're wrong with
hard evidence (a citation, a number, a code pointer), not by
restating the original claim louder.]

## R2: [second-most important concern, e.g. C++ language choice]

**Concern.** [Paraphrase.]

**Response.** Our position on the language choice is documented in
§7.1: capability discipline can be retrofitted onto an unsafe-language
ecosystem with constant-time primitives, oracle-checked tests, a
libFuzzer harness, and a CBMC monotonicity proof. We are not claiming
the language is safe; we are claiming the *capability layer* is
defensible regardless. A Rust port of the hot path is on our roadmap
conditional on reviewer feedback; we will note this explicitly in §7.

## R3: [missing baseline, e.g. "did you try TENS?"]

**Concern.** [Paraphrase.]

**Response.** [If the baseline is gettable in the rebuttal window:
"We have run TENS in the rebuttal window; numbers in
Table~R3.1 below." If not: "TENS is not deployable in our environment
because [specific reason]; we will cite the published TENS numbers
[ref] and note the caveat in §6."]

## R4–R6: smaller items (per reviewer)

R4 [≤50 words]: ...
R5 [≤50 words]: ...
R6 [≤50 words]: ...

## Promised revisions, summarised

| Section | Promised change | Reviewer |
|---|---|---|
| §1     | Soften "first" claim to "first software-only on stock Linux"   | R1     |
| §6.1   | Add bootstrapped 95% CI to Table 1                              | R3     |
| §7.1   | Note Rust port on roadmap                                       | R2     |
| §8     | Cite TENS [ref]                                                 | R3     |

We thank the reviewers again for their time and look forward to the
revision.

— Authors
