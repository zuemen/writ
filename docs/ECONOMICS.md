# The guarantor's numbers

A model, not a market. Nobody has underwritten anything on Writ, and no source gives a default rate for AI-agent buyers. Figures marked *assumption* have no source. The site has the same model as a calculator.

## Formula

Per 1 of order value:

```
L  = p × (1 − b)                 expected loss, after the bond takes the first b
K  = (1 − b) × c × D / 365 / u   cost of the money locked behind the order; idle stake still costs
F  = (L + K) / (1 − e)           lowest fee that does not lose money
p* = (F × (1 − e) − K) / (1 − b) loss rate a given fee can absorb
c* = F × 365 / (D × (1 − b))     buyer's cost of cash above which a buyer-paid fee beats escrow
```

| Symbol | Meaning | Value | Basis |
|---|---|---|---|
| b | bond, share of the order | 20% | assumption; `bond_bps` in the mandate |
| D | terms plus inspection | 37 days | assumption; net-30 plus 7 |
| c | cost of locked money | 4.6% to 14.2% a year | USDC lending, 2026-10-05 ([DeFi Rate](https://defirate.com/lend/snapshot/2026-10-05T0151/), moves a lot); Atradius 2025 ROE ([report](https://atradius.nl/kennisbank/news/atradius-2025-strong-performance-in-a-complex-environment)) |
| e | running cost, share of the fee | 25% | assumption; credit insurers run 32.8% ([Coface FY2025](https://www.coface.com/news-economy-and-insights/2025-results-coface-closes-another-strong-year-with-net-income-at-222.0m)) |
| p | loss rate | scenario | assumption |
| u | share of stake in use | 60% | assumption |

For scale on p: claims of €3.39B against about €9.25T of supported trade give 0.037% on insured books (derived from [ICISA](https://icisa.org/?p=21395) figures; the two populations may differ, so treat it as a floor). Self-reported bad debt in Western Europe is about 6% ([Atradius survey](https://group.atradius.com/knowledge-and-research/news/what-did-a-year-of-b2b-payment-disruption-teach-us)). The definitions differ. The roughly 160× gap is what screening and policy terms are worth, and nothing tells us where a new book of agent buyers would sit.

## A $10,000 order

At 60% of stake in use. The top of the range overlaps B2B BNPL.

| Loss rate p | L | F at c=4.6% | F at c=14.2% | Fee on $10,000 |
|---|---|---|---|---|
| 0.037% | 0.03% | 0.87% | 2.60% | $87–260 |
| 1% | 0.80% | 1.90% | 3.63% | $190–363 |
| 2% | 1.60% | 2.96% | 4.69% | $296–469 |
| 6% | 4.80% | 7.23% | 8.96% | $723–896 |

At low loss rates most of the cost is locked money, not losses. A fully reserved guarantee cannot reach an insurer's price. That is the honest answer to "why is this dearer than credit insurance?"

A flat 2% fee absorbs a loss rate of up to 1.10% at c=4.6%, and none at c=14.2%. Without screening, a guarantor at that price loses money.

## Suggested price tiers

| Tier | Bond | Assumed p | Cost range | Fee |
|---|---|---|---|---|
| A: guarantor knows the buyer well | 50% | 0.5% | 0.85–1.93% | 1.00% |
| B: standard | 20% | 1% | 1.90–3.63% | 2.25% |
| C: higher risk | 20% | 3% | 4.03–5.76% | 4.50% |
| Decline | | about 4% and up | above B2B BNPL's range | |

## Guarantor's return, per $1M staked, one year

2.25% fee, 20% bond, 25% running cost, 37-day cycle, fully reserved.

| Scenario | Volume | Fees | Losses | Costs | Net | Return |
|---|---|---|---|---|---|---|
| p=1%, 60% of stake in use | $7.40M | $166.5k | $59.2k | $41.6k | $65.7k | 6.6% |
| p=1%, 100% in use | $12.33M | $277.4k | $98.6k | $69.4k | $109.4k | 10.9% |
| p=6%, 60% in use | $7.40M | $166.5k | $355.1k | $41.6k | −$230.3k | −23.0% |

The 2.25% fee covers the cost of locked money only near the bottom of the range: at c=14.2% it loses money against that hurdle. Compare 4.6% for lending with no buyer risk, and 14.2% for Atradius's ROE. A purely financial guarantor earns less than an insurer here. So the first guarantor is more likely a party that already knows the buyer and gains from the sale, such as a platform hosting the buyer's agents. That is a hypothesis; nobody has been asked.

## Why a buyer would use it

A buyer-paid fee beats escrow only above c* of about 25% a year (2% fee, 37 days, 20% bond). That attracts buyers who cannot borrow cheaply, which is adverse selection. Two things help: the seller pays the fee to close the sale (`fee_payer`), and usage-priced orders, where the amount is unknown until delivery and escrow must over-lock.

## What this does not show

- Agent payment volume today is tiny: about $5,000–11,000 a month through x402 by [TRM Labs' estimate](https://www.trmlabs.com/trm-tech-blog/whos-actually-paying-measuring-ai-agent-payments-onchain). Do not use it as a market size.
- Writ takes no protocol fee. A business would need a share of the fee or tools sold to guarantors.
- Charging for guarantees is probably regulated. The guarantor would need its own licence or legal opinion.
