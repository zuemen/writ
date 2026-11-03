# The guarantor's numbers

A model, not a market. Nobody has underwritten anything on Writ. Figures marked *assumption* have no source.

## Cover: what a guarantor would have to charge

**Nobody has data on how often agents get fooled.** We can't compute a loss rate, so we can't compute a price. We only know the floor.

The guarantor locks the whole limit for as long as cover runs, and can't lend or reuse it. Per 1 of limit, per year:

```
F = (c + p × (1 − s)) / (1 − e)      lowest yearly fee that does not lose money
```

| Symbol | Meaning | Value | Basis |
|---|---|---|---|
| c | cost of locked money | 4.6% to 14.2% a year | USDC lending rate we read on 2026-10-05 (the source no longer keeps that snapshot, and the rate moves a lot); Atradius 2025 ROE ([report](https://atradius.nl/kennisbank/news/atradius-2025-strong-performance-in-a-complex-environment)) |
| p | loss rate, share of the limit lost to fooled payments a year | scenario | assumption; **no data exists** |
| s | the company's share of each loss | 20% | the demo's terms; the contract allows 10% to 90% |
| e | running cost, share of the fee | 25% | assumption; credit insurers run 32.8% ([Coface FY2025](https://www.coface.com/news-economy-and-insights/2025-results-coface-closes-another-strong-year-with-net-income-at-222.0m)) |

| Loss rate p (assumption) | F at c=4.6% | F at c=14.2% | Fee on a $100,000 limit |
|---|---|---|---|
| 0% | 6.13% | 18.93% | $6,133–18,933 |
| 1% | 7.20% | 20.00% | $7,200–20,000 |
| 2% | 8.27% | 21.07% | $8,267–21,067 |
| 5% | 11.47% | 24.27% | $11,467–24,267 |
| 10% | 16.80% | 29.60% | $16,800–29,600 |

**The cost floor is c itself, 4.6–14.2% of the limit a year, before any claim or running cost.** Fully locked money is why this is expensive. An insurer pools risk and reuses capital; a guarantor here doesn't. That is what makes the payment certain, and what makes it cost more.

**The demo's fee is a placeholder.** It charges 2% per 30 days, about 24% of the limit a year (24.33%). No one priced that. It would absorb a loss rate of about 17% at c=4.6% and about 5% at c=14.2%, with the assumptions above.

How the fee works in the contract:

- It is charged once, at activation, for every started 30-day period to `valid_until`.
- At register it must leave one maximum payment under what the cover can pay, so on a long mandate it can still come close to the limit. The guarantor chooses when to activate, within the first half of the term.
- A guarantor that revokes keeps the fee for periods already started, which can be two periods even after a few seconds, and returns the rest, as far as its free stake reaches. Its lock isn't released early, so revoking doesn't free its money. A company revoking its own mandate gets no fee back.

Whether anyone would pay this is untested. Nobody has been asked. Offering it for real money may be regulated insurance or guarantee business, depending on the jurisdiction; no lawyer has reviewed it.

### What you would have to believe

No customer behind this; every input is an assumption. An agent pays $12M a year in invoices. Its mandate caps one payment at $5,000 and a day at $20,000, and the company reviews payments every 3 days, so one undetected run costs at most $60,000. That is the limit, not the $12M: filing a claim stops the whole tree. (The contract requires a limit of at least 10 maximum payments; $60,000 is 12.)

Same formula, s=20%, e=25%. Loss rate p = fooled payments × $5,000 / $60,000.

| Fooled $5,000 payments a year | p | Fee a year, c=4.6% to 14.2% | Share of $12M | The company gets back a year | Back per $1 of fee |
|---|---|---|---|---|---|
| 0 | 0% | $3,680–11,360 | 0.03–0.09% | $0 | $0 |
| 1 every 4 years | 2.08% | $5,013–12,693 | 0.04–0.11% | $1,000 | $0.08–0.20 |
| 1 | 8.33% | $9,013–16,693 | 0.08–0.14% | $4,000 | $0.24–0.44 |
| 3 | 25% | $19,680–27,360 | 0.16–0.23% | $12,000 | $0.44–0.61 |

Read the last column first. A company paying this itself gets back less than it pays, in every row, and full locking is why. So it would buy for another reason (a board or auditor that won't let an agent pay without it), or someone else pays.

### Who would pay, if not the company

Our first guess is the vendor of the agent, standing behind its own product to win a customer. It knows the agent, and it can fix what gets fooled, which a financial guarantor can't. Nobody has been asked, and nobody has agreed. The nearest public example we found is different in kind: [ElevenLabs](https://elevenlabs.io/blog/aiuc-announcement) insuring its own voice agents through an insurer, so that "risks associated with using AI, like an AI agent providing incorrect information to a customer, can now be insured against". That shows a vendor wanting this; it doesn't show one locking money. Merchants point the same way: "93% of merchants believe that AI or agent providers should bear the financial loss when an agent makes an incorrect purchase" ([Forkast](https://forkast.news/the-agentic-commerce-liability-gap-who-pays-when-the-agent-buys-wrong/), citing PYMNTS Intelligence, September 2026; we haven't read the PYMNTS report). That is sellers talking about incorrect purchases, not vendors agreeing to pay.

On the example above, for one customer, before any running cost: locked money $2,760–8,520 a year, plus $4,000 repaid if one payment is fooled, so $6,760–12,520. Ten such customers lock $600,000. The vendor should do this only if the cover wins sales worth more than that. Whether it does is untested.

What this doesn't solve: the arbiter's pay isn't in this model and the contract has no arbiter fee; a claim stops the tree for up to 14 days by default, so a small loss may not be worth filing unless each agent has its own tree; and a vendor backing its own product may still be regulated. No lawyer has reviewed it.

### Public cases

What each would do on Writ is our reading of the rules, not a test.

| Case | What happened | On Writ |
|---|---|---|
| [Grok and Bankrbot](https://incidentdatabase.ai/cite/1556/) | "An X user reportedly induced Grok and Bankrbot to transfer 3 billion DRB tokens, then valued at about $200,000." The same entry says "linked funds were later returned or converted." | The payee isn't in the mandate, so `SCOPE` refuses it. No loss, no claim. This is the firewall half. |
| [FBI IC3, 2025](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf) | $3,046,598,558 reported lost to business email compromise, in 24,768 complaints. People were fooled, not agents, and many of these change the payee. | Changed payees: `SCOPE`. It can't be used as a loss rate for Writ. |
| Our demo: a re-bill with a fake controller note | The model paid 10 of 10 (small sample), and every check passes. | The case cover is for. **We found no public case of this happening to an agent.** |

The gap matters: public cases show agents do get talked out of money, but they fall in the half an allowlist stops. Whether the other half is common enough to pay for is what nobody knows yet.

## Second use: net-30 for sellers

The same stake can back orders on credit. No source gives a default rate for AI-agent buyers either. The rest of this page is that model. `exposure` counts orders and locked cover together, so one dollar can't back both.

### Formula

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
| c | cost of locked money | 4.6% to 14.2% a year | USDC lending rate we read on 2026-10-05 (the source no longer keeps that snapshot, and the rate moves a lot); Atradius 2025 ROE ([report](https://atradius.nl/kennisbank/news/atradius-2025-strong-performance-in-a-complex-environment)) |
| e | running cost, share of the fee | 25% | assumption; credit insurers run 32.8% ([Coface FY2025](https://www.coface.com/news-economy-and-insights/2025-results-coface-closes-another-strong-year-with-net-income-at-222.0m)) |
| p | loss rate | scenario | assumption |
| u | share of stake in use | 60% | assumption |

For scale on p: claims of €3.39B against about €9.25T of supported trade give 0.037% on insured books (derived from [ICISA](https://icisa.org/?p=21395) figures; the two populations may differ, so treat it as a floor). Self-reported bad debt in Western Europe is about 6% ([Atradius survey](https://group.atradius.com/knowledge-and-research/news/what-did-a-year-of-b2b-payment-disruption-teach-us)). The definitions differ. The roughly 160× gap is what screening and policy terms are worth, and nothing tells us where a new book of agent buyers would sit.

### A $10,000 order

At 60% of stake in use. The top of the range overlaps B2B BNPL.

| Loss rate p | L | F at c=4.6% | F at c=14.2% | Fee on $10,000 |
|---|---|---|---|---|
| 0.037% | 0.03% | 0.87% | 2.60% | $87–260 |
| 1% | 0.80% | 1.90% | 3.63% | $190–363 |
| 2% | 1.60% | 2.96% | 4.69% | $296–469 |
| 6% | 4.80% | 7.23% | 8.96% | $723–896 |

At low loss rates most of the cost is locked money, not losses. A fully reserved guarantee cannot reach an insurer's price. That is the honest answer to "why is this dearer than credit insurance?"

A flat 2% fee absorbs a loss rate of up to 1.10% at c=4.6%, and none at c=14.2%. Without screening, a guarantor at that price loses money.

### Suggested price tiers

| Tier | Bond | Assumed p | Cost range | Fee |
|---|---|---|---|---|
| A: guarantor knows the buyer well | 50% | 0.5% | 0.85–1.93% | 1.00% |
| B: standard | 20% | 1% | 1.90–3.63% | 2.25% |
| C: higher risk | 20% | 3% | 4.03–5.76% | 4.50% |
| Decline | | about 4% and up | above B2B BNPL's range | |

### Guarantor's return, per $1M staked, one year

2.25% fee, 20% bond, 25% running cost, 37-day cycle, fully reserved.

| Scenario | Volume | Fees | Losses | Costs | Net | Return |
|---|---|---|---|---|---|---|
| p=1%, 60% of stake in use | $7.40M | $166.5k | $59.2k | $41.6k | $65.7k | 6.6% |
| p=1%, 100% in use | $12.33M | $277.4k | $98.6k | $69.4k | $109.4k | 10.9% |
| p=6%, 60% in use | $7.40M | $166.5k | $355.1k | $41.6k | −$230.3k | −23.0% |

The 2.25% fee covers the cost of locked money only near the bottom of the range: at c=14.2% it loses money against that hurdle. Compare 4.6% for lending with no buyer risk, and 14.2% for Atradius's ROE. A purely financial guarantor earns less than an insurer here. So the first guarantor is more likely a party that already knows the buyer and gains from the sale, such as a platform hosting the buyer's agents. That is a hypothesis; nobody has been asked.

### Why a buyer would use it

A buyer-paid fee beats escrow only above c* of about 25% a year (2% fee, 37 days, 20% bond). That attracts buyers who cannot borrow cheaply, which is adverse selection. Two things help: the seller pays the fee to close the sale (`fee_payer`), and usage-priced orders, where the amount is unknown until delivery and escrow must over-lock.

### What this does not show

- Agent payment volume today is tiny: about $5,000–11,000 a month through x402 by [TRM Labs' estimate](https://www.trmlabs.com/trm-tech-blog/whos-actually-paying-measuring-ai-agent-payments-onchain). Do not use it as a market size.
- Writ takes no protocol fee. A business would need a share of the fee or tools sold to guarantors.
- Charging for guarantees is probably regulated. The guarantor would need its own licence or legal opinion.
