# Yield Basis — exploit PoC harnesses

Two attack vectors from the security review were the only ones with a realistic shot at
*actual* theft (vs. DoS / centralization): the staker-rebasing accounting (b) and the
HybridVault shared crvUSD backing (c). This directory contains harnesses that try to
break them.

## Vector (b): LT staker-rebasing / admin-fee accounting — `lt_accounting_model.py`

**Approach.** `LT._calculate_values` + the staker branch of `_transfer` + the
deposit/withdraw/withdraw_admin_fees state updates are pure integer arithmetic, so they
are ported to Python with faithful EVM semantics (SDIV truncates toward zero; unsigned
floor division) and fuzzed. A mock AMM holds the single source of truth `amm_value`; the
price oracle is pinned to 1e18 to isolate the share math. After **every** operation the
harness runs a full sequential unwind (every holder withdraws, recomputing via the real
`withdraw` path) and asserts **payout ≤ amm_value** — the airtight solvency oracle —
plus a post-recompute check that the LT never *records* owing more than the AMM holds.

```
python3 poc/lt_accounting_model.py 1500
```

### Result

**At the production `min_admin_fee = 10%`, no solvency or conservation violation was found**
across 1500 seeds × 2 scenarios (random + a targeted staker-desync adversary), with the
unwind checked after every operation. The core invariant — holders can never collectively
redeem more than the AMM holds — **held**. The obvious "mint shares from rounding" theft
does **not** exist at production parameters.

### What it *did* find — admin-fee buffer loss-asymmetry (LP-fund-safety, rare)

There is one genuine accounting degeneracy. On a **loss** with stakers present
(`staked ≥ MIN_STAKED_FOR_FEES`), `LT.vy:326-328` sets `dv_use = value_change*1e18`, so
the admin buffer is **never reduced** (`prev.admin += 0`). On gains it accrues. Under a
specific adversarial sequence — sustained drawdown, most of the supply staked, and
**repeated partial unstaking** (which perturbs the `ideal_staked` loss-clawback) — the
admin buffer can ratchet **above the pool's actual value**. Then:

- `new_total = max(prev_value*1e18 + dv_use, 0)` **clamps `total` to 0**;
- `withdraw` computes `frac = 1e18*total/(total+admin)*… = 0` → **LPs withdraw nothing**
  (and burn their shares if they try);
- `withdraw_admin_fees` divides by `total == 0` → reverts (admin can't exit either);
- the value is **stranded** until a price recovery lifts `total` back above 0; a deposit
  during the window hits the first-deposit branch that resets `admin` and re-bases supply.

**Frequency (6000 adversarial seeds each):**

| `min_admin_fee` | brick rate |
|---|---|
| 10% (production default) | 0.02% (1/6000) |
| 20% | 0.03% |
| 30% | 0.07% |
| 50% | 0.50% |

**Severity: Low→Medium.** It is **not** attacker-profit theft — no third party gains; value
is stranded / LPs are temporarily unable to withdraw fair value, self-healing on price
recovery. It is reachable at the production 10% fee but only under a narrow adversarial
path, and its probability grows with the governance-set fee. **Mitigations:** cap
`set_min_admin_fee` well below 1e18; make the buffer symmetric (disgorge on losses) or
floor `frac`/guard the `total == 0` deposit/withdraw paths.

> Caveat: this is a faithful *port*, not the live bytecode. It models the share-accounting
> in isolation (oracle pinned, cryptopool treated as value-preserving). It is strong
> evidence, not a substitute for running it against the Vyper via titanoboa.

## Vector (c): HybridVault shared crvUSD backing — `test_hybridvault_shared_backing.py`

A titanoboa stateful-test harness targeting the cross-user invariant: the sum of every
HybridVault's `required_crvusd()` must never exceed the scrvUSD actually backing them, and
no vault may free more crvUSD than its position releases. **This requires the full upstream
environment (Vyper 0.4.3 + titanoboa + the `curvefi/twocrypto-ng` submodules) and was not
executed here** — the sandbox has no Vyper toolchain and the submodules are SSH-only. The
file encodes the exact invariants and setup so it can be run in a configured checkout.

```
# in a full upstream checkout:
poetry install && git submodule update --init
pytest poc/test_hybridvault_shared_backing.py -x
```
