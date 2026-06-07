# Yield Basis (yb-core) — Security Review

**Reviewer:** Claude (AI-assisted security review)
**Date:** 2026-06-07
**Scope:** Core protocol Vyper contracts (AMM, leveraged token, vault, factory, oracles, migrator) + DAO/governance contracts.

> ⚠️ This is an AI-assisted review intended to surface candidate issues, document the
> trust model, and prioritize areas for a professional audit. It is **not** a substitute
> for a formal audit + economic modeling + full test/fuzz execution. Where I could not
> confirm exploitability by static inspection, findings are labelled accordingly.

---

## 0. Provenance / "is this repo outdated?" — YES

The checked-out repo (`jtdoherty/yb-core`, default `master`) is **~9 months stale**.

| | Commit | Date |
|---|---|---|
| This repo HEAD | `0bf9715` | 2025-09-08 |
| Upstream `yield-basis/yb-core` HEAD | `ea1c758` | 2026-06-07 |

The upstream protocol has materially changed since this snapshot. **This review was performed
against the live upstream code** (`yield-basis/yb-core@ea1c758`), not the stale local copy.

Key architectural changes upstream vs. this local copy:

- **Removed:** `LT-Restricted.vy` (894 lines).
- **Added:** `HybridVault.vy` (858 lines, per-user combined YB + scrvUSD vault),
  `HybridVaultFactory.vy`, `HybridFactoryOwner.vy`, `MigrationFactoryOwner.vy`,
  `LTMigrator.vy`, `utils/YBLendingOracle.vy`, `dao/FeeDistributor.vy`,
  `dao/CallComparator.vy`, `dao/SnapshotSplitter.vy`, `dao/Multisend.vy`, `dao/TokenSender.vy`.
- **Modified:** `AMM.vy`, `LT.vy`, `Factory.vy`, `CryptopoolLPOracle.vy`,
  `VirtualPool.vy`, `LiquidityGauge.vy`, `VotingEscrow.vy`, `GaugeController.vy`.
- The vendored `twocrypto` test pool was replaced with git submodules
  (`curvefi/twocrypto-ng`, branches `fxswap-ext-fee` and `feat/lp-oracle`).

**Recommendation:** if you intend to keep auditing/working here, sync this fork to upstream
first (`git remote add upstream https://github.com/yield-basis/yb-core && git fetch upstream`),
otherwise you are reviewing code that is no longer deployed.

---

## 1. Architecture & trust model (as reviewed)

```
            crvUSD reserve (Factory / allocators / crvUSD mint factory)
                              │ allocate_stablecoins (debt ceiling)
                              ▼
 user asset (e.g. tBTC) ─▶ LT.vy (ERC20 share token, ERC4626-ish)
                              │  borrows crvUSD from AMM, LPs into Curve twocrypto
                              ▼
                          AMM.vy  ("LEVAMM": constant 2× leverage AMM)
                              │  holds Curve LP as collateral + crvUSD debt
                              ▼
                      Curve twocrypto pool (crvUSD / asset)
```

- **AMM.vy ("LEVAMM"):** holds Curve-LP collateral + crvUSD debt, maintains a
  constant-leverage invariant via `x0`. Re-leverages on every trade. Only `LT_CONTRACT`
  may `_deposit`/`_withdraw`/`set_rate`/`set_fee`/`set_killed`; `exchange` is public.
- **LT.vy:** the user-facing leveraged-liquidity token. Mints/burns shares against the AMM's
  oracle value, runs the staker-rebasing/admin-fee accounting (`_calculate_values`).
- **Factory.vy:** blueprints markets (price oracle → LT → AMM → vpool → staker); holds the
  crvUSD reserve and approves each LT to pull it.
- **HybridVault.vy / HybridVaultFactory.vy:** per-user (EIP-1167 minimal-proxy) vaults that
  co-manage a YB position and an scrvUSD buffer, with shared crvUSD-backing accounting.
- **HybridFactoryOwner / MigrationFactoryOwner:** privileged admin proxies that own the
  Factory and gate `allocate_stablecoins`, market creation, kill switch, etc.
- **Oracles:** `CryptopoolLPOracle.vy` (LP price), `utils/YBLendingOracle.vy` (prices a YB
  LT position for an *external* crvUSD lending market).

### Centralization / privileged powers (by design — document for users)
- `Factory.admin` (a FactoryOwner proxy, ultimately the DAO) can: add markets, set
  implementations, set the price aggregator (`set_agg`), set the flash lender, set fee
  receiver, set min admin fee, and **approve the crvUSD `mint_factory` for `max_uint`
  (one-time, irreversible)**.
- `set_agg` / `set_flash` / `set_implementations` change pricing and execution for **live**
  markets. A malicious or compromised admin can effectively reprice or brick markets.
  `set_agg` is sanity-bounded (`0.9 < price < 1.1`); `set_flash`/`set_implementations` are not.
- `emergency_admin` can kill markets and withdraw-for-others (to themselves) when killed.
- `limit_setters` on `HybridFactoryOwner` can raise an LT's crvUSD allocation up to the
  collateral-backed `available_limit` — i.e., pull protocol crvUSD reserve into an AMM.
  These must be trusted contracts (HybridVaultFactory, LTMigrator).

**Trust assumption:** the entire system trusts (a) the Curve twocrypto pool, (b) the crvUSD
price aggregator, and (c) the DAO/admin proxies. Compromise of any of these is catastrophic
and is outside the scope of the contract logic itself.

---

## 2. Findings

Severity reflects *potential* impact; several require economic modeling / test execution to
confirm. No unconditional fund-loss bug was found by static inspection of the core AMM
invariant, which is encoded defensively (`assert get_x0(...) >= x0` on every trade).

### M-1 — Liveness: borrower-fee distribution can revert and block every trade/deposit/withdraw
**Contracts:** `LT.vy:854-869` (`_distribute_borrower_fees`), called from `AMM.exchange`
(`AMM.vy:361-363`) and at the end of `LT.deposit`/`LT.withdraw`.

Every `exchange`/`deposit`/`withdraw` ends by sweeping the LT's crvUSD balance into the
Curve pool via single-sided `add_liquidity([amount, 0], min_amount, donation=True)` with
`min_amount = (1e18 - discount) * amount / lp_price` and `discount = 1%` (`FEE_CLAIM_DISCOUNT`).
If a single-sided crvUSD deposit into an imbalanced twocrypto pool incurs **> 1% slippage/fee**,
this call reverts, which reverts the *entire* outer transaction. An attacker can push the
twocrypto pool out of balance to make single-sided crvUSD deposits exceed the 1% buffer,
temporarily **denying all AMM trades, deposits and withdrawals** for that market.

Mitigating factors: only triggers when pending borrower fees > 0; the imbalance is
self-correcting and costs the attacker (arbitrage restores it); `emergency_withdraw` does
**not** call this path, so user exit is preserved. The code comment at `LT.vy:863-866`
explicitly acknowledges a "temporary denial of service." Still, a cheap, repeatable grief on
core liveness deserves a hard look (e.g., make the fee sweep best-effort / `raw_call` with
`revert_on_failure=False`, or skip when slippage would exceed the buffer rather than reverting).

### M-2 — Critical accounting logic is duplicated across two contracts and must stay byte-for-byte in sync
**Contracts:** `LT.vy:289-392` (`_calculate_values`) vs.
`utils/YBLendingOracle.vy:80-147` (`_calculate_fresh_lv`).

`YBLendingOracle` re-implements LT's staker-rebasing / admin-fee math to price a YB position
for an **external crvUSD lending market**. The two copies currently match, but any future
change to `_calculate_values` that is not mirrored will make the lending oracle misprice
collateral — directly enabling bad-debt or unfair liquidations in the *lending* market that
consumes this oracle. This is a structural risk, not a present bug.

**Recommendation:** factor the shared math into a single imported Vyper module/library used by
both, or add an invariant test that asserts the two produce identical outputs over fuzzed state.

### M-3 — `_calculate_values` staker-rebasing math is complex, signed, and unverifiable by inspection
**Contract:** `LT.vy:289-392` (and the YBLendingOracle twin).

This is the economic heart of the protocol: signed 1e36-fixed-point arithmetic, `mul_div_signed`,
`token_reduction` clamps (`max_token_reduction`, `staked-1`, `supply-1`, the `SQRT_MIN_UNSTAKED_FRACTION`
guard, the `< 1e4*1e18` denominator guard). It allocates value between stakers, total supply,
and an `admin` buffer that can go **negative** (losses). Several rounding/clamp choices
(`mul_div_signed` truncates toward zero; `dv_s_36` is min-clamped only when positive;
`prev.admin` can be negative and is socialized in withdraws via `max(admin,0)`) are plausible
but **cannot be validated without the whitepaper math + the Hypothesis stateful tests**
(`tests/lt/test_st_staker.py`, `tests/fuzz/`).

**Recommendation:** treat as the #1 target for formal/economic review. Confirm: (a) sum of
`staked_value + (supply-staked)_value` is conserved (no value minted from rounding), (b)
`pricePerShare()` is monotonic except for genuine losses, (c) `admin` going negative cannot be
weaponized to mint shares in `withdraw_admin_fees` (`LT.vy:882-914` asserts `v.admin >= 0`,
good) or to dilute the staker.

### L-1 — Oracle availability coupling: when the AMM enters the "untradable" region, normal pricing/withdraw revert
**Contracts:** `AMM.get_x0` (`AMM.vy:142-157`, `D` can underflow → revert),
`AMM.value_oracle`/`get_state`, consumed by `LT.pricePerShare`, `LT.withdraw`,
`CryptopoolLPOracle`/`YBLendingOracle`.

By design, on a large adverse move `get_x0`'s discriminant underflows and `value_oracle()`
reverts. The protocol handles this with `raw_call(..., revert_on_failure=False)` fallbacks in
`LT.emergency_withdraw` (`LT.vy:643-654`), `YBLendingOracle._price` (`:179-214`), and
`HybridVault._pool_crvusd` (`:278-290`) — and `emergency_withdraw` remains available. But
`LT.withdraw` and `LT.pricePerShare` will **revert** in that state, so any integrator relying on
`pricePerShare()` as a live oracle (or on `withdraw`) experiences an outage until price recovers
or the market is killed. Confirm all downstream consumers (esp. external lending markets) treat
an oracle revert as "pause," not as a zero/garbage price.

### L-2 — `HybridVault` shared crvUSD-backing accounting uses magic factors and per-pool sentinels
**Contract:** `HybridVault.vy` (`deposit` `:413-474`, `withdraw` `:478-559`,
`emergency_withdraw` `:563-668`), `LTMigrator.vy:197-209`.

The "downscale by `stablecoin_fraction`", `*22/10` over-allocation, `2 * additional_crvusd`
tracking, and the `disabled_lts` / `allocation == 1` sentinel handshake between `LTMigrator`
and `HybridFactoryOwner` form an intricate state machine across four contracts. I did not find
a concrete drain, but the surface (multiple HybridVaults competing for one LT's global
`stablecoin_allocation`, the `update_vault_required` limit accounting in
`HybridVaultFactory.vy:166-193`) is exactly where shared-pool DeFi bugs live. Worth dedicated
fuzzing of concurrent deposit/withdraw/emergency across several vaults on one market.

### L-3 — `set_agg` / `set_flash` repricing & execution-path swaps on live markets
**Contract:** `Factory.vy:322-341`, exposed via `HybridFactoryOwner.set_agg/set_flash`.

`set_agg` swaps the USD aggregator for **all** markets at once (only loosely bounded to
[0.9,1.1]); `set_flash` swaps the flash lender the `VirtualPool` depends on. Both are admin-only
but instantly affect live pricing/execution with no timelock at this layer (the DAO may add one
above). Document and consider a per-call timelock/guardian.

### I-1 — `erc4626.vy` genesis branches are unusual
**Contract:** `dao/erc4626.vy:462-488`.

`_convert_to_shares` returns `assets + total_assets()` and `_convert_to_assets` returns
`shares - total_assets()` when `supply == 0`. The latter can underflow-revert if assets were
donated before the first deposit. The vault is otherwise protected against the classic inflation
attack by the `MIN_SHARES` floor and the snekmate `+1` virtual offset, and these branches only
execute at genesis (factory-seeded), so impact is limited. Confirm first-deposit is performed
atomically by the factory/deployer.

### I-2 — EIP-1167 minimal proxy + Vyper immutables (verified SAFE — noted to pre-empt confusion)
`HybridVault` is deployed via `create_minimal_proxy_to` yet reads `immutable` `FACTORY`,
`CRVUSD`, `VAULT_FACTORY`. This is **correct**: under `DELEGATECALL` the executing code is the
implementation's, so `CODECOPY`-based immutables resolve against the implementation bytecode.
Per-proxy storage (`owner`, `crvusd_vault`) is independent, and the implementation pins itself
with `owner = 0x...01` to block direct init. No issue — flagged only because this pattern is a
frequent source of false bug reports.

### I-3 — `initialize` front-running (not exploitable as wired)
`HybridVault.initialize` (`:127-141`) is guarded by `owner == empty(address)` and is called
**atomically** inside `HybridVaultFactory.create_vault` (`:90-91`), so there is no window to
front-run it. Safe as long as no deployment path creates a proxy without initializing it in the
same transaction.

---

## 3. Things checked and found OK (non-exhaustive)
- **Core AMM value invariant:** every `exchange`/`_deposit` enforces `get_x0_after >= x0` and
  safe-debt bounds; trade fees accrue to LPs (kept as extra collateral / reduced debt). No path
  found to extract value below the invariant. (`AMM.vy:337-356`, `318-335`)
- **Access control on privileged AMM/LT setters:** `set_rate`/`set_fee`/`_deposit`/`_withdraw`/
  `set_killed` are `LT_CONTRACT`-gated; LT admin setters go through `_check_admin`. Factory and
  the two FactoryOwner proxies consistently gate state-changers on `ADMIN`.
- **Reentrancy:** core mutating entry points are `@nonreentrant`; crvUSD and Curve-LP tokens
  have no transfer callbacks. ERC4626 staker uses burn-before-transfer ordering.
- **First-deposit inflation on LT:** LT values positions from the AMM's internal `x0`/oracle,
  not `balanceOf`, so token donations don't move share price; `MIN_SHARE_REMAINDER` enforced.

---

## 4. DAO / governance contracts

The DAO contracts are **not** light Curve forks. `VotingEscrow` was reworked into an
NFT-style ve with infinite locks and position-merging on transfer, and `GaugeController` /
`LiquidityGauge` / `FeeDistributor` re-implement the emissions/accounting from scratch. The
"audited Curve original" comparison therefore gives limited assurance for those three.

### DH-1 (High) — `FeeDistributor` claim DoS via a zero-ve-supply funded epoch
**Contract:** `dao/FeeDistributor.vy:193` — `amount = balances_for_epoch[epoch][token] * votes // total_votes`.
`total_votes = VE.getPastTotalSupply(epoch)` has **no zero guard**, and claims advance
`last_claimed_for[user]` strictly week-by-week (cannot skip an epoch). If any epoch was funded
(`_fill_epochs`) during a week when total ve voting supply was 0 — plausible early on, or any
week where all locks have expired — the `// total_votes` divides by zero and reverts. Because the
claim loop must pass through that epoch, **that epoch's fees and all later fees become
permanently unclaimable for affected users.** Curve's FeeDistributor explicitly does
`if ve_supply == 0: continue`; that guard was dropped here. **Verified** by direct inspection.
**Fix:** skip epochs where `total_votes == 0`.

### DM-1 (Medium) — `GaugeController`: killing a gauge does not stop its emissions
**Contract:** `dao/GaugeController.vy` — `is_killed` is read **only** at `:232`
(`vote_for_gauge_weights`, blocking *new* weight). `_checkpoint_gauge` (`:152`) and `emit`
(`:351`) never consult `is_killed`, so a killed gauge keeps its existing vote-derived weight and
keeps accruing/claiming YB. This diverges from Curve, where a killed gauge gets zero weight. The
doc comment at `:370` ("if unkilled — all accumulated emissions get available") implies kill was
meant to *pause* emissions, but the code doesn't. Governance has no effective off-switch for a
malicious/broken gauge short of convincing all voters to manually zero their weight.
**Verified** by direct inspection. **Fix:** force adjusted weight to 0 for killed gauges in
`_checkpoint_gauge`.

### DL-1 (Low) — `LiquidityGauge.previewMint` is unreachable (EIP-4626 break)
`dao/LiquidityGauge.vy:513` defines a rebase-aware `previewMint` but is **missing `@external`**,
so it compiles as a private function; meanwhile the base `erc4626.previewMint` is not in the
gauge's `exports:` list. Net: `previewMint` is uncallable on the deployed gauge, breaking
EIP-4626 conformance for integrators. (All other preview/convert functions are correctly external.)

### DL-2 (Low) — `Multisend` ignores `transferFrom` return value
`dao/Multisend.vy:30` calls `transferFrom` without `default_return_value=True` and without
asserting the bool. For a `False`-returning ERC20 the single-use guard `already_sent[user]` would
be set without the transfer succeeding, blocking retry. Admin-only and intended for YB (which
reverts on failure), so impact is limited, but inconsistent with the rest of the codebase.

### DL-3 (Low) — `FeeDistributor` permissionless claim + heuristic cliff detection
`dao/FeeDistributor.vy:220-253` — `claim(receiver, …)` is permissionless and relies on
`_similar_to_cliff_escrow` (a `method_id("VE()")` probe) to route funds correctly for
cliff-escrow receivers. Third parties cannot steal funds, but a cliff-like contract that doesn't
expose `VE()`, or a contract that deliberately matches the probe, can cause **misattribution** of
claimed fees. Document the trust assumption.

### DAO — informational
- **VotingEscrow:** forward `total_supply_at` projection is slightly off unless `checkpoint()`
  is called first; FeeDistributor mitigates by calling `VE.checkpoint()`. `increase_amount` is a
  permissionless deposit-for (benefits recipient only; no griefing path found given the
  strict same-slope merge conditions in `_ve_transfer_allowed`).
- **LiquidityGauge** maintains two notions of total assets (`balanceOf` vs.
  `LT.updated_balances()`), reconciled by `checkpoint_staker_rebase()` at the top of every
  state-changing entrypoint — intentional rebase handling, correctness depends on
  `LT.checkpoint_staker_rebase` (see M-3).

### DAO — clean / no material findings
`CliffEscrow.vy`, `YB.vy` (minter-gated `emit`, no `reserve` underflow), `InflationaryVest.vy`,
`VestingEscrow.vy`, `SnapshotSplitter.vy` (claims only after ownership renounced),
`CallComparator.vy`, `VotingPowerCondition.vy`, `TokenSender.vy`, `StakeZap.vy` (redeems only the
caller's own shares) — reviewed, no access-control or arithmetic issues found.

---

## 5. Recommended next steps
1. **Sync this fork to upstream** before any further work (section 0).
2. Run the upstream suite (`poetry install && pytest -n auto`, incl. `tests/fuzz` and
   `tests/lt/test_st_staker.py`, `test_oracle_shift_attack.py`) — none were executed here
   (no Vyper toolchain in this environment).
3. Prioritize formal/economic review of `LT._calculate_values` (M-3) and de-duplicate it from
   `YBLendingOracle` (M-2).
4. Make the borrower-fee sweep non-reverting (M-1).
5. Fuzz concurrent multi-vault HybridVault flows on a single market (L-2).
6. **DAO:** add the `total_votes == 0` skip in FeeDistributor (DH-1) and make gauge-kill
   actually zero emissions in GaugeController (DM-1) — both are deviations from audited Curve
   semantics that affect fund safety / governance control.

---

## Appendix — severity legend
Critical = unconditional loss of funds; High = loss/lockup of funds under a plausible
precondition; Medium = limited loss, liveness/DoS, or loss of a safety lever; Low = minor /
hard-to-trigger / spec-conformance; Informational = no direct risk. Findings not confirmed by
execution are marked as requiring tests/economic modeling.
