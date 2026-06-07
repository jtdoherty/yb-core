#!/usr/bin/env python3
"""
PoC fuzz harness for Yield Basis LT staker-rebasing accounting (vector "b").

It ports LT._calculate_values + the staker branch of _transfer + the
deposit/withdraw/withdraw_admin_fees state updates from contracts/LT.vy
(upstream yield-basis/yb-core@ea1c758) to Python with FAITHFUL EVM integer
semantics (SDIV truncates toward zero; unsigned floor division).

A mock AMM holds the single source of truth `amm_value` (== value_oracle().value).
We keep the price oracle p_o == 1e18 so cur_value == amm_value, isolating the
share-accounting math from oracle/cryptopool effects.

The protocol is solvent iff, at every state, the value the LT *thinks* it owes
holders does not exceed what the AMM actually holds. After every operation we assert:

  POST-RECOMPUTE: right after an op that commits _calculate_values, in the
                  admin>=0 regime, total+admin must NOT exceed cur_value (the
                  insolvent direction). [admin<0 = documented loss socialization]
  INV2 (bounds):  staked_value <= total ; balanceOf[staker] <= totalSupply
  UNWIND:         the airtight oracle — a full sequential unwind of EVERY holder
                  (recomputing via withdraw) pays out <= amm_value; amm never < 0.

RESULT (this run): at the production min_admin_fee = 10%, NO violation across
1500 seeds x 2 scenarios. The only state that breaks conservation is reachable
only at a pathological min_admin_fee >= ~50% combined with extreme volatility AND
partial unstaking: the admin-fee buffer (LT.vy:326-328 never disgorges on losses
when staked>=MIN) ratchets above the pool value, `total` clamps to 0, and LP
withdrawals compute frac=0 (funds stranded). See poc/README.md.

Run: python3 poc/lt_accounting_model.py        # defaults to 1500 seeds
"""
import math
import random

WEEK = 0
PREC = 10**18
MIN_STAKED_FOR_FEES = 10**16
SQRT_MIN_UNSTAKED_FRACTION = 10**14
FEE_CLAIM_DISCOUNT = 10**16


# ---- EVM integer helpers --------------------------------------------------
def sdiv(a: int, b: int) -> int:
    """EVM SDIV: integer division truncated toward zero. Reverts on div by 0."""
    assert b != 0, "SDIV by zero (would revert)"
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def mul_div(x: int, y: int, d: int, roundup: bool) -> int:
    """snekmate math._mul_div, unsigned (x,y,d >= 0)."""
    assert d != 0
    if roundup:
        return (x * y + d - 1) // d
    return (x * y) // d


def mul_div_signed(x: int, y: int, denominator: int) -> int:
    if denominator == 0:
        return 0
    value = mul_div(abs(x), abs(y), abs(denominator), False)
    if ((x < 0) != (y < 0)) != (denominator < 0):
        value = -value
    return value


def isqrt(x: int) -> int:
    return math.isqrt(x)


# ---- The model ------------------------------------------------------------
class Insolvency(Exception):
    pass


class LTModel:
    def __init__(self, min_admin_fee=10**17, has_staker=True):
        self.min_admin_fee = min_admin_fee
        self.staker = "STAKER" if has_staker else None
        # liquidity struct
        self.l_admin = 0          # int256 (can be negative)
        self.l_total = 0          # uint
        self.l_ideal_staked = 0   # uint
        self.l_staked = 0         # uint
        # erc20
        self.totalSupply = 0
        self.balanceOf = {}
        # ground-truth AMM
        self.amm_value = 0        # value_oracle().value (USD units)
        self.p_o = PREC           # keep == 1e18 so cur_value == amm_value
        self._tag = ''

    # ---- mock AMM ----
    def cur_value(self):
        return self.amm_value * PREC // self.p_o

    def amm_deposit(self, dvalue):
        self.amm_value += dvalue

    def amm_withdraw(self, frac):
        # removes frac of collateral & debt -> removes frac of value
        removed = self.cur_value() * frac // PREC
        self.amm_value -= self.amm_value * frac // PREC
        return removed  # value (coll units) handed to the withdrawer

    def bal(self, a):
        return self.balanceOf.get(a, 0)

    # ---- faithful port of LT._calculate_values ----
    def _calculate_values(self, amm_value_override=None):
        p_o = self.p_o
        staked = 0
        if self.staker is not None:
            staked = self.bal(self.staker)
        supply = self.totalSupply

        # f_a
        if supply == 0:
            # division by zero in the contract would revert; callers guard supply>0
            raise AssertionError("calc with supply==0")
        f_a = PREC - (PREC - self.min_admin_fee) * isqrt(10**36 - staked * 10**36 // supply) // PREC

        amm_value = amm_value_override
        if amm_value is None:
            amm_value = self.amm_value
        cur_value = amm_value * PREC // p_o
        prev_value = self.l_total
        value_change = cur_value - (prev_value + self.l_admin)

        v_st = self.l_staked
        v_st_ideal = self.l_ideal_staked

        dv_use_36 = 0
        v_st_loss = max(v_st_ideal - v_st, 0)
        if staked >= MIN_STAKED_FOR_FEES:
            if value_change > 0:
                v_loss = min(value_change, v_st_loss * supply // staked)
                dv_use_36 = v_loss * PREC + (value_change - v_loss) * (PREC - f_a)
            else:
                dv_use_36 = value_change * PREC
        else:
            dv_use_36 = value_change * (PREC - f_a)

        admin_new = self.l_admin + (value_change - sdiv(dv_use_36, PREC))

        dv_s_36 = mul_div_signed(dv_use_36, staked, supply)
        if dv_use_36 > 0:
            dv_s_36 = min(dv_s_36, v_st_loss * PREC)

        new_total_36 = max(prev_value * PREC + dv_use_36, 0)
        new_staked_36 = max(v_st * PREC + dv_s_36, 0)

        denom = new_total_36 - new_staked_36
        token_reduction = mul_div_signed(new_total_36, staked, denom) - mul_div_signed(new_staked_36, supply, denom)

        # max_token_reduction
        mtr_den = prev_value + value_change + 1
        if mtr_den == 0:
            raise AssertionError("max_token_reduction div by zero (would revert)")
        max_token_reduction = abs(sdiv(sdiv(value_change * supply, mtr_den) * (PREC - f_a), SQRT_MIN_UNSTAKED_FRACTION))

        if staked > 0:
            token_reduction = min(token_reduction, staked - 1)
        if supply > 0:
            token_reduction = min(token_reduction, supply - 1)
        if token_reduction >= 0:
            token_reduction = min(token_reduction, max_token_reduction)
        else:
            token_reduction = max(token_reduction, -max_token_reduction)
        if new_total_36 - new_staked_36 < 10**4 * PREC:
            token_reduction = max(token_reduction, 0)

        return {
            "admin": admin_new,
            "total": new_total_36 // PREC,
            "ideal_staked": self.l_ideal_staked,
            "staked": new_staked_36 // PREC,
            "staked_tokens": staked - token_reduction,
            "supply_tokens": supply - token_reduction,
            "token_reduction": token_reduction,
        }

    # ---- checkpoint_staker_rebase (LT.vy:721) ----
    def checkpoint(self):
        if self.staker is None or self.totalSupply == 0:
            return
        lv = self._calculate_values()
        self.l_admin = lv["admin"]
        self.l_total = lv["total"]
        self.l_staked = lv["staked"]
        self.totalSupply = lv["supply_tokens"]
        self.balanceOf[self.staker] = lv["staked_tokens"]
        self._post_recompute_check(self._tag)

    # ---- deposit (LT.vy:458, supply>0 and first-deposit branches) ----
    def deposit(self, actor, dvalue):
        assert actor != self.staker
        supply = self.totalSupply
        lv = None
        if supply > 0:
            lv = self._calculate_values()
        # amm._deposit adds value
        self.amm_deposit(dvalue)
        value_after = self.cur_value()  # v.value*1e18//p_o
        if supply > 0 and lv["total"] > 0:
            supply = lv["supply_tokens"]
            self.l_admin = lv["admin"]
            value_before = lv["total"]
            value_after = value_after - lv["admin"]
            self.l_total = value_after
            self.l_staked = lv["staked"]
            self.totalSupply = lv["supply_tokens"]
            if self.staker is not None:
                self.balanceOf[self.staker] = lv["staked_tokens"]
            shares = supply * value_after // value_before - supply
        else:
            shares = value_after
            self.l_ideal_staked = 0
            self.l_staked = 0
            self.l_total = shares
            self.l_admin = 0
            if self.staker is not None:
                self.balanceOf[self.staker] = 0
        self._mint(actor, shares)
        self._post_recompute_check(self._tag)
        return shares

    # ---- withdraw (LT.vy:535) -> returns assets paid out (value units) ----
    def withdraw(self, actor, shares):
        assert shares > 0 and actor != self.staker
        lv = self._calculate_values()
        supply = lv["supply_tokens"]
        self.l_admin = lv["admin"]
        self.l_staked = lv["staked"]
        self.totalSupply = supply
        assert supply >= shares
        if self.staker is not None:
            self.balanceOf[self.staker] = lv["staked_tokens"]
        admin_balance = max(lv["admin"], 0)
        frac = PREC * lv["total"] // (lv["total"] + admin_balance) * shares // supply
        assets = self.amm_withdraw(frac)
        self._burn(actor, shares)
        self.l_total = lv["total"] * (supply - shares) // supply
        if lv["admin"] < 0:
            self.l_admin = lv["admin"] * (supply - shares) // supply
        self._post_recompute_check(self._tag)
        return assets

    # ---- withdraw_admin_fees (LT.vy:882): mint to fee_receiver ----
    def withdraw_admin_fees(self, fee_receiver):
        assert fee_receiver not in (self.staker,)
        v = self._calculate_values()
        if v["admin"] < 0:
            return 0  # "Loss made admin fee negative"
        self.totalSupply = v["supply_tokens"]
        new_total = v["total"] + v["admin"]
        if v["total"] == 0:
            return 0
        to_mint = v["supply_tokens"] * new_total // v["total"] - v["supply_tokens"]
        self._mint(fee_receiver, to_mint)
        self.l_total = new_total
        self.l_admin = 0
        self.l_staked = v["staked"]
        if self.staker is not None:
            self.balanceOf[self.staker] = v["staked_tokens"]
        self._post_recompute_check(self._tag)
        return to_mint

    # ---- stake/unstake via gauge: checkpoint then _transfer staker-branch ----
    def stake(self, actor, value):
        if value == 0 or self.staker is None:
            return
        assert self.bal(actor) >= value
        self.checkpoint()  # gauge checkpoints before pulling
        self._transfer_staker(actor, self.staker, value, sender_is_staker=True)

    def unstake(self, actor, value):
        if value == 0 or self.staker is None:
            return
        assert self.bal(self.staker) >= value
        self.checkpoint()
        self._transfer_staker(self.staker, actor, value, sender_is_staker=True)

    def _transfer_staker(self, _from, _to, _value, sender_is_staker):
        staker = self.staker
        if sender_is_staker:
            liq = {
                "ideal_staked": self.l_ideal_staked,
                "staked": self.l_staked,
                "supply_tokens": self.totalSupply,
                "staked_tokens": self.bal(staker),
                "total": self.l_total,
            }
        else:
            lv = self._calculate_values()
            self.l_admin = lv["admin"]
            self.l_total = lv["total"]
            self.totalSupply = lv["supply_tokens"]
            self.balanceOf[staker] = lv["staked_tokens"]
            liq = lv
        if _from == staker:  # unstake
            liq["staked"] -= liq["total"] * _value // liq["supply_tokens"]  # unsafe_div
            liq["ideal_staked"] = liq["ideal_staked"] * (liq["staked_tokens"] - _value) // liq["staked_tokens"]
        elif _to == staker:  # stake
            d = liq["total"] * _value // liq["supply_tokens"]
            liq["staked"] += d
            if liq["staked_tokens"] > 10**10:
                liq["ideal_staked"] = liq["ideal_staked"] * (liq["staked_tokens"] + _value) // liq["staked_tokens"]
            else:
                liq["ideal_staked"] += d
        self.l_staked = liq["staked"]
        self.l_ideal_staked = liq["ideal_staked"]
        self.balanceOf[_from] = self.bal(_from) - _value
        self.balanceOf[_to] = self.bal(_to) + _value

    def _mint(self, a, v):
        self.balanceOf[a] = self.bal(a) + v
        self.totalSupply += v

    def _burn(self, a, v):
        self.balanceOf[a] = self.bal(a) - v
        self.totalSupply -= v

    # ---- invariant checks ----
    # TOL: legitimate per-op integer rounding (1e6 wei == 1e-12 of a token).
    TOL = 10**7

    def check_invariants(self, tag):
        # INV2 bounds — always valid on stored state.
        if self.totalSupply == 0:
            return
        if self.staker is not None:
            if self.bal(self.staker) > self.totalSupply:
                raise Insolvency(f"[{tag}] INV2 staked_tokens {self.bal(self.staker)} > supply {self.totalSupply}")
            if self.l_staked > self.l_total + self.TOL:
                raise Insolvency(f"[{tag}] INV2 staked_value {self.l_staked} > total {self.l_total}")

    def _post_recompute_check(self, tag):
        """Called right after an op that commits _calculate_values (deposit/withdraw/
        admin_fee/staker-checkpoint). In the admin>=0 regime, total+admin must NOT exceed
        what the AMM actually holds (the insolvent direction). The admin<0 case is the
        documented loss-socialization path (withdraw uses max(admin,0)), so skip it here —
        full_unwind_solvency is the airtight check for that case."""
        if self.totalSupply == 0 or self.l_admin < 0:
            return
        cur = self.cur_value()
        owed = self.l_total + self.l_admin          # admin>=0
        if owed - cur > self.TOL:                   # LT thinks it owes more than AMM holds
            raise Insolvency(f"[{tag}] POST-RECOMPUTE LT owes {owed} > AMM holds {cur} by {owed-cur}")

    def full_unwind_solvency(self, tag):
        """Sequentially withdraw EVERY holder; assert total paid <= initial amm_value and amm never negative."""
        snap = self.snapshot()
        paid = 0
        # unstake the staker's balance to a synthetic holder first
        if self.staker is not None and self.bal(self.staker) > 0:
            sb = self.bal(self.staker)
            self.unstake("UNWIND_STAKER", sb)
        holders = [a for a in list(self.balanceOf) if a != self.staker and self.bal(a) > 0]
        start_amm = self.amm_value
        for h in holders:
            sh = self.bal(h)
            if sh == 0:
                continue
            if self.totalSupply == sh or self.totalSupply >= sh:
                paid += self.withdraw(h, sh)
            if self.amm_value < -2:
                raise Insolvency(f"[{tag}] UNWIND amm_value went negative: {self.amm_value}")
        if paid > start_amm + 4:
            raise Insolvency(f"[{tag}] UNWIND paid {paid} > amm_value held {start_amm} (theft={paid-start_amm})")
        self.restore(snap)

    def snapshot(self):
        return (self.l_admin, self.l_total, self.l_ideal_staked, self.l_staked,
                self.totalSupply, dict(self.balanceOf), self.amm_value)

    def restore(self, s):
        (self.l_admin, self.l_total, self.l_ideal_staked, self.l_staked,
         self.totalSupply, bo, self.amm_value) = s
        self.balanceOf = dict(bo)


# ---- Fuzzer ---------------------------------------------------------------
def run_fuzz(seed, n_ops=400, maf_pool=(0, 10**16, 10**17, 5 * 10**17)):
    rng = random.Random(seed)
    maf = rng.choice(maf_pool)
    m = LTModel(min_admin_fee=maf, has_staker=rng.random() < 0.85)
    actors = ["alice", "bob", "carol"]
    # seed first deposit
    m.deposit("alice", rng.randint(10**18, 10**24))
    for i in range(n_ops):
        op = rng.choices(
            ["deposit", "withdraw", "stake", "unstake", "yield_up", "yield_down",
             "checkpoint", "admin_fee"],
            weights=[18, 14, 16, 16, 14, 8, 8, 6])[0]
        m._tag = f"seed={seed} maf={maf} op={i}:{op}"
        try:
            if op == "deposit":
                m.deposit(rng.choice(actors), rng.randint(10**15, 10**24))
            elif op == "withdraw":
                a = rng.choice(actors)
                b = m.bal(a)
                if b > 0 and m.totalSupply > b:
                    m.withdraw(a, rng.randint(1, b))
            elif op == "stake":
                a = rng.choice(actors)
                b = m.bal(a)
                if b > 0:
                    m.stake(a, rng.randint(1, b))
            elif op == "unstake":
                sb = m.bal(m.staker) if m.staker else 0
                if sb > 0:
                    m.unstake(rng.choice(actors), rng.randint(1, sb))
            elif op == "yield_up":
                m.amm_value += rng.randint(0, max(1, m.amm_value // 20))
                m.checkpoint()
            elif op == "yield_down":
                m.amm_value -= rng.randint(0, max(1, m.amm_value // 30))
                m.checkpoint()
            elif op == "checkpoint":
                m.checkpoint()
            elif op == "admin_fee":
                if m.l_admin > 0:
                    m.withdraw_admin_fees("FEE_RX")
        except AssertionError:
            continue  # operation guarded/reverted in-contract; skip
        m.check_invariants(m._tag)
        m.full_unwind_solvency(m._tag)   # airtight solvency oracle, every op
    m.full_unwind_solvency(f"seed={seed} FINAL")


def adversarial_staker_desync(seed, maf_pool=(0, 10**17, 5 * 10**17)):
    """Targeted: attacker stakes ~all supply, harvests a big yield as a staker
    (maximizing the admin-fee-free / token_reduction path), then unstakes in many
    small pieces and withdraws — the exact shape that would exploit a desync
    between staked_tokens/supply and staked_value/total."""
    rng = random.Random(seed)
    maf = rng.choice(maf_pool)
    m = LTModel(min_admin_fee=maf, has_staker=True)
    m._tag = f"adv seed={seed} maf={maf}"
    m.deposit("attacker", 10**21)
    m.deposit("honest", rng.randint(10**18, 10**22))
    # attacker stakes nearly everything
    m.stake("attacker", m.bal("attacker") * 99 // 100)
    for k in range(60):
        # big swings while staked
        if rng.random() < 0.6:
            m.amm_value += rng.randint(0, m.amm_value // 5)
        else:
            m.amm_value -= rng.randint(0, m.amm_value // 8)
        m.checkpoint()
        m.full_unwind_solvency(m._tag)
        # peel off small unstake + withdraw
        sb = m.bal(m.staker)
        if sb > 100:
            try:
                m.unstake("attacker", rng.randint(1, sb // 10))
            except AssertionError:
                pass
        ab = m.bal("attacker")
        if ab > 0 and m.totalSupply > ab:
            try:
                m.withdraw("attacker", rng.randint(1, ab))
            except AssertionError:
                pass
        m.check_invariants(m._tag)
        m.full_unwind_solvency(m._tag)


def _pass(runs, prod_pool, adv_pool, label):
    found = 0
    for s in range(runs):
        try:
            run_fuzz(s, maf_pool=prod_pool)
        except Insolvency as e:
            found += 1
            print(f"  !! {e}")
        except Exception as e:
            print(f"  (model error seed={s} run_fuzz: {type(e).__name__}: {e})")
        try:
            adversarial_staker_desync(s, maf_pool=adv_pool)
        except Insolvency as e:
            found += 1
            print(f"  !! {e}")
        except Exception as e:
            print(f"  (model error seed={s} adversarial: {type(e).__name__}: {e})")
    verdict = "PASS — no violation" if found == 0 else f"{found} violation(s)"
    print(f"[{label}] {runs} seeds x2 scenarios (unwind after every op): {verdict}\n")
    return found


if __name__ == "__main__":
    import sys
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
    print("=== Pass A: PRODUCTION admin fees (<= 10%) ===")
    _pass(runs, prod_pool=(0, 10**16, 10**17), adv_pool=(0, 10**17), label="production")
    print("=== Pass B: STRESS admin fees (up to 50%, governance-set max abuse) ===")
    _pass(runs, prod_pool=(10**17, 5 * 10**17), adv_pool=(10**17, 5 * 10**17), label="stress")
