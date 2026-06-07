"""
PoC: HybridVault shared crvUSD-backing solvency (vector "c").

REQUIRES THE FULL UPSTREAM ENVIRONMENT — NOT EXECUTED IN THIS REVIEW SANDBOX.
    poetry install && git submodule update --init      # vyper 0.4.3 + titanoboa + twocrypto-ng
    pytest poc/test_hybridvault_shared_backing.py -x

Thesis: multiple per-user HybridVaults draw on ONE shared crvUSD vault (e.g. scrvUSD).
Each vault reports how much crvUSD its YB positions require via `required_crvusd()`, and
the HybridVaultFactory tracks the running total in `crvusd_vault_total_required`. The
shared buffer is solvent iff that bookkeeping can never let the vaults collectively claim
more crvUSD than is actually deposited. We drive concurrent deposit/withdraw/emergency
across several vaults on one market and assert three invariants after every step.

This file deliberately reuses the project's existing market/DAO fixtures (see
tests/lt/conftest.py and tests/conftest.py). Wire the fixtures marked TODO to the
upstream conftest factory that deploys: crvUSD, a twocrypto crvUSD/asset pool, a YB
Factory market (price_oracle -> lt -> amm -> staker), a crvUSD ERC4626 vault (scrvUSD
mock), the HybridVault implementation, and the HybridVaultFactory.
"""
import boa
import pytest
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize
import hypothesis.strategies as st


# --------------------------------------------------------------------------------------
# Fixtures — TODO: bind to upstream conftest. Signatures follow the contracts as reviewed
# (HybridVaultFactory.create_vault, HybridVault.deposit/withdraw/emergency_withdraw,
#  HybridVault.required_crvusd, HybridVaultFactory.crvusd_vault_total_required, etc.)
# --------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def shared_env():
    """Return a dict with: crvusd, asset, market_id, factory(YB), vault_factory(Hybrid),
    crvusd_vault(scrvUSD), stablecoin_fraction, and a helper to mint asset/crvUSD to a user."""
    raise NotImplementedError(
        "Bind to upstream conftest: deploy crvUSD + twocrypto pool + YB market + "
        "scrvUSD ERC4626 + HybridVault impl + HybridVaultFactory, and configure "
        "set_allowed_crvusd_vault(scrvUSD, True) and pool_limits."
    )


def _downscale(vf, x):
    return x * vf.stablecoin_fraction() // 10**18


class SharedBackingMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.env = None  # set in initialize
        self.users = []
        self.vaults = {}  # user -> HybridVault

    @initialize()
    def setup(self):
        self.env = shared_env_singleton  # injected by the pytest wrapper below
        e = self.env
        for u in e["users"]:
            with boa.env.prank(u):
                v = e["vault_factory"].create_vault(e["crvusd_vault"].address)
            self.vaults[u] = e["factory_at"](v)

    # ---- rules ----
    @rule(ui=st.integers(0, 2), assets=st.integers(10**15, 10**21), debt_bps=st.integers(8000, 12000))
    def deposit(self, ui, assets, debt_bps):
        e = self.env
        u = e["users"][ui % len(e["users"])]
        v = self.vaults[u]
        p_o = e["market"].price_oracle.price()
        debt = assets * p_o // 10**18 * debt_bps // 10000
        e["mint_asset"](u, assets)
        with boa.env.prank(u):
            try:
                v.deposit(e["market_id"], assets, debt, 0, False, True)  # deposit_stablecoins=True
            except Exception:
                pass

    @rule(ui=st.integers(0, 2), frac_bps=st.integers(1, 10000))
    def withdraw(self, ui, frac_bps):
        e = self.env
        u = e["users"][ui % len(e["users"])]
        v = self.vaults[u]
        shares = e["market"].lt.balanceOf(v.address)
        if shares == 0:
            return
        with boa.env.prank(u):
            try:
                v.withdraw(e["market_id"], shares * frac_bps // 10000, 0, False, u, True)
            except Exception:
                pass

    @rule(ui=st.integers(0, 2))
    def emergency_withdraw(self, ui):
        e = self.env
        u = e["users"][ui % len(e["users"])]
        v = self.vaults[u]
        shares = e["market"].lt.balanceOf(v.address)
        if shares == 0:
            return
        with boa.env.prank(u):
            try:
                v.emergency_withdraw(e["market_id"], shares, True)
            except Exception:
                pass

    @rule(up=st.booleans(), bps=st.integers(0, 1500))
    def move_price(self, up, bps):
        # nudge the twocrypto pool / oracle so positions gain or lose value
        self.env["shift_price"](up, bps)

    # ---- invariants ----
    @invariant()
    def bookkeeping_matches(self):
        """INV-A: the factory's per-vault tracked requirement sums to its global total."""
        e = self.env
        vf = e["vault_factory"]
        total = sum(vf.crvusd_vault_required(v.address) for v in self.vaults.values())
        assert vf.crvusd_vault_total_required(e["crvusd_vault"].address) == total, \
            "INV-A: crvusd_vault_total_required desynced from sum of per-vault required"

    @invariant()
    def each_vault_backed(self):
        """INV-B: every vault holds at least its downscaled required crvUSD (the
        contract enforces this on several paths; assert it holds globally)."""
        e = self.env
        vf = e["vault_factory"]
        for v in self.vaults.values():
            req = v.required_crvusd()
            avail = e["crvusd_available"](v)  # scrvUSD.previewRedeem(scrvUSD.balanceOf(v))
            if req != 2**256 - 1:
                assert avail + 1 >= req, f"INV-B: vault {v.address} under-backed: {avail} < {req}"

    @invariant()
    def shared_solvency(self):
        """INV-C (airtight): the scrvUSD actually deposited by all vaults must cover the
        sum of their requirements — no bookkeeping path may let the group claim more
        backing than exists."""
        e = self.env
        vf = e["vault_factory"]
        sum_required = 0
        for v in self.vaults.values():
            r = v.required_crvusd()
            if r == 2**256 - 1:
                return  # oracle-broken state: contract forbids stable withdrawals; skip
            sum_required += r
        backed = e["total_scrvusd_value_held_by_vaults"]()
        assert backed + len(self.vaults) >= sum_required, \
            f"INV-C: shared backing {backed} < total required {sum_required} (insolvent)"


# Hypothesis settings: long runs to exercise concurrent multi-vault interleavings.
TestSharedBacking = SharedBackingMachine.TestCase
TestSharedBacking.settings = settings(max_examples=200, stateful_step_count=60, deadline=None)


@pytest.fixture(autouse=True, scope="module")
def _inject(shared_env):
    global shared_env_singleton
    shared_env_singleton = shared_env
    yield
