"""Pure finite journal diagnostics; never emit message fragments or grant audit credit."""


def valid_fee_approval(event: dict[str, object]) -> bool:
    """C3's successful read-only fee notice has no action or error fields."""
    sequence, stamp, text = event.get("seq"), event.get("at_ms"), event.get("text")
    return (
        set(event) == {"seq", "at_ms", "kind", "approved", "text"}
        and event.get("kind") == "fee_approval"
        and event.get("approved") is True
        and type(sequence) is int
        and sequence > 0
        and type(stamp) is int
        and stamp >= 0
        and type(text) is str
        and 0 < len(text) <= 16384
    )


def error_category(value: object) -> str:
    """Classify public producer message templates; never return message data.

    Templates come from guard/{sync,mod,observe}.rs. This is a diagnostic only:
    every Error still refuses credit, including recognized operational failures.
    """
    if not isinstance(value, str) or len(value) > 16384:
        return "unknown"
    if value.startswith("reading the account: HIP-3 dex ") and value.endswith(
        " could not be read; its positions go unprotected by Guard until it can be, "
        "and no entry is judged"
    ):
        return "account-dex-read"
    for prefix, category in (
        ("reading the account: ", "account-read"),
        ("builder fee approved (", "fee-approved"),
        ("builder fee not approved (", "fee-unapproved"),
        ("reading the builder fee approval: ", "fee-read"),
        ("the builder fee approval was withdrawn or lowered (", "fee-withdrawn"),
        ("licence key not used (", "licence-warning"),
        ("licence: ", "licence-warning"),
        ("recovery after a restart failed: ", "restart-recovery"),
        (
            "the decision journal ended in writes a crash cut short "
            "(never synced, so nothing was sent on their strength): ",
            "crash-cut-journal",
        ),
        ("the account's ledger has an entry Guard cannot account for (", "unaccounted-ledger"),
        ("account-flow arithmetic cannot be represented: ", "flow-arithmetic"),
        ("account value at a flow is uncertain: ", "flow-uncertain"),
    ):
        if value.startswith(prefix):
            return category
    if value.startswith("a flow of ") and value.endswith(
        " USDC (deposit, withdrawal or transfer) kept out of the account stops"
    ):
        return "account-flow"
    if value.startswith("positions on HIP-3 dex ") and value.endswith(
        ", which the rules' markets do not name: Guard neither judges nor protects them, "
        "and the kill switch leaves them"
    ):
        return "unmanaged-dex"
    return "unknown"
