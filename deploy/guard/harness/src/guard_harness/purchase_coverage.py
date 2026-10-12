"""Pinned public identities of every required purchase scenario."""

TITLES = {
    "P4": frozenset(
        "P4 quote: " + label
        for label in ("German business", "EU reverse charge", "non-EU business", "invalid VAT ID")
    ),
    "P5": frozenset(
        "P5 " + label + " payment disposition and operator notice"
        for label in ("under", "over", "late", "blocked")
    ),
    "P7": frozenset({"P7 quote: blocked country"}),
    **{
        row: frozenset({row + " pricing to paid email to installed released licence"})
        for row in ("P1", "P2", "P3", "P6")
    },
}
PURCHASE_COVERAGE = {row: titles for row, titles in TITLES.items()}
