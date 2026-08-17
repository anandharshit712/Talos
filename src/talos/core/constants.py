"""Non-domain constants: the contract strings that several components must agree on.

The category strings are the load-bearing ones. A classifier's emitted category, the
``AttackTypeSubAgent.category`` registered for it, and the package name under
``domains/<domain>/`` are the same string -- so it is defined once, here, rather than typed
three times and silently diverging on the fourth.

Thresholds and tunables do not belong in this module. They live in ``config/`` and reach
detectors through ``ctx.settings`` (standards 2.3).
"""

from __future__ import annotations

from typing import Final, Literal

PACKAGE_NAME: Final = "talos"

# --- Domains -------------------------------------------------------------------------------

DOMAIN_WEB: Final = "web"
DOMAIN_NETWORK: Final = "network"

#: Every domain the hackathon slice routes. Matches ``NormalizedEvent.domain``.
DOMAINS: Final[tuple[str, ...]] = (DOMAIN_WEB, DOMAIN_NETWORK)

# --- Attack categories ---------------------------------------------------------------------

CATEGORY_INJECTION: Final = "injection"
CATEGORY_AUTH_FAILURE: Final = "auth_failure"
CATEGORY_BROKEN_ACCESS_CONTROL: Final = "broken_access_control"
CATEGORY_NETWORK_BRUTE_FORCE: Final = "network_brute_force"

#: Emitted when no category clears the classifier's confidence floor. Routed nowhere.
CATEGORY_UNCLASSIFIED: Final = "unclassified"

#: Categories a type classifier may emit (LLD 6). Each -- except ``unclassified`` -- is also a
#: package name under ``src/talos/domains/<domain>/``.
CATEGORIES: Final[tuple[str, ...]] = (
    CATEGORY_INJECTION,
    CATEGORY_AUTH_FAILURE,
    CATEGORY_BROKEN_ACCESS_CONTROL,
    CATEGORY_NETWORK_BRUTE_FORCE,
    CATEGORY_UNCLASSIFIED,
)

# --- Reporting -----------------------------------------------------------------------------

#: The report severity vocabulary, mirrored by ``IncidentReport.severity``.
Severity = Literal["info", "low", "medium", "high", "critical"]

#: Severity vocabulary, least to most severe. Index order is the comparison order.
SEVERITIES: Final[tuple[Severity, ...]] = ("info", "low", "medium", "high", "critical")

#: ``ModelInfo.name`` when a verdict was produced with no model call at all.
MODEL_NAME_NONE: Final = "none"
