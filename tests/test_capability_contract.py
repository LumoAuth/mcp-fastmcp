"""capability_covered must answer exactly as the LumoAuth server does.

The contract cases (``sdk-contract/vectors/agent-capabilities.json``) are
checked against the server's own matcher by the contract repo. This test runs
the ``covers`` and ``any_covers`` cases through ``capability_covered``. It is
skipped when no contract checkout is found: set ``LUMO_SDK_CONTRACT`` or keep
``sdk-contract`` next to this repository.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lumoauth_fastmcp import capability_covered

_CANDIDATES = [
    *([Path(os.environ["LUMO_SDK_CONTRACT"])] if os.environ.get("LUMO_SDK_CONTRACT") else []),
    Path(__file__).resolve().parents[2] / "sdk-contract",
]
_VECTOR = next(
    (c / "vectors/agent-capabilities.json" for c in _CANDIDATES if (c / "vectors/agent-capabilities.json").is_file()),
    None,
)


@pytest.mark.skipif(_VECTOR is None, reason="sdk-contract not found (set LUMO_SDK_CONTRACT)")
def test_contract_capability_vector() -> None:
    assert _VECTOR is not None
    vector = json.loads(_VECTOR.read_text(encoding="utf-8"))
    failures = []
    for case in vector["covers"]:
        got = capability_covered(case["action"], [case["capability"]])
        if got is not case["expected"]:
            failures.append(f"covers {case}: got {got}")
    for case in vector["any_covers"]:
        got = capability_covered(case["action"], case["capabilities"])
        if got is not case["expected"]:
            failures.append(f"any_covers {case}: got {got}")
    assert vector["covers"] and vector["any_covers"]
    assert not failures, "\n".join(failures)
