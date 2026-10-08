"""`liebert_re.dynamic.guest_attestation`: measured Hyper-V facts become VERIFIED or UNKNOWN.

Every GUID, name and hash below is synthetic and built in code; no real machine identity is
written here. The module is pure, so no file, clock or registry is touched.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from liebert_re.dynamic.guest_attestation import GuestAttestation

pytestmark = pytest.mark.contract

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
MEASURED_AT = NOW - timedelta(seconds=60)
VM_ID = "11111111-1111-4111-8111-111111111111"
CHECKPOINT_ID = "22222222-2222-4222-8222-222222222222"
SWITCH_ID = "33333333-3333-4333-8333-333333333333"
OTHER_SWITCH_ID = "44444444-4444-4444-8444-444444444444"
OTHER_VM_ID = "55555555-5555-4555-8555-555555555555"
ADAPTER_ID = "Adapter-A"
GUEST_SERVICE_SUFFIX = "6C09BB55-D683-4DA0-8931-C9BF705F6480"
HOST_HASH = "ab" * 32
ALL = ("isolated_guest", "snapshot_and_rollback", "network_control")


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _measurement(**overrides):
    """A fully isolated, fresh measurement; keyword overrides replace top-level keys."""
    m = {
        "schema_version": GuestAttestation.SCHEMA,
        "measured_at_utc": _stamp(MEASURED_AT),
        "script_version": "1",
        "elevated": True,
        "host": {"ok": True, "error": None, "identity_sha256": HOST_HASH},
        "vm": {"ok": True, "error": None, "id": VM_ID, "name": "lab-vm", "state": "Running", "generation": 2,
               "automatic_checkpoints": False, "parent_checkpoint_id": CHECKPOINT_ID},
        "checkpoints": {"ok": True, "error": None, "items": [
            {"id": CHECKPOINT_ID, "name": "clean", "vm_id": VM_ID,
             "created_utc": _stamp(MEASURED_AT - timedelta(days=1)), "type": "Standard"}]},
        "adapters": {"ok": True, "error": None, "items": [
            {"id": ADAPTER_ID, "switch_id": SWITCH_ID, "switch_name": "lab-private", "connected": True}]},
        "switches": {"ok": True, "error": None, "items": [
            {"id": SWITCH_ID, "name": "lab-private", "switch_type": "Private"}]},
        "switch_peers": {"ok": True, "error": None, "items": []},
        "host_adapters": {"ok": True, "error": None, "items": []},
        "integration_services": {"ok": True, "error": None, "items": [
            {"id_suffix": GUEST_SERVICE_SUFFIX, "enabled": False},
            {"id_suffix": "9F3B1C00-0000-4000-8000-000000000000", "enabled": True}]},
        "security": {"ok": True, "error": None, "tpm_enabled": False, "shielded": False},
        "guest": {"ok": True, "error": None, "vm_id_from_kvp": VM_ID, "os_build": "26100",
                  "vbs_status": 0, "security_services_running": []},
    }
    for section in m.values():
        if isinstance(section, dict):
            section["error_category"] = None
    m.update(overrides)
    return m


def _evaluate(m, **kw):
    kw.setdefault("now_utc", NOW)
    kw.setdefault("local_vm_id", VM_ID)
    return GuestAttestation.evaluate(m, **kw)


def _status(result):
    return {k: v["status"] for k, v in result["capabilities"].items()}


def _walk(m, path):
    """Return (container, key) for a dotted path; digits index lists."""
    parts = path.split(".")
    cur = m
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = parts[-1]
    return cur, (int(last) if isinstance(cur, list) else last)


def _without(m, path):
    m = copy.deepcopy(m)
    container, key = _walk(m, path)
    del container[key]
    return m


def _with(m, path, value):
    m = copy.deepcopy(m)
    container, key = _walk(m, path)
    container[key] = value
    return m


def _has_reason(cap, prefix):
    return any(r.startswith(prefix) for r in cap["reasons"])


def _assert_invariants(result):
    json.dumps(result)
    for name in ALL:
        cap = result["capabilities"][name]
        assert cap["spoofable"] is True
        assert cap["status"] in ("VERIFIED", "UNKNOWN")
        if cap["status"] == "UNKNOWN":
            assert cap["reasons"], name
    verified = [c["status"] == "VERIFIED" for c in result["capabilities"].values()]
    assert result["isolation_verified"] is all(verified)


def test_fully_isolated_verifies_all_three():
    result = _evaluate(_measurement())
    assert _status(result) == {n: "VERIFIED" for n in ALL}
    assert result["isolation_verified"] is True
    assert result["isolation_basis"] == "observed"
    assert result["schema_version"] == "liebert-re.guest-measurement/2"
    assert result["isolation_asserted_by_operator"] is False
    assert result["informational"]["guest_hvci_running"] is False
    for cap in result["capabilities"].values():
        assert cap["spoofable"] is True and cap["not_covered"]
    # evidence carries no GUID, name or host hash
    text = json.dumps(result)
    for secret in (VM_ID, CHECKPOINT_ID, SWITCH_ID, HOST_HASH, "lab-vm", "lab-private"):
        assert secret not in text
    _assert_invariants(result)


def test_hvci_is_reported_but_never_decides():
    m = _with(_measurement(), "guest.security_services_running", [1, 2])
    result = _evaluate(m)
    assert result["informational"]["guest_hvci_running"] is True
    assert result["isolation_verified"] is True
    bad = _with(_measurement(), "guest.security_services_running", "2")
    assert _evaluate(bad)["informational"]["guest_hvci_running"] is None


@pytest.mark.parametrize("switch_type", ["Internal", "External", "Weird", ""])
def test_default_switch_internal_is_network_unknown(switch_type):
    m = _with(_measurement(), "switches.items.0.switch_type", switch_type)
    result = _evaluate(m)
    net = result["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN"
    assert "SWITCH_NOT_PRIVATE" in net["reasons"]
    assert result["capabilities"]["isolated_guest"]["status"] == "VERIFIED"
    assert result["isolation_basis"] == "observed_partial"
    assert result["isolation_verified"] is False


def test_zero_adapters_measured_is_network_verified():
    m = _with(_measurement(), "adapters.items", [])
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "VERIFIED"
    assert net["evidence"]["adapter_count"] == 0
    assert net["reasons"] == ["measured absence of adapters"]


def test_zero_adapters_with_section_not_ok_is_unknown():
    m = _measurement(adapters={"ok": False, "error": "query failed", "items": []})
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN"
    assert "SECTION_NOT_OK:adapters" in net["reasons"]
    assert net["evidence"]["adapter_count"] is None
    # an ok section that nevertheless reports an error contradicts itself
    m2 = _measurement(adapters={"ok": True, "error": "boom", "items": []})
    assert "CONTRADICTION:adapters.error" in _evaluate(m2)["capabilities"]["network_control"]["reasons"]


def test_unconnected_adapter_needs_no_switch():
    m = _with(_measurement(), "adapters.items.0.connected", False)
    m = _with(m, "adapters.items.0.switch_id", None)
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "VERIFIED"
    assert net["evidence"]["connected_adapter_count"] == 0


def test_assertion_alone_never_verifies():
    m = _measurement(isolation_asserted_by_operator=True)
    broken = {"schema_version": GuestAttestation.SCHEMA, "isolation_asserted_by_operator": True}
    for source in (broken, _with(m, "measured_at_utc", _stamp(NOW - timedelta(days=3)))):
        result = _evaluate(source)
        assert result["isolation_verified"] is False
        assert set(_status(result).values()) == {"UNKNOWN"}
        assert result["isolation_basis"] == "asserted"
        assert result["isolation_asserted_by_operator"] is True
    for junk in (None, "yes", 1, [True]):
        assert _evaluate({"isolation_asserted_by_operator": junk})["isolation_asserted_by_operator"] is False


def test_assertion_does_not_raise_partial():
    # An assertion beside a partial observation changes nothing: still partial, not upgraded.
    m = _with(_measurement(isolation_asserted_by_operator=True), "switches.items.0.switch_type", "Internal")
    result = _evaluate(m)
    assert result["isolation_basis"] == "observed_partial"
    assert result["isolation_verified"] is False
    assert _status(result)["network_control"] == "UNKNOWN"
    # and an assertion does not rescue a failing capability
    plain = _evaluate(_with(_measurement(), "switches.items.0.switch_type", "Internal"))
    assert _status(plain) == _status(result)


_MISSING_FIELDS = [
    ("measured_at_utc", ALL), ("script_version", ALL), ("elevated", ALL), ("vm", ALL), ("vm.id", ALL),
    ("vm.state", ("isolated_guest",)), ("host", ("isolated_guest",)),
    ("host.identity_sha256", ("isolated_guest",)), ("guest", ("isolated_guest",)),
    ("guest.vm_id_from_kvp", ("isolated_guest",)), ("integration_services", ("isolated_guest",)),
    ("integration_services.items", ("isolated_guest",)),
    ("integration_services.items.0.enabled", ("isolated_guest",)),
    ("integration_services.items.0.id_suffix", ("isolated_guest",)),
    ("vm.parent_checkpoint_id", ("snapshot_and_rollback",)), ("checkpoints", ("snapshot_and_rollback",)),
    ("checkpoints.items", ("snapshot_and_rollback",)),
    ("checkpoints.items.0.id", ("snapshot_and_rollback",)),
    ("checkpoints.items.0.vm_id", ("snapshot_and_rollback",)),
    ("checkpoints.items.0.created_utc", ("snapshot_and_rollback",)),
    ("adapters", ("network_control",)), ("adapters.items", ("network_control",)),
    ("adapters.items.0.id", ("network_control",)), ("adapters.items.0.connected", ("network_control",)),
    ("adapters.items.0.switch_id", ("network_control",)),
    ("adapters.items.0.switch_name", ("network_control",)),
    ("switches", ("network_control",)), ("switches.items.0.id", ("network_control",)),
    ("switches.items.0.name", ("network_control",)),
    ("switches.items.0.switch_type", ("network_control",)), ("switch_peers", ("network_control",)),
    ("switch_peers.items", ("network_control",)), ("host_adapters", ("network_control",)),
    ("host_adapters.items", ("network_control",)),
]


@pytest.mark.parametrize("path,affected", _MISSING_FIELDS)
def test_missing_field_is_unknown_with_reason(path, affected):
    result = _evaluate(_without(_measurement(), path))
    for name in ALL:
        cap = result["capabilities"][name]
        if name in affected:
            assert cap["status"] == "UNKNOWN", (path, name)
            assert cap["reasons"], (path, name)
        else:
            assert cap["status"] == "VERIFIED", (path, name)
    assert result["isolation_verified"] is False
    assert any(
        _has_reason(result["capabilities"][n], "MISSING:") or _has_reason(result["capabilities"][n], "INVALID:")
        for n in affected
    ), path
    _assert_invariants(result)


def test_stale_measurement_is_unknown():
    m = _with(_measurement(), "measured_at_utc", _stamp(NOW - timedelta(seconds=901)))
    result = _evaluate(m)
    assert set(_status(result).values()) == {"UNKNOWN"}
    assert all("STALE_MEASUREMENT" in c["reasons"] for c in result["capabilities"].values())
    edge = _with(_measurement(), "measured_at_utc", _stamp(NOW - timedelta(seconds=900)))
    assert _evaluate(edge)["isolation_verified"] is True
    assert _evaluate(edge, max_age_s=899)["isolation_verified"] is False
    for bad in (0, -5, True, "900", None):
        assert _evaluate(_measurement(), max_age_s=bad)["isolation_verified"] is False


def test_future_timestamp_is_contradiction():
    far = _with(_measurement(), "measured_at_utc", _stamp(NOW + timedelta(seconds=121)))
    result = _evaluate(far)
    assert set(_status(result).values()) == {"UNKNOWN"}
    assert all("CONTRADICTION:measured_at_utc" in c["reasons"] for c in result["capabilities"].values())
    skew = _with(_measurement(), "measured_at_utc", _stamp(NOW + timedelta(seconds=120)))
    assert _evaluate(skew)["isolation_verified"] is True


def test_naive_or_malformed_timestamps_are_unknown():
    for value in ("2030-01-01T11:59:00", "yesterday", 1893499140, "2030-13-01T00:00:00Z", ""):
        result = _evaluate(_with(_measurement(), "measured_at_utc", value))
        assert result["isolation_verified"] is False, value
    assert _evaluate(_measurement(), now_utc=NOW.replace(tzinfo=None))["isolation_verified"] is False
    assert _evaluate(_measurement(), now_utc="now")["isolation_verified"] is False
    # offsets and 7-digit fractions (the .NET "o" format) are read, not rejected
    ok = _with(_measurement(), "measured_at_utc", "2030-01-01T13:59:00.1234567+02:00")
    assert _evaluate(ok)["isolation_verified"] is True


def test_empty_string_guest_vm_id_is_unknown():
    result = _evaluate(_with(_measurement(), "guest.vm_id_from_kvp", ""))
    iso = result["capabilities"]["isolated_guest"]
    assert iso["status"] == "UNKNOWN" and "INVALID:guest.vm_id_from_kvp" in iso["reasons"]
    assert result["isolation_verified"] is False


def test_guest_and_host_vm_id_disagree():
    m = _with(_measurement(), "guest.vm_id_from_kvp", OTHER_VM_ID)
    result = _evaluate(m)
    iso = result["capabilities"]["isolated_guest"]
    assert iso["status"] == "UNKNOWN"
    assert "CONTRADICTION:guest.vm_id_from_kvp" in iso["reasons"]
    assert iso["evidence"]["guest_vm_id_matches"] is False
    assert result["isolation_verified"] is False
    # a checkpoint that belongs to another VM is the same kind of contradiction
    cp = _with(_measurement(), "checkpoints.items.0.vm_id", OTHER_VM_ID)
    assert "CONTRADICTION:checkpoints.vm_id" in _evaluate(cp)["capabilities"]["snapshot_and_rollback"]["reasons"]


def test_evaluated_on_host_without_local_vm_id_is_unknown():
    result = _evaluate(_measurement(), local_vm_id=None)
    assert set(_status(result).values()) == {"UNKNOWN"}
    assert all("MISSING:local_vm_id" in c["reasons"] for c in result["capabilities"].values())
    # a different machine than the one measured is a contradiction, not a pass
    other = _evaluate(_measurement(), local_vm_id=OTHER_VM_ID)
    assert all("CONTRADICTION:local_vm_id" in c["reasons"] for c in other["capabilities"].values())
    for junk in ("", "not-a-guid", 7, "{" + VM_ID + "}"):
        assert _evaluate(_measurement(), local_vm_id=junk)["isolation_verified"] is False
    # the binding is case-insensitive on the GUID text, nothing more
    assert _evaluate(_measurement(), local_vm_id=VM_ID.upper())["isolation_verified"] is True


def test_guest_service_interface_enabled_is_unknown():
    m = _with(_measurement(), "integration_services.items.0.enabled", True)
    iso = _evaluate(m)["capabilities"]["isolated_guest"]
    assert iso["status"] == "UNKNOWN" and "GUEST_SERVICE_INTERFACE_ENABLED" in iso["reasons"]
    stopped = _with(_measurement(), "vm.state", "Off")
    assert "VM_NOT_RUNNING" in _evaluate(stopped)["capabilities"]["isolated_guest"]["reasons"]
    dup = _measurement()
    dup["integration_services"]["items"].append({"id_suffix": GUEST_SERVICE_SUFFIX.lower(), "enabled": False})
    assert _has_reason(_evaluate(dup)["capabilities"]["isolated_guest"], "CONTRADICTION:integration_services")


def test_snapshot_rules():
    base = _measurement()
    unknown_parent = _with(base, "vm.parent_checkpoint_id", OTHER_VM_ID)
    assert "PARENT_CHECKPOINT_NOT_MEASURED" in _evaluate(unknown_parent)["capabilities"]["snapshot_and_rollback"]["reasons"]
    after = _with(base, "checkpoints.items.0.created_utc", _stamp(MEASURED_AT + timedelta(seconds=1)))
    assert _has_reason(_evaluate(after)["capabilities"]["snapshot_and_rollback"], "CONTRADICTION:checkpoints.created_utc")
    dup = copy.deepcopy(base)
    dup["checkpoints"]["items"].append(dict(dup["checkpoints"]["items"][0]))
    assert _has_reason(_evaluate(dup)["capabilities"]["snapshot_and_rollback"], "CONTRADICTION:checkpoints.id")
    null_parent = _with(base, "vm.parent_checkpoint_id", None)
    assert _evaluate(null_parent)["capabilities"]["snapshot_and_rollback"]["status"] == "UNKNOWN"


def test_ambiguous_switch_is_unknown():
    dup = _measurement()
    dup["switches"]["items"].append({"id": SWITCH_ID, "name": "lab-private", "switch_type": "Private"})
    net = _evaluate(dup)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and "CONTRADICTION:switches.id" in net["reasons"]
    unresolved = _with(_measurement(), "adapters.items.0.switch_id", OTHER_SWITCH_ID)
    net = _evaluate(unresolved)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and "SWITCH_NOT_RESOLVED" in net["reasons"]
    renamed = _with(_measurement(), "adapters.items.0.switch_name", "other-name")
    net = _evaluate(renamed)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and "CONTRADICTION:switch_name" in net["reasons"]
    dup_adapter = _measurement()
    dup_adapter["adapters"]["items"].append(dict(dup_adapter["adapters"]["items"][0]))
    assert "CONTRADICTION:adapters.id" in _evaluate(dup_adapter)["capabilities"]["network_control"]["reasons"]


def test_peer_vm_on_private_switch_is_unknown():
    m = _with(_measurement(), "switch_peers.items", [{"switch_id": SWITCH_ID, "vm_id": OTHER_VM_ID}])
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and "PEER_VM_ON_SWITCH" in net["reasons"]
    # a peer on a switch this VM is not attached to does not matter
    elsewhere = _with(_measurement(), "switch_peers.items", [{"switch_id": OTHER_SWITCH_ID, "vm_id": OTHER_VM_ID}])
    assert _evaluate(elsewhere)["capabilities"]["network_control"]["status"] == "VERIFIED"
    # the VM listed as its own peer contradicts the measurement
    own = _with(_measurement(), "switch_peers.items", [{"switch_id": SWITCH_ID, "vm_id": VM_ID}])
    assert "CONTRADICTION:switch_peers" in _evaluate(own)["capabilities"]["network_control"]["reasons"]


def test_wrong_schema_is_unknown():
    for schema in ("liebert-re.guest-measurement/3", "", None, 1, ["liebert-re.guest-measurement/2"]):
        result = _evaluate(_measurement(schema_version=schema))
        assert set(_status(result).values()) == {"UNKNOWN"}, schema
        assert all(c["reasons"] == ["SCHEMA_MISMATCH"] for c in result["capabilities"].values())
    missing = _measurement()
    del missing["schema_version"]
    assert _evaluate(missing)["isolation_verified"] is False


_HOSTILE_VALUES = [None, "", "x" * 10_000, 0, -1, 1.5, float("nan"), True, [], {}, [None], [[]], {"ok": True},
                   {"ok": "yes"}, b"bytes", object(), ("tuple",), 10**30]


def _deep(depth):
    node = []
    for _ in range(depth):
        node = [node]
    return node


def _deep_dict(depth):
    node = {}
    for _ in range(depth):
        node = {"a": node}
    return node


def _paths(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            p = f"{prefix}.{k}" if prefix else k
            yield p
            yield from _paths(v, p)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            p = f"{prefix}.{i}"
            yield p
            yield from _paths(v, p)


def test_hostile_input_never_raises():
    for hostile in _HOSTILE_VALUES + [_deep(5000), _deep_dict(5000), set(), range(3), Exception("boom")]:
        result = _evaluate(hostile)
        assert set(_status(result).values()) == {"UNKNOWN"}
        assert result["isolation_basis"] == "none"
        _assert_invariants(result)
        for kw in ({"now_utc": hostile}, {"local_vm_id": hostile}, {"max_age_s": hostile}):
            result = _evaluate(_measurement(), **kw)
            if "max_age_s" not in kw:  # a huge positive int is a legitimate (if lax) window
                assert result["isolation_verified"] is False
            _assert_invariants(result)
    # every single field of a good measurement replaced by every hostile value
    base = _measurement()
    for path in list(_paths(base)):
        for hostile in _HOSTILE_VALUES + [_deep(2000), _deep_dict(2000)]:
            result = _evaluate(_with(base, path, hostile))
            assert set(result) == {"schema_version", "capabilities", "isolation_verified", "isolation_basis",
                                   "isolation_asserted_by_operator", "informational"}
            for cap in result["capabilities"].values():
                assert not any(r.startswith("EVALUATION_ERROR") for r in cap["reasons"]), (path, cap["reasons"])
    # raising mapping: the fallback announces itself and still says UNKNOWN

    class Exploding(dict):
        def get(self, *a, **k):
            raise RuntimeError("no")

    result = _evaluate(Exploding())
    assert set(_status(result).values()) == {"UNKNOWN"}
    assert all(c["reasons"] == ["EVALUATION_ERROR:RuntimeError"] for c in result["capabilities"].values())
    huge = _with(_measurement(), "adapters.items", [{"id": str(i)} for i in range(1001)])
    assert "TOO_MANY_ITEMS:adapters" in _evaluate(huge)["capabilities"]["network_control"]["reasons"]


def test_every_unknown_has_a_reason():
    base = _measurement()
    variants = [base, None, {}, "x", _without(base, "vm"), _with(base, "vm.state", "Paused")]
    variants += [_without(base, p) for p in _paths(base)]
    variants += [_with(base, p, None) for p in _paths(base)]
    variants += [_with(base, p, "garbage") for p in _paths(base)]
    seen_unknown = seen_verified = 0
    for m in variants:
        result = _evaluate(m)
        _assert_invariants(result)
        for cap in result["capabilities"].values():
            if cap["status"] == "UNKNOWN":
                seen_unknown += 1
                assert all(isinstance(r, str) and r for r in cap["reasons"])
            else:
                seen_verified += 1
    assert seen_unknown > 100 and seen_verified > 0
    assert GuestAttestation.CAPABILITIES == ALL


def test_input_is_not_mutated():
    m = _measurement()
    before = copy.deepcopy(m)
    _evaluate(m)
    assert m == before


def test_schema_fields_describe_the_fixture():
    # The slice-2 script is tested against these constants: they must match what the evaluator reads.
    m = _measurement()
    assert set(GuestAttestation.SCHEMA_FIELDS[""]) <= set(m)
    for section, fields in GuestAttestation.SCHEMA_FIELDS.items():
        if section:
            assert set(fields) == set(m[section]), section
    for section, fields in GuestAttestation.SCHEMA_ITEM_FIELDS.items():
        for item in m[section]["items"]:
            assert set(fields) == set(item), section


def test_schema_1_is_refused_with_an_explicit_reason():
    # /1 wrote host adapters as vm_id: null peers; reading it back would be a guess, so it is refused.
    result = _evaluate(_measurement(schema_version="liebert-re.guest-measurement/1"))
    assert set(_status(result).values()) == {"UNKNOWN"}
    for cap in result["capabilities"].values():
        assert cap["reasons"] == ["SCHEMA_MISMATCH", "SCHEMA_SUPERSEDED"]
    assert result["isolation_basis"] == "none"
    assert result["schema_version"] == GuestAttestation.SCHEMA


def _internal_switch_with_host(host_switch_id=SWITCH_ID, switch_type="Internal"):
    m = _with(_measurement(), "switches.items.0.switch_type", switch_type)
    return _with(m, "host_adapters.items", [{"switch_id": host_switch_id, "kind": "host_management"}])


def test_host_adapter_on_internal_switch_is_a_shared_switch_fact():
    result = _evaluate(_internal_switch_with_host())
    net = result["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN"
    assert "SWITCH_SHARED_WITH_HOST" in net["reasons"] and "SWITCH_NOT_PRIVATE" in net["reasons"]
    assert not any(r.startswith(("INVALID:", "MISSING:", "SECTION_NOT_OK")) for r in net["reasons"])
    assert net["evidence"]["switch_shared_with_host"] is True
    assert result["capabilities"]["isolated_guest"]["status"] == "VERIFIED"
    assert result["isolation_basis"] == "observed_partial"
    _assert_invariants(result)


def test_private_switch_without_host_adapter_still_verifies():
    result = _evaluate(_measurement())
    net = result["capabilities"]["network_control"]
    assert net["status"] == "VERIFIED"
    assert net["evidence"]["switch_shared_with_host"] is False
    assert result["isolation_verified"] is True
    # a host adapter on a switch this VM is not attached to does not matter
    elsewhere = _with(_measurement(), "host_adapters.items",
                      [{"switch_id": OTHER_SWITCH_ID, "kind": "host_management"}])
    assert _evaluate(elsewhere)["capabilities"]["network_control"]["status"] == "VERIFIED"


def test_host_adapter_on_a_private_switch_contradicts_the_file():
    net = _evaluate(_internal_switch_with_host(switch_type="Private"))["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN"
    assert "SWITCH_SHARED_WITH_HOST" in net["reasons"] and "CONTRADICTION:host_adapters" in net["reasons"]


def test_switch_peer_with_null_vm_id_is_still_invalid():
    # The old ambiguity is not silently re-read as a host adapter.
    m = _with(_measurement(), "switch_peers.items", [{"switch_id": SWITCH_ID, "vm_id": None}])
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and "INVALID:switch_peers" in net["reasons"]


@pytest.mark.parametrize("item,reason", [
    ({"switch_id": "not-a-guid", "kind": "host_management"}, "INVALID:host_adapters.switch_id"),
    ({"switch_id": None, "kind": "host_management"}, "INVALID:host_adapters.switch_id"),
    ({"switch_id": SWITCH_ID}, "MISSING:host_adapters.kind"),
    ({"switch_id": SWITCH_ID, "kind": "vm"}, "INVALID:host_adapters.kind"),
])
def test_malformed_host_adapter_item_is_unknown(item, reason):
    m = _with(_measurement(), "host_adapters.items", [item])
    net = _evaluate(m)["capabilities"]["network_control"]
    assert net["status"] == "UNKNOWN" and reason in net["reasons"]


def test_unconnected_adapter_needs_no_host_adapter_section():
    m = _with(_without(_measurement(), "host_adapters"), "adapters.items.0.connected", False)
    assert _evaluate(m)["capabilities"]["network_control"]["status"] == "VERIFIED"


def _failed_guest(category):
    return {"ok": False, "error": "System.Management.Automation.Remoting.PSDirectException",
            "error_category": category, "vm_id_from_kvp": None, "os_build": None,
            "vbs_status": None, "security_services_running": None}


def test_error_category_is_carried_into_the_reason():
    result = _evaluate(_with(_measurement(), "guest", _failed_guest("AuthenticationError/InvalidPassword")))
    iso = result["capabilities"]["isolated_guest"]
    assert iso["status"] == "UNKNOWN"
    assert "SECTION_NOT_OK:guest:AuthenticationError/InvalidPassword" in iso["reasons"]
    # the message-like error text is never copied
    assert "PSDirectException" not in json.dumps(result)
    steps = _with(_measurement(), "guest", _failed_guest("kvp:ObjectNotFound,vbs:PermissionDenied"))
    assert "SECTION_NOT_OK:guest:kvp:ObjectNotFound,vbs:PermissionDenied" in \
        _evaluate(steps)["capabilities"]["isolated_guest"]["reasons"]
    host_down = _with(_measurement(), "host_adapters",
                      {"ok": False, "error": "x", "error_category": "NotSpecified", "items": []})
    assert "SECTION_NOT_OK:host_adapters:NotSpecified" in \
        _evaluate(host_down)["capabilities"]["network_control"]["reasons"]


@pytest.mark.parametrize("category", [None, "", "has space", "D:\\secret\\x", "x" * 500, 7, ["Cat"], "a\nb",
                                      "9start", "quote'd"])
def test_unsafe_error_category_is_not_copied(category):
    reasons = _evaluate(_with(_measurement(), "guest", _failed_guest(category)))["capabilities"][
        "isolated_guest"]["reasons"]
    assert "SECTION_NOT_OK:guest" in reasons
    assert not any(r.startswith("SECTION_NOT_OK:guest:") for r in reasons)


def test_category_on_an_ok_section_is_a_contradiction():
    m = _with(_measurement(), "host_adapters.error_category", "PermissionDenied")
    assert "CONTRADICTION:host_adapters.error_category" in \
        _evaluate(m)["capabilities"]["network_control"]["reasons"]
    absent = _without(_measurement(), "host_adapters.error_category")
    assert _evaluate(absent)["capabilities"]["network_control"]["status"] == "VERIFIED"


# ---------------------------------------------------------------------------------------------
# GuestAttestation.admit: the one VERIFIED / UNKNOWN / FAILED answer the lab gate reads.
# ---------------------------------------------------------------------------------------------

def _admissible(**overrides):
    """A fully VERIFIED measurement: the isolated fixture plus Memory Integrity running in the guest."""
    return _with(_measurement(**overrides), "guest.security_services_running", [1, 2])


def _admit(m, **kw):
    kw.setdefault("now_utc", NOW)
    kw.setdefault("local_vm_id", VM_ID)
    return GuestAttestation.admit(m, **kw)


def test_admit_verifies_a_complete_fresh_measurement_and_leaks_no_identity():
    result = _admit(_admissible())
    assert result["verdict"] == "VERIFIED" and result["reasons"] == []
    assert all(v is True for v in result["conditions"].values()) and result["conditions"]
    assert result["spoofable"] is True and result["not_covered"]
    assert {c["status"] for c in result["capabilities"].values()} == {"VERIFIED"}
    text = json.dumps(result)
    for secret in (VM_ID, CHECKPOINT_ID, SWITCH_ID, HOST_HASH, "lab-vm", "lab-private"):
        assert secret not in text


def test_admit_accepts_a_measured_absence_of_adapters():
    m = _with(_admissible(), "adapters.items", [])
    result = _admit(m)
    assert result["verdict"] == "VERIFIED" and result["notes"] == ["measured absence of adapters"]


# (case id, mutation of the VERIFIED fixture, expected verdict, a reason that must be present)
_ADMIT_CASES = [
    # measured violations in a trustworthy file -> FAILED
    ("hvci_off", lambda m: _with(m, "guest.security_services_running", [1]), "FAILED", "HVCI_NOT_RUNNING"),
    ("hvci_list_empty", lambda m: _with(m, "guest.security_services_running", []), "FAILED", "HVCI_NOT_RUNNING"),
    ("checkpoint_not_standard", lambda m: _with(m, "checkpoints.items.0.type", "Production"), "FAILED",
     "NO_STANDARD_CHECKPOINT"),
    ("no_checkpoints_measured", lambda m: _with(m, "checkpoints.items", []), "FAILED", "NO_STANDARD_CHECKPOINT"),
    ("standard_checkpoint_of_another_vm", lambda m: _with(m, "checkpoints.items.0.vm_id", OTHER_VM_ID), "UNKNOWN",
     "NO_STANDARD_CHECKPOINT"),  # the parent checkpoint also contradicts: the file is not trusted
    ("switch_external", lambda m: _with(m, "switches.items.0.switch_type", "External"), "FAILED",
     "SWITCH_NOT_PRIVATE"),
    ("switch_internal", lambda m: _with(m, "switches.items.0.switch_type", "Internal"), "FAILED",
     "SWITCH_NOT_PRIVATE"),
    ("host_adapter_on_external_switch",
     lambda m: _with(_with(m, "switches.items.0.switch_type", "External"), "host_adapters.items",
                     [{"switch_id": SWITCH_ID, "kind": "host_management"}]),
     "FAILED", "SWITCH_SHARED_WITH_HOST"),
    ("peer_vm_on_switch", lambda m: _with(m, "switch_peers.items", [{"switch_id": SWITCH_ID, "vm_id": OTHER_VM_ID}]),
     "FAILED", "PEER_VM_ON_SWITCH"),
    ("vm_not_running", lambda m: _with(m, "vm.state", "Off"), "FAILED", "VM_NOT_RUNNING"),
    ("guest_service_interface_enabled",
     lambda m: _with(m, "integration_services.items.0.enabled", True), "FAILED", "GUEST_SERVICE_INTERFACE_ENABLED"),
    # missing or unreadable facts -> UNKNOWN, never FAILED and never VERIFIED
    ("hvci_list_absent", lambda m: _without(m, "guest.security_services_running"), "UNKNOWN",
     "MISSING:guest.security_services_running"),
    ("hvci_list_null", lambda m: _with(m, "guest.security_services_running", None), "UNKNOWN",
     "MISSING:guest.security_services_running"),
    ("hvci_list_malformed", lambda m: _with(m, "guest.security_services_running", ["2"]), "UNKNOWN",
     "INVALID:guest.security_services_running"),
    ("hvci_list_a_string", lambda m: _with(m, "guest.security_services_running", "2"), "UNKNOWN",
     "INVALID:guest.security_services_running"),
    ("guest_unreached", lambda m: _with(_with(m, "guest.ok", False), "guest.error", "x"), "UNKNOWN",
     "HVCI_NOT_MEASURED"),
    ("guest_section_absent", lambda m: _without(m, "guest"), "UNKNOWN", "MISSING:guest"),
    ("guest_section_wrong_type", lambda m: _with(m, "guest", "ok"), "UNKNOWN", "HVCI_NOT_MEASURED"),
    ("checkpoint_type_absent", lambda m: _without(m, "checkpoints.items.0.type"), "UNKNOWN",
     "MISSING:checkpoints.type"),
    ("checkpoint_type_not_a_string", lambda m: _with(m, "checkpoints.items.0.type", 1), "UNKNOWN",
     "MISSING:checkpoints.type"),
    ("checkpoints_section_absent", lambda m: _without(m, "checkpoints"), "UNKNOWN", "MISSING:checkpoints"),
    ("checkpoints_query_failed", lambda m: _with(_with(m, "checkpoints.ok", False), "checkpoints.error", "x"),
     "UNKNOWN", "SECTION_NOT_OK:checkpoints"),
    ("adapters_section_absent", lambda m: _without(m, "adapters"), "UNKNOWN", "MISSING:adapters"),
    ("switches_section_absent", lambda m: _without(m, "switches"), "UNKNOWN", "MISSING:switches"),
    ("host_adapters_section_absent", lambda m: _without(m, "host_adapters"), "UNKNOWN", "MISSING:host_adapters"),
    ("switch_type_absent", lambda m: _without(m, "switches.items.0.switch_type"), "UNKNOWN",
     "MISSING:switches.switch_type"),
    ("vm_section_absent", lambda m: _without(m, "vm"), "UNKNOWN", "MISSING:vm"),
    ("vm_state_absent", lambda m: _without(m, "vm.state"), "UNKNOWN", "MISSING:vm.state"),
    ("measured_at_absent", lambda m: _without(m, "measured_at_utc"), "UNKNOWN", "MISSING:measured_at_utc"),
    ("measured_at_malformed", lambda m: _with(m, "measured_at_utc", "yesterday"), "UNKNOWN",
     "INVALID:measured_at_utc"),
    ("measured_at_naive", lambda m: _with(m, "measured_at_utc", "2030-01-01T11:59:00"), "UNKNOWN",
     "INVALID:measured_at_utc"),
    # a file that cannot be trusted proves nothing: UNKNOWN, even when it also states a violation
    ("stale", lambda m: _with(m, "measured_at_utc", _stamp(NOW - timedelta(seconds=901))), "UNKNOWN",
     "STALE_MEASUREMENT"),
    ("stale_and_hvci_off",
     lambda m: _with(_with(m, "measured_at_utc", _stamp(NOW - timedelta(days=3))),
                     "guest.security_services_running", []), "UNKNOWN", "STALE_MEASUREMENT"),
    ("from_the_future", lambda m: _with(m, "measured_at_utc", _stamp(NOW + timedelta(minutes=10))), "UNKNOWN",
     "CONTRADICTION:measured_at_utc"),
    ("schema_superseded", lambda m: _with(m, "schema_version", "liebert-re.guest-measurement/1"), "UNKNOWN",
     "SCHEMA_SUPERSEDED"),
    ("schema_unknown", lambda m: _with(m, "schema_version", "something/9"), "UNKNOWN", "SCHEMA_MISMATCH"),
    ("schema_absent", lambda m: _without(m, "schema_version"), "UNKNOWN", "SCHEMA_MISMATCH"),
    ("guest_reports_another_vm", lambda m: _with(m, "guest.vm_id_from_kvp", OTHER_VM_ID), "UNKNOWN",
     "CONTRADICTION:guest.vm_id_from_kvp"),
    ("violation_plus_contradiction",
     lambda m: _with(_with(m, "guest.security_services_running", []), "guest.vm_id_from_kvp", OTHER_VM_ID),
     "UNKNOWN", "CONTRADICTION:guest.vm_id_from_kvp"),
    ("private_switch_with_host_adapter",
     lambda m: _with(m, "host_adapters.items", [{"switch_id": SWITCH_ID, "kind": "host_management"}]), "UNKNOWN",
     "CONTRADICTION:host_adapters"),
    ("duplicate_checkpoint_ids", lambda m: _with(m, "checkpoints.items", m["checkpoints"]["items"] * 2), "UNKNOWN",
     "CONTRADICTION:checkpoints.id"),
]


@pytest.mark.parametrize("case_id,mutate,verdict,reason", _ADMIT_CASES, ids=[c[0] for c in _ADMIT_CASES])
def test_admit_breaks_on_every_condition(case_id, mutate, verdict, reason):
    result = _admit(mutate(_admissible()))
    assert result["verdict"] == verdict, result["reasons"]
    assert result["verdict"] != "VERIFIED" and reason in result["reasons"], result["reasons"]
    assert result["spoofable"] is True
    json.dumps(result)


@pytest.mark.parametrize("measurement", [None, [], "x", 7, 1.5, True, {}, {"schema_version": GuestAttestation.SCHEMA}])
def test_admit_of_a_non_measurement_is_unknown(measurement):
    result = _admit(measurement)
    assert result["verdict"] == "UNKNOWN" and result["reasons"]


@pytest.mark.parametrize("path", ["schema_version", "measured_at_utc", "script_version", "elevated", "host", "vm",
                                  "checkpoints", "adapters", "switches", "switch_peers", "host_adapters",
                                  "integration_services", "guest", "vm.id", "vm.state", "vm.parent_checkpoint_id",
                                  "host.identity_sha256", "guest.vm_id_from_kvp", "guest.ok", "checkpoints.ok",
                                  "adapters.items", "adapters.items.0.connected", "adapters.items.0.switch_id",
                                  "switches.items.0.id", "switches.items.0.name"])
def test_admit_is_never_verified_when_a_required_field_is_missing(path):
    assert _admit(_without(_admissible(), path))["verdict"] != "VERIFIED"


def test_admit_freshness_threshold_is_a_parameter():
    m = _admissible()  # measured 60 s before NOW
    assert _admit(m, max_age_s=120)["verdict"] == "VERIFIED"
    assert _admit(m, max_age_s=60)["verdict"] == "VERIFIED"  # exactly at the limit is still fresh
    result = _admit(m, max_age_s=59)
    assert result["verdict"] == "UNKNOWN" and "STALE_MEASUREMENT" in result["reasons"]
    assert result["conditions"]["measurement_fresh"] is False


@pytest.mark.parametrize("bad", [0, -5, None, True, "900", float("nan")])
def test_admit_refuses_an_unusable_age_threshold(bad):
    result = _admit(_admissible(), max_age_s=bad)
    assert result["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("bad", [None, "", "not-a-guid", 7, OTHER_VM_ID])
def test_admit_needs_a_measurement_about_the_machine_it_runs_on(bad):
    assert _admit(_admissible(), local_vm_id=bad)["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("now", [None, "2030-01-01", 7, datetime(2030, 1, 1)])
def test_admit_needs_a_timezone_aware_clock(now):
    assert _admit(_admissible(), now_utc=now)["verdict"] == "UNKNOWN"


def test_admit_conditions_say_which_fact_broke():
    off = _admit(_with(_admissible(), "guest.security_services_running", []))
    assert off["conditions"]["guest_memory_integrity"] is False and off["conditions"]["standard_checkpoint"] is True
    public = _admit(_with(_admissible(), "switches.items.0.switch_type", "External"))
    assert public["conditions"]["network_private_only"] is False
    shared = _admit(_with(_with(_admissible(), "switches.items.0.switch_type", "External"), "host_adapters.items",
                          [{"switch_id": SWITCH_ID, "kind": "host_management"}]))
    assert shared["conditions"]["no_host_adapter_on_switch"] is False
    nockpt = _admit(_with(_admissible(), "checkpoints.items.0.type", "Production"))
    assert nockpt["conditions"]["standard_checkpoint"] is False
    unknown = _admit(_without(_admissible(), "guest.security_services_running"))
    assert unknown["conditions"]["guest_memory_integrity"] is None


def test_admit_never_raises_on_hostile_nesting():
    hostile = _admissible()
    hostile["checkpoints"]["items"] = [[], None, 3, {"id": {}}]
    hostile["adapters"]["items"] = "x"
    hostile["guest"]["security_services_running"] = [object()]
    result = _admit(hostile)
    assert result["verdict"] == "UNKNOWN" and result["reasons"]


def test_admit_ignores_the_operator_assertion():
    m = _with(_with(_admissible(), "guest.security_services_running", []), "isolation_asserted_by_operator", True)
    assert _admit(m)["verdict"] == "FAILED"
