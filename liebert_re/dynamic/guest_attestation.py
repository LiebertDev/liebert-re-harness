"""Guest attestation: turn MEASURED Hyper-V facts into VERIFIED or UNKNOWN, never into a guess.

The dynamic-lab gate cannot see whether the machine it runs in is a disposable, snapshotted,
network-controlled guest. This module decides that from a measurement document (schema
``liebert-re.guest-measurement/1``) that a separate host-side script produces. It is PURE: it
reads no file, no clock and no registry. The caller passes the measurement, the current time
(``now_utc``) and the VM id of the machine the gate is running on (``local_vm_id``).

Three capabilities are judged independently. Each is ``VERIFIED`` only when every condition in
its table holds; anything missing, malformed, stale or contradictory is ``UNKNOWN`` with a
machine-readable reason. There is no third answer and no default (CONTRIBUTING.md, first rule).

* ``isolated_guest``: the VM is Running; the guest reports the same VM id the host measured
  (read through the Hyper-V data-exchange channel); the id of the machine running the gate is
  that VM id; the Guest Service Interface integration service is disabled.
* ``snapshot_and_rollback``: the VM's parent checkpoint id resolves to exactly one measured
  checkpoint that belongs to this VM and was created before the measurement.
* ``network_control``: the adapter section is measured and either no adapter exists (a measured
  absence) or every connected adapter resolves to exactly one Private switch with no other VM
  on it.

Preconditions for all three: the schema matches, the measurement is fresh (``0 <= age <=
max_age_s``; a clock skew of up to 120 s into the future is tolerated, more is a contradiction),
``vm.id`` is a GUID, the measurement is bound to the machine evaluating it (``local_vm_id``
equals ``vm.id``; a measurement evaluated on the host, or about another VM, proves nothing about
this machine) and every section the capability reads reports ``ok``.

WHAT THIS IS NOT. Every capability carries ``spoofable: true``: the file can be fabricated by
anyone who can write it, and a malicious hypervisor is out of scope. The threat model is a
careless operator, not an adversary. ``not_covered`` lists, per capability, what the measurement
does not establish (that a checkpoint is clean, that a restore works, what an allow-list
contains). An operator assertion that the lab is isolated (``isolation_asserted_by_operator``)
is carried through and may label ``isolation_basis`` as ``asserted``; no rule reads it and it
never produces VERIFIED. ``informational.guest_hvci_running`` is a report only; this module
never inspects, changes or advises on it.

Evidence holds counts, booleans and switch types only; no VM names, GUIDs or host identity are
copied into the result (AGENTS.md rule 9).

Public surface is the class ``GuestAttestation``; module helpers are underscore-private on purpose.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_UTC_STAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})"
)
# Item cap: a measurement of one VM has a handful of entries; a huge list is refused, not walked.
_MAX_ITEMS = 1000
_FUTURE_SKEW = timedelta(seconds=120)
_GUEST_SERVICE_SUFFIX = "6c09bb55-d683-4da0-8931-c9bf705f6480"  # unmeasured assumption (spec VARSAYIM 4)
_HVCI_SERVICE_CODE = 2  # unmeasured assumption (spec VARSAYIM 5)
_HVCI_NOTE = "service code 2 read as HVCI is an unmeasured assumption"
_KNOWN_SWITCH_TYPES = ("Private", "Internal", "External")

_CAPABILITIES = ("isolated_guest", "snapshot_and_rollback", "network_control")
_NOT_COVERED = MappingProxyType({
    "isolated_guest": (
        "that the guest is single-use",
        "enhanced session / clipboard sharing",
        "a malicious hypervisor",
    ),
    "snapshot_and_rollback": (
        "that the checkpoint is clean",
        "that a restore was attempted",
    ),
    "network_control": (
        "the contents of any allow-list",
        "traffic actually blocked (only switch topology is measured)",
    ),
})


def _guid(value: Any) -> str | None:
    """Canonical lower-case GUID or ``None``; braces, whitespace and non-strings are refused."""
    if isinstance(value, str) and _GUID.fullmatch(value):
        return value.lower()
    return None


def _utc(value: Any) -> datetime | None:
    """Parse an ISO 8601 stamp that carries an offset; a naive or malformed stamp is ``None``."""
    if not isinstance(value, str):
        return None
    m = _UTC_STAMP.fullmatch(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    micro = int((m.group(7) or "0").ljust(6, "0")[:6])
    zone = m.group(8)
    try:
        if zone == "Z":
            tz = timezone.utc
        else:
            sign = -1 if zone[0] == "-" else 1
            tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _section(m: dict, name: str, reasons: list[str]) -> dict | None:
    """The section object when it is present and reports ``ok``; otherwise a reason is appended."""
    sec = m.get(name)
    if not isinstance(sec, dict):
        reasons.append(f"MISSING:{name}" if sec is None else f"INVALID:{name}")
        return None
    ok = sec.get("ok")
    if not isinstance(ok, bool):
        reasons.append(f"INVALID:{name}.ok")
        return None
    if not ok:
        reasons.append(f"SECTION_NOT_OK:{name}")
        return None
    if sec.get("error") not in (None, ""):
        reasons.append(f"CONTRADICTION:{name}.error")
        return None
    return sec


def _items(m: dict, name: str, reasons: list[str]) -> list[dict] | None:
    """The ``items`` list of an ``ok`` list section, every element an object; else a reason."""
    sec = _section(m, name, reasons)
    if sec is None:
        return None
    items = sec.get("items")
    if not isinstance(items, list):
        reasons.append(f"MISSING:{name}.items" if items is None else f"INVALID:{name}.items")
        return None
    if len(items) > _MAX_ITEMS:
        reasons.append(f"TOO_MANY_ITEMS:{name}")
        return None
    if not all(isinstance(i, dict) for i in items):
        reasons.append(f"INVALID:{name}.items")
        return None
    return items


def _field_guid(obj: dict, key: str, path: str, reasons: list[str]) -> str | None:
    value = obj.get(key)
    if value is None:
        reasons.append(f"MISSING:{path}")
        return None
    g = _guid(value)
    if g is None:
        reasons.append(f"INVALID:{path}")
    return g


def _unique(ids: list[str], path: str, reasons: list[str]) -> bool:
    """False (with a contradiction) when an id is repeated."""
    if len(set(ids)) != len(ids):
        reasons.append(f"CONTRADICTION:{path}")
        return False
    return True


class _Context:
    """Facts every capability needs, established once; ``reasons`` blocks all three."""

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.vm_id: str | None = None
        self.measured_at: datetime | None = None
        self.age_s: float | None = None
        self.vm: dict | None = None


def _precheck(m: Any, now_utc: Any, local_vm_id: Any, max_age_s: Any) -> _Context:
    ctx = _Context()
    r = ctx.reasons
    if not isinstance(m, dict):
        r.append("MEASUREMENT_NOT_AN_OBJECT")
        return ctx
    if m.get("schema_version") != GuestAttestation.SCHEMA:
        r.append("SCHEMA_MISMATCH")
        return ctx
    now = now_utc if isinstance(now_utc, datetime) and now_utc.tzinfo is not None else None
    if now is None:
        r.append("NOW_UTC_INVALID")
    if isinstance(max_age_s, bool) or not isinstance(max_age_s, (int, float)) or not max_age_s > 0:
        r.append("MAX_AGE_INVALID")
        now = None
    stamp = m.get("measured_at_utc")
    if stamp is None:
        r.append("MISSING:measured_at_utc")
    else:
        ctx.measured_at = _utc(stamp)
        if ctx.measured_at is None:
            r.append("INVALID:measured_at_utc")
    if now is not None and ctx.measured_at is not None:
        age = now.astimezone(timezone.utc) - ctx.measured_at
        ctx.age_s = round(age.total_seconds(), 3)
        if age < -_FUTURE_SKEW:
            r.append("CONTRADICTION:measured_at_utc")
        elif age > timedelta(seconds=max_age_s):
            r.append("STALE_MEASUREMENT")
    script = m.get("script_version")
    if script is None:
        r.append("MISSING:script_version")
    elif not isinstance(script, str) or not script:
        r.append("INVALID:script_version")
    elev = m.get("elevated")
    if elev is None:
        r.append("MISSING:elevated")
    elif not isinstance(elev, bool):
        r.append("INVALID:elevated")
    ctx.vm = _section(m, "vm", r)
    if ctx.vm is not None:
        ctx.vm_id = _field_guid(ctx.vm, "id", "vm.id", r)
    if ctx.vm_id is not None:
        if local_vm_id is None:
            r.append("MISSING:local_vm_id")
        elif _guid(local_vm_id) is None:
            r.append("INVALID:local_vm_id")
        elif _guid(local_vm_id) != ctx.vm_id:
            r.append("CONTRADICTION:local_vm_id")
    return ctx


def _result(status_reasons: list[str], evidence: dict, name: str, *, note: str | None = None) -> dict:
    reasons = list(dict.fromkeys(status_reasons))
    verified = not reasons
    if verified and note is not None:
        reasons = [note]
    return {
        "status": "VERIFIED" if verified else "UNKNOWN",
        "reasons": reasons,
        "evidence": evidence,
        "not_covered": list(_NOT_COVERED[name]),
        "spoofable": True,
    }


def _eval_isolated_guest(m: Any, ctx: _Context) -> dict:
    r = list(ctx.reasons)
    ev: dict[str, Any] = {"measurement_age_s": ctx.age_s, "vm_running": None, "guest_vm_id_matches": None,
                          "guest_service_interface_enabled": None}
    if isinstance(m, dict) and ctx.vm is not None:
        state = ctx.vm.get("state")
        if state is None:
            r.append("MISSING:vm.state")
        elif not isinstance(state, str):
            r.append("INVALID:vm.state")
        else:
            ev["vm_running"] = state == "Running"
            if state != "Running":
                r.append("VM_NOT_RUNNING")
        host = _section(m, "host", r)
        if host is not None:
            digest = host.get("identity_sha256")
            if digest is None:
                r.append("MISSING:host.identity_sha256")
            elif not (isinstance(digest, str) and _SHA256.fullmatch(digest)):
                r.append("INVALID:host.identity_sha256")
        guest = _section(m, "guest", r)
        if guest is not None:
            kvp = _field_guid(guest, "vm_id_from_kvp", "guest.vm_id_from_kvp", r)
            if kvp is not None and ctx.vm_id is not None:
                ev["guest_vm_id_matches"] = kvp == ctx.vm_id
                if kvp != ctx.vm_id:
                    r.append("CONTRADICTION:guest.vm_id_from_kvp")
        services = _items(m, "integration_services", r)
        if services is not None:
            _check_guest_service(services, ev, r)
    return _result(r, ev, "isolated_guest")


def _check_guest_service(services: list[dict], ev: dict, r: list[str]) -> None:
    suffixes = [s.get("id_suffix") for s in services]
    if not all(isinstance(s, str) for s in suffixes):
        r.append("INVALID:integration_services.id_suffix")
        return
    hits = [s for s in services if s["id_suffix"].lower() == _GUEST_SERVICE_SUFFIX]
    if len(hits) > 1:
        r.append("CONTRADICTION:integration_services.id_suffix")
    elif not hits:
        r.append("MISSING:integration_services.guest_service_interface")
    else:
        enabled = hits[0].get("enabled")
        if not isinstance(enabled, bool):
            r.append("MISSING:integration_services.enabled" if enabled is None
                     else "INVALID:integration_services.enabled")
        else:
            ev["guest_service_interface_enabled"] = enabled
            if enabled:
                r.append("GUEST_SERVICE_INTERFACE_ENABLED")


def _eval_snapshot(m: Any, ctx: _Context) -> dict:
    r = list(ctx.reasons)
    ev: dict[str, Any] = {"measurement_age_s": ctx.age_s, "checkpoint_count": None,
                          "parent_checkpoint_found": None, "checkpoint_vm_id_matches": None,
                          "checkpoint_before_measurement": None}
    if isinstance(m, dict) and ctx.vm is not None:
        parent = _field_guid(ctx.vm, "parent_checkpoint_id", "vm.parent_checkpoint_id", r)
        items = _items(m, "checkpoints", r)
        if items is not None:
            ev["checkpoint_count"] = len(items)
            ids = [_guid(c.get("id")) for c in items]
            if any(i is None for i in ids):
                r.append("INVALID:checkpoints.id")
            elif _unique(ids, "checkpoints.id", r) and parent is not None:
                hits = [c for c, i in zip(items, ids) if i == parent]
                ev["parent_checkpoint_found"] = bool(hits)
                if not hits:
                    r.append("PARENT_CHECKPOINT_NOT_MEASURED")
                else:
                    _check_checkpoint(hits[0], ctx, ev, r)
    return _result(r, ev, "snapshot_and_rollback")


def _check_checkpoint(cp: dict, ctx: _Context, ev: dict, r: list[str]) -> None:
    owner = _field_guid(cp, "vm_id", "checkpoints.vm_id", r)
    if owner is not None and ctx.vm_id is not None:
        ev["checkpoint_vm_id_matches"] = owner == ctx.vm_id
        if owner != ctx.vm_id:
            r.append("CONTRADICTION:checkpoints.vm_id")
    created = cp.get("created_utc")
    if created is None:
        r.append("MISSING:checkpoints.created_utc")
        return
    stamp = _utc(created)
    if stamp is None:
        r.append("INVALID:checkpoints.created_utc")
    elif ctx.measured_at is not None:
        ev["checkpoint_before_measurement"] = stamp < ctx.measured_at
        if not stamp < ctx.measured_at:
            r.append("CONTRADICTION:checkpoints.created_utc")


def _eval_network(m: Any, ctx: _Context) -> dict:
    r = list(ctx.reasons)
    ev: dict[str, Any] = {"measurement_age_s": ctx.age_s, "adapter_count": None,
                          "connected_adapter_count": None, "switch_types": None}
    note = None
    if isinstance(m, dict) and ctx.vm_id is not None:
        adapters = _items(m, "adapters", r)
        if adapters is not None:
            ev["adapter_count"] = len(adapters)
            if not adapters:
                ev["connected_adapter_count"] = 0
                ev["switch_types"] = []
                note = "measured absence of adapters"
            else:
                ids = [a.get("id") for a in adapters]
                if not all(isinstance(i, str) and i for i in ids):
                    r.append("INVALID:adapters.id")
                elif _unique(ids, "adapters.id", r):
                    _check_adapters(m, adapters, ctx.vm_id, ev, r)
    return _result(r, ev, "network_control", note=note)


def _check_adapters(m: dict, adapters: list[dict], vm_id: str, ev: dict, r: list[str]) -> None:
    flags = [a.get("connected") for a in adapters]
    if not all(isinstance(f, bool) for f in flags):
        r.append("INVALID:adapters.connected")
        return
    connected = [a for a in adapters if a["connected"]]
    ev["connected_adapter_count"] = len(connected)
    if not connected:
        ev["switch_types"] = []
        return
    switches = _items(m, "switches", r)
    peers = _items(m, "switch_peers", r)
    if switches is None or peers is None:
        return
    switch_ids = [_guid(s.get("id")) for s in switches]
    if any(i is None for i in switch_ids) or not _unique(switch_ids, "switches.id", r):
        if None in switch_ids:
            r.append("INVALID:switches.id")
        return
    peer_pairs = []
    for p in peers:
        sid, pvm = _guid(p.get("switch_id")), _guid(p.get("vm_id"))
        if sid is None or pvm is None:
            r.append("INVALID:switch_peers")
            return
        peer_pairs.append((sid, pvm))
    by_id = dict(zip(switch_ids, switches))
    types: set[str] = set()
    for a in connected:
        sid = _field_guid(a, "switch_id", "adapters.switch_id", r)
        if sid is None:
            continue
        sw = by_id.get(sid)
        if sw is None:
            r.append("SWITCH_NOT_RESOLVED")
            continue
        _check_switch(a, sw, [pvm for psid, pvm in peer_pairs if psid == sid], vm_id, types, r)
    ev["switch_types"] = sorted(types)


def _check_switch(a: dict, sw: dict, others: list[str], vm_id: str, types: set[str], r: list[str]) -> None:
    if a.get("switch_name") is None or sw.get("name") is None:
        r.append("MISSING:switch_name")
    elif a["switch_name"] != sw["name"]:
        r.append("CONTRADICTION:switch_name")
    stype = sw.get("switch_type")
    if not isinstance(stype, str):
        r.append("MISSING:switches.switch_type" if stype is None else "INVALID:switches.switch_type")
        return
    types.add(stype if stype in _KNOWN_SWITCH_TYPES else "OTHER")
    if stype != "Private":
        r.append("SWITCH_NOT_PRIVATE")
    if vm_id in others:
        r.append("CONTRADICTION:switch_peers")
    elif others:
        r.append("PEER_VM_ON_SWITCH")


def _guest_hvci(m: Any) -> bool | None:
    """True/False from the guest's reported services, ``None`` when it could not be read."""
    if not isinstance(m, dict):
        return None
    guest = m.get("guest")
    if not isinstance(guest, dict) or guest.get("ok") is not True:
        return None
    running = guest.get("security_services_running")
    if not isinstance(running, list) or len(running) > _MAX_ITEMS:
        return None
    if not all(isinstance(i, int) and not isinstance(i, bool) for i in running):
        return None
    return _HVCI_SERVICE_CODE in running


class GuestAttestation:
    """Evaluate a ``liebert-re.guest-measurement/1`` document; see the module docstring."""

    SCHEMA = "liebert-re.guest-measurement/1"
    DEFAULT_MAX_AGE_S = 900
    CAPABILITIES = _CAPABILITIES

    # Wire format the host-side script must emit. Key "" is the top level. ``checkpoints``,
    # ``adapters``, ``switches``, ``switch_peers`` and ``integration_services`` are list sections:
    # {ok, error, items: [<SCHEMA_ITEM_FIELDS>]}. ``host``, ``vm``, ``security`` and ``guest``
    # carry their fields directly next to ok/error. The optional top-level key
    # ``isolation_asserted_by_operator`` is never emitted by the script.
    SCHEMA_FIELDS = MappingProxyType({
        "": ("schema_version", "measured_at_utc", "script_version", "elevated"),
        "host": ("ok", "error", "identity_sha256"),
        "vm": ("ok", "error", "id", "name", "state", "generation", "automatic_checkpoints",
               "parent_checkpoint_id"),
        "checkpoints": ("ok", "error", "items"),
        "adapters": ("ok", "error", "items"),
        "switches": ("ok", "error", "items"),
        "switch_peers": ("ok", "error", "items"),
        "integration_services": ("ok", "error", "items"),
        "security": ("ok", "error", "tpm_enabled", "shielded"),
        "guest": ("ok", "error", "vm_id_from_kvp", "os_build", "vbs_status", "security_services_running"),
    })
    SCHEMA_ITEM_FIELDS = MappingProxyType({
        "checkpoints": ("id", "name", "vm_id", "created_utc", "type"),
        "adapters": ("id", "switch_id", "switch_name", "connected"),
        "switches": ("id", "name", "switch_type"),
        "switch_peers": ("switch_id", "vm_id"),
        "integration_services": ("id_suffix", "enabled"),
    })

    @classmethod
    def evaluate(cls, measurement: Any, *, now_utc: Any, local_vm_id: Any, max_age_s: Any = 900) -> dict:
        """Judge the three isolation capabilities. Never raises; any failure is UNKNOWN + reason."""
        try:
            ctx = _precheck(measurement, now_utc, local_vm_id, max_age_s)
            caps = {
                "isolated_guest": _eval_isolated_guest(measurement, ctx),
                "snapshot_and_rollback": _eval_snapshot(measurement, ctx),
                "network_control": _eval_network(measurement, ctx),
            }
            hvci = _guest_hvci(measurement)
            asserted = isinstance(measurement, dict) and measurement.get("isolation_asserted_by_operator") is True
        except Exception as exc:  # noqa: BLE001 - hostile input must degrade to UNKNOWN, announced
            reason = f"EVALUATION_ERROR:{type(exc).__name__}"
            caps = {n: _result([reason], {}, n) for n in _CAPABILITIES}
            hvci = None
            asserted = False
        verified = sum(1 for c in caps.values() if c["status"] == "VERIFIED")
        if verified == len(caps):
            basis = "observed"
        elif verified:
            basis = "observed_partial"
        elif asserted:
            basis = "asserted"
        else:
            basis = "none"
        return {
            "schema_version": cls.SCHEMA,
            "capabilities": caps,
            "isolation_verified": verified == len(caps),
            "isolation_basis": basis,
            "isolation_asserted_by_operator": asserted,
            "informational": {"guest_hvci_running": hvci, "guest_hvci_note": _HVCI_NOTE},
        }
