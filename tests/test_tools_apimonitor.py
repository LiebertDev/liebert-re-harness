"""tools_apimonitor.py's own contract: TOOL_MISSING when the API/ definitions
tree is absent (never raises), live_trace/parse_trace are unconditional,
honest NOT_SUPPORTED refusals that never construct a subprocess (this
install genuinely has no CLI/headless automation surface -- verified against
the real binary, see the module docstring), and api_catalog is a real,
deterministic parse of API Monitor's own XML definition schema
(<Module Name=...><Api Name=.../></Module>). Mirrors tests/test_tools_die.py's
guard style for a real, possibly-absent external toolchain: probe first,
skipTest cleanly when API Monitor genuinely isn't installed on this machine.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tools_apimonitor as am

REPO_ROOT = Path(__file__).resolve().parent.parent

# A small, schema-faithful fixture mirroring the REAL API Monitor definitions
# format verified on this host (API/Windows/Advapi32.xml uses exactly this
# <ApiMonitor><Module Name="..." CallingConvention="..."><Api Name="..."/>
# .../Module></ApiMonitor> shape).
FIXTURE_XML = """<?xml version="1.0"?>
<ApiMonitor>
    <Module Name="Advapi32.dll" CallingConvention="STDCALL">
        <Api Name="RegCreateKeyEx" />
        <Api Name="RegCloseKey" />
        <Api Name="RegOpenKeyEx" />
    </Module>
</ApiMonitor>
"""

FIXTURE_XML_SECOND_MODULE = """<?xml version="1.0"?>
<ApiMonitor>
    <Module Name="Kernel32.dll" CallingConvention="STDCALL">
        <Api Name="CreateFileW" />
        <Api Name="ReadFile" />
    </Module>
</ApiMonitor>
"""

# Schema-faithful fixture for the SECOND real container shape this tree
# uses (API/Interfaces/*.xml -- verified against the real
# IClassFactory.xml on this host): <Interface Name="..."> wrapping COM
# interface methods, not <Module>.
FIXTURE_XML_INTERFACE = """<?xml version="1.0"?>
<ApiMonitor>
    <Interface Name="IClassFactory" BaseInterface="IUnknown">
        <Api Name="CreateInstance" />
        <Api Name="LockServer" />
    </Interface>
</ApiMonitor>
"""


class ApiMonitorMissingTests(unittest.TestCase):
    """The absence path must never raise and must use the repo's standard
    TOOL_MISSING shape, independent of whether API Monitor is actually
    installed on the machine running the test."""

    def test_missing_exe_reports_unavailable(self):
        with mock.patch.object(am, "_exe_path", return_value=None):
            self.assertFalse(am.apimonitor_available())

    def test_status_reports_unavailable_when_no_exe_present(self):
        with mock.patch.object(am, "_exe_path", return_value=None), \
             mock.patch.object(am, "_api_dir", return_value=Path("C:/does/not/exist")):
            out = am.status()
        data = json.loads(out)
        self.assertTrue(data["ok"])  # status() itself never fails, only reports
        self.assertFalse(data["available"])
        self.assertFalse(data["api_definitions_dir_present"])

    def test_api_catalog_returns_tool_missing_when_api_dir_absent(self):
        with mock.patch.object(am, "_api_dir", return_value=Path("C:/definitely/not/here")):
            out = am.api_catalog()
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TOOL_MISSING")
        self.assertIn("required_capability", data)


class ApiMonitorUnsupportedOperationTests(unittest.TestCase):
    """live_trace and parse_trace are unconditional, honest refusals -- no
    CLI/headless automation surface exists for either on this real install,
    verified against the actual binary before this module was written."""

    def test_live_trace_never_starts_a_subprocess(self):
        with mock.patch("tools_apimonitor.run_bounded_process") as mocked_run:
            out = am.live_trace(target_path="C:/some/target.exe", isolated_context_confirmed=True)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_SUPPORTED")
        self.assertFalse(data["execution_performed"])
        mocked_run.assert_not_called()

    def test_live_trace_refuses_even_with_arbitrary_args(self):
        out = am.live_trace()
        data = json.loads(out)
        self.assertEqual(data["status"], "NOT_SUPPORTED")

    def test_parse_trace_never_reads_a_file(self):
        with mock.patch("tools_apimonitor.run_bounded_process") as mocked_run:
            out = am.parse_trace(trace_path="C:/some/trace.apmx64")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_SUPPORTED")
        self.assertFalse(data["execution_performed"])
        mocked_run.assert_not_called()


class ApiCatalogParsingTests(unittest.TestCase):
    """Real parse of API Monitor's own XML definition schema against a
    schema-faithful fixture -- deterministic, never guessed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.api_dir = Path(self._tmp.name) / "API"
        windows_dir = self.api_dir / "Windows"
        windows_dir.mkdir(parents=True)
        (windows_dir / "Advapi32.xml").write_text(FIXTURE_XML, encoding="utf-8")
        (windows_dir / "Kernel32.xml").write_text(FIXTURE_XML_SECOND_MODULE, encoding="utf-8")
        interfaces_dir = self.api_dir / "Interfaces"
        interfaces_dir.mkdir(parents=True)
        (interfaces_dir / "IClassFactory.xml").write_text(FIXTURE_XML_INTERFACE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_catalog_parses_dll_modules_and_functions(self):
        with mock.patch.object(am, "_api_dir", return_value=self.api_dir):
            out = am.api_catalog()
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["module_count"], 3)
        self.assertEqual(data["total_functions"], 7)
        names = {m["module"] for m in data["modules"]}
        self.assertEqual(names, {"Advapi32.dll", "Kernel32.dll", "IClassFactory"})
        advapi = next(m for m in data["modules"] if m["module"] == "Advapi32.dll")
        self.assertEqual(advapi["functions"], ["RegCloseKey", "RegCreateKeyEx", "RegOpenKeyEx"])
        self.assertEqual(advapi["calling_convention"], "STDCALL")
        self.assertEqual(advapi["kind"], "dll_module")

    def test_catalog_parses_com_interface_container_shape(self):
        with mock.patch.object(am, "_api_dir", return_value=self.api_dir):
            out = am.api_catalog(module_filter="iclassfactory")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["module_count"], 1)
        iface = data["modules"][0]
        self.assertEqual(iface["module"], "IClassFactory")
        self.assertEqual(iface["kind"], "com_interface")
        self.assertEqual(iface["base_interface"], "IUnknown")
        self.assertEqual(iface["functions"], ["CreateInstance", "LockServer"])

    def test_module_filter_narrows_result(self):
        with mock.patch.object(am, "_api_dir", return_value=self.api_dir):
            out = am.api_catalog(module_filter="kernel32")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["module_count"], 1)
        self.assertEqual(data["modules"][0]["module"], "Kernel32.dll")

    def test_unknown_category_is_a_clean_not_found(self):
        with mock.patch.object(am, "_api_dir", return_value=self.api_dir):
            out = am.api_catalog(category="NoSuchCategory")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_FOUND")

    def test_malformed_xml_is_reported_not_a_crash(self):
        (self.api_dir / "Windows" / "Broken.xml").write_text("<ApiMonitor><Module", encoding="utf-8")
        with mock.patch.object(am, "_api_dir", return_value=self.api_dir):
            out = am.api_catalog()
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(len(data["parse_errors"]), 1)
        # the well-formed modules/interfaces are still parsed despite the broken file
        self.assertEqual(data["module_count"], 3)


class ApiMonitorRealInstallTests(unittest.TestCase):
    """Exercised against the real API/*.xml definitions tree when API Monitor
    is actually installed; skips cleanly otherwise."""

    def setUp(self):
        if not am._api_dir().is_dir():
            raise unittest.SkipTest("API Monitor API/ definitions tree not installed on this machine")

    def test_real_catalog_scan_finds_a_large_known_module(self):
        out = am.api_catalog(category="Windows", module_filter="advapi32")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertGreaterEqual(data["module_count"], 1)
        advapi = next((m for m in data["modules"] if m["module"] == "Advapi32.dll"), None)
        self.assertIsNotNone(advapi, data["modules"])
        self.assertIn("RegCreateKeyEx", advapi["functions"])
        self.assertGreater(len(advapi["functions"]), 100)

    def test_real_status_reports_installed(self):
        out = am.status()
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(data["api_definitions_dir_present"])


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool or spawns a bounded subprocess -- these can be
# slow or hang, so they are excluded from the default run and must be run explicitly
# with `pytest -m heavy`. See pytest.ini in this repo for the tools actually involved.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
