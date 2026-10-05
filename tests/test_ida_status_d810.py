"""`ida_status` reports the plugin `ida_microcode_cfg(deobfuscate=True)` depends on (`_d810_probe`).

Fast tier: nothing starts IDA; `idat` is `FakeIdat`, the registry is a stand-in and the two
places d810 can live are temporary directories. What is pinned:

* the three answers stay three: FOUND, NOT_FOUND, UNKNOWN (with a reason);
* a pip copy and a plugins copy are each reported, and which one IDA loads is UNKNOWN
  whenever both exist;
* a long project list is cut visibly (`projects_truncated`, `projects_total`);
* the probe does not import d810 and does not start IDA.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import liebert_re.tools.ida as ti
from tests.test_tools_ida import IdaCase


def _make_package(package: Path, version: str, projects=("default", "eidolon")) -> None:
    (package / "conf").mkdir(parents=True)
    (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    for name in (*projects, "options"):
        (package / "conf" / f"{name}.json").write_text("{}", encoding="utf-8")


class D810StatusTests(IdaCase):
    def setUp(self):
        super().setUp()
        self.base = Path(tempfile.mkdtemp(prefix="liebert-d810-status-"))
        self.addCleanup(lambda: shutil.rmtree(self.base, ignore_errors=True))
        self.python = self.base / "py"
        self.site = self.python / "Lib" / "site-packages"
        self.site.mkdir(parents=True)
        self.user = self.base / "idauser"
        (self.user / "plugins").mkdir(parents=True)
        self.dll = str(self.python / "python310.dll")

    def status(self, dll="default", user_dir=True, registry_error=None):
        value = self.dll if dll == "default" else dll
        env = {k: v for k, v in os.environ.items() if k not in ("IDAUSR", "APPDATA")}
        if user_dir:
            env["IDAUSR"] = str(self.user)

        def query(key, name):
            if registry_error is not None:
                raise registry_error
            return value, 1
        fake = SimpleNamespace(HKEY_CURRENT_USER=object(), OpenKey=lambda root, sub: mock.MagicMock(),
                               QueryValueEx=query)
        with mock.patch.dict(sys.modules, {"winreg": fake}), mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            return json.loads(ti.ida_status())["d810"]

    def copy(self, data, kind):
        return next(c for c in data["copies"] if c["kind"] == kind)

    def test_the_status_carries_a_d810_field(self):
        data = self.status()
        self.assertIn(data["status"], ("FOUND", "NOT_FOUND", "UNKNOWN"))
        self.assertEqual({c["kind"] for c in data["copies"]}, {"pip", "plugins"})

    def test_a_missing_d810_is_a_plain_not_found(self):
        data = self.status()
        self.assertEqual(data["status"], "NOT_FOUND")
        self.assertEqual([c["status"] for c in data["copies"]], ["NOT_FOUND", "NOT_FOUND"])
        self.assertIn("reason", data)
        self.assertNotIn("version", data)

    def test_a_pip_copy_is_reported_with_its_version_and_projects(self):
        _make_package(self.site / "d810", "9.9.8")
        dist = self.site / "d810_ng-9.9.9.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Name: d810-ng\nVersion: 9.9.9\n", encoding="utf-8")
        data = self.status()
        self.assertEqual((data["status"], data["version"]), ("FOUND", "9.9.9"))     # METADATA wins over __init__
        pip = self.copy(data, "pip")
        self.assertEqual(pip["projects"], ["default", "eidolon"])        # options.json is not a project
        self.assertEqual((pip["projects_total"], pip["projects_truncated"]), (2, False))
        self.assertEqual(self.copy(data, "plugins")["status"], "NOT_FOUND")
        self.assertEqual(data["loaded_copy"], "pip")
        self.assertIn("not observed", data["loaded_copy_basis"])

    def test_both_copies_are_reported_and_the_loaded_one_is_unknown(self):
        _make_package(self.site / "d810", "0.6.6")
        _make_package(self.user / "plugins" / "d810-ng" / "src" / "d810", "0.6.6")
        data = self.status()
        self.assertEqual({c["kind"]: c["status"] for c in data["copies"]}, {"pip": "FOUND", "plugins": "FOUND"})
        self.assertEqual(data["loaded_copy"], "UNKNOWN")
        self.assertEqual(data["version"], "0.6.6")

    def test_two_copies_that_disagree_on_version_do_not_claim_one(self):
        _make_package(self.site / "d810", "0.6.6")
        _make_package(self.user / "plugins" / "d810-ng" / "src" / "d810", "0.7.0")
        data = self.status()
        self.assertEqual(data["version"], "UNKNOWN")
        self.assertEqual({c["version"] for c in data["copies"]}, {"0.6.6", "0.7.0"})

    def test_an_unreadable_place_is_unknown_with_a_reason(self):
        for registry_error in (FileNotFoundError(2, "gone"), PermissionError(13, "denied")):
            with self.subTest(error=type(registry_error).__name__):
                data = self.status(registry_error=registry_error)
                pip = self.copy(data, "pip")
                self.assertEqual(pip["status"], "UNKNOWN")
                self.assertIn("reason", pip)
                self.assertEqual(data["status"], "UNKNOWN")      # the other place says NOT_FOUND; one doubt keeps UNKNOWN
        self.assertEqual(self.copy(self.status(dll=""), "pip")["status"], "UNKNOWN")
        self.assertEqual(self.copy(self.status(user_dir=False), "plugins")["status"], "UNKNOWN")

    def test_not_found_and_unknown_are_different_answers(self):
        absent = self.status()
        unreadable = self.status(registry_error=PermissionError(13, "denied"))
        self.assertEqual(absent["status"], "NOT_FOUND")
        self.assertEqual(unreadable["status"], "UNKNOWN")
        self.assertNotEqual(absent["status"], unreadable["status"])

    def test_an_unreadable_place_does_not_hide_a_copy_found_elsewhere(self):
        _make_package(self.user / "plugins" / "d810-ng" / "src" / "d810", "0.6.6")
        data = self.status(registry_error=PermissionError(13, "denied"))
        self.assertEqual(data["status"], "FOUND")
        self.assertEqual(data["loaded_copy"], "UNKNOWN")      # the pip place could not be read

    def test_a_long_project_list_is_cut_and_says_so(self):
        _make_package(self.site / "d810", "1.0", projects=[f"p{i:02d}" for i in range(7)])
        with mock.patch.object(ti, "_D810_PROJECT_LIST_LIMIT", 3):
            data = self.status()
        pip = self.copy(data, "pip")
        self.assertEqual(len(pip["projects"]), 3)
        self.assertIs(pip["projects_truncated"], True)
        self.assertEqual(pip["projects_total"], 7)

    def test_the_probe_does_not_import_d810(self):
        _make_package(self.site / "d810", "1.0")
        sys.modules.pop("d810", None)
        self.status()
        self.assertNotIn("d810", sys.modules)


if __name__ == "__main__":
    unittest.main()
