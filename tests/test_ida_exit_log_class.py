"""`liebert_re.tools.ida._classify_exit_log`: what idat's own log says about a non-zero exit.

Fast tier: the logs are made-up text in the forms that were observed on a real IDA 9.4 install (an
intermittent "exit code 4" at database open, and a worker script idat could not locate). Nothing starts IDA.

The rule names only observed forms. Texts that merely sound like a licence problem, a second running
instance or a locked database are NOT classified: no such log has been observed, so they stay UNKNOWN.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import liebert_re.tools.ida as ti

PREAMBLE = (
    "Possible file format: Portable executable for AMD64 (PE)\n"
    "Loading file '<INPUT>' into database...\n"
    "Detected file format: Portable executable for AMD64 (PE)\n"
)
OPEN_FAILED_EMPTY = PREAMBLE + (
    "Database is empty -> OK\n"
    "Database initialization failed with error 4\n"
    "Open database failed with result: 4\n"
)
SCRIPT_NOT_LOCATED = PREAMBLE + "liebert_ida_job.py: could not locate file -> OK\nFlushing buffers, please wait...ok\n"


def test_the_observed_exit_4_log_is_the_empty_database_open_failure():
    got = ti._classify_exit_log(OPEN_FAILED_EMPTY)
    assert got == {"class": "DATABASE_OPEN_FAILED_EMPTY", "error_code": 4,
                   "evidence": ["database_is_empty", "database_initialization_failed", "open_database_failed"]}


def test_the_classification_is_case_insensitive_and_reads_the_code_it_was_given():
    got = ti._classify_exit_log("DATABASE IS EMPTY\r\nDATABASE INITIALIZATION FAILED WITH ERROR 7\r\n")
    assert (got["class"], got["error_code"]) == ("DATABASE_OPEN_FAILED_EMPTY", 7)


def test_an_open_failure_without_the_empty_database_line_does_not_claim_it():
    got = ti._classify_exit_log(PREAMBLE + "Open database failed with result: 2\n")
    assert got == {"class": "DATABASE_OPEN_FAILED", "error_code": 2, "evidence": ["open_database_failed"]}


def test_a_worker_script_idat_could_not_locate_is_its_own_class():
    got = ti._classify_exit_log(SCRIPT_NOT_LOCATED)
    assert got == {"class": "SCRIPT_NOT_LOCATED", "error_code": None, "evidence": ["script_could_not_locate_file"]}


def test_the_empty_database_line_alone_is_not_a_failure_class():
    # "Database is empty -> OK" is printed on a normal first analysis too; only the failure lines classify
    assert ti._classify_exit_log(PREAMBLE + "Database is empty -> OK\nAutoanalysis finished\n")["class"] == "UNKNOWN"


@pytest.mark.parametrize("text", [
    "License check failed: no free seat",                        # sounds like a licence problem; never observed
    "Another instance of IDA is already running on this database",  # sounds like concurrency; never observed
    "The database is locked by another process (id0 busy)",         # sounds like a DB lock; never observed
    "Python exception in plugin\nTraceback (most recent call last):\n",
    "",
    "   \n",
])
def test_unobserved_or_unrelated_text_stays_unknown(text):
    assert ti._classify_exit_log(text) == {"class": "UNKNOWN", "error_code": None, "evidence": []}


@pytest.mark.parametrize("value", [None, b"Database initialization failed with error 4", 4, ["x"]])
def test_a_log_that_is_not_text_is_unknown(value):
    assert ti._classify_exit_log(value)["class"] == "UNKNOWN"


def test_the_evidence_names_patterns_and_never_carries_log_text():
    got = ti._classify_exit_log(OPEN_FAILED_EMPTY.replace("<INPUT>", "C:/Us" + "ers/SomeOne/secret.exe"))
    assert "SomeOne" not in repr(got) and "secret" not in repr(got)


def _cp(code):
    return SimpleNamespace(returncode=code, stdout="", stderr="")


def test_the_idat_verdict_reports_the_class_next_to_the_exit_diagnosis(tmp_path):
    (tmp_path / ti._LOG_NAME).write_text(OPEN_FAILED_EMPTY, encoding="utf-8")
    _data, error, signals = ti._verdict(_cp(4), tmp_path, tmp_path / ti._DB_NAME, expect_database=True)
    assert error == "IDA_EXITED_NONZERO"
    diag = signals["exit_diagnosis"]
    assert diag["class"] == "NONZERO_EXIT_NO_RESULT" and diag["exit_code"] == 4
    assert diag["log_class"]["class"] == "DATABASE_OPEN_FAILED_EMPTY" and diag["log_class"]["error_code"] == 4


def test_the_idat_verdict_with_no_log_says_unknown(tmp_path):
    _data, error, signals = ti._verdict(_cp(4), tmp_path, tmp_path / ti._DB_NAME, expect_database=True)
    assert error == "IDA_EXITED_NONZERO"
    assert signals["log_readable"] is False
    assert signals["exit_diagnosis"]["log_class"]["class"] == "UNKNOWN"


def test_the_idalib_verdict_reports_the_class_too(tmp_path):
    (tmp_path / ti._LOG_NAME).write_text(OPEN_FAILED_EMPTY, encoding="utf-8")
    _env, _first, error, signals = ti._verdict_idalib(_cp(4), tmp_path, creating=False,
                                                      operations=[{"operation": "summary"}])
    assert error == "IDA_EXITED_NONZERO"
    assert signals["exit_diagnosis"]["log_class"]["class"] == "DATABASE_OPEN_FAILED_EMPTY"


def test_a_clean_exit_carries_no_exit_diagnosis(tmp_path):
    (tmp_path / ti._LOG_NAME).write_text(OPEN_FAILED_EMPTY, encoding="utf-8")
    _data, _error, signals = ti._verdict(_cp(0), tmp_path, tmp_path / ti._DB_NAME, expect_database=True)
    assert "exit_diagnosis" not in signals
