"""Version logic against the bundled Esri matrix."""

from datetime import date

import pytest

from rdsops.compat import check, find_release, load_matrix, vtuple
from rdsops.findings import Severity

TODAY = date(2026, 11, 4)


def sev(findings, code):
    return next(f.severity for f in findings if f.code == code)


def test_vtuple():
    assert vtuple("17.7") == (17, 7)
    assert vtuple("3.5.2") == (3, 5, 2)
    assert vtuple("3.6.0dev") == (3, 6, 0)
    with pytest.raises(ValueError):
        vtuple("latest")


def test_matrix_loads_and_every_entry_has_a_source():
    m = load_matrix()
    assert {r.enterprise for r in m} >= {"12.1", "12.0", "11.5"}
    assert all(r.sources and r.checked for r in m)
    assert find_release(m, "pro3.7").enterprise == "12.1"
    assert find_release(m, "Pro-3.5").enterprise == "11.5"


def test_certified_combination_is_clean():
    f = check("17.7", "12.1", "3.5.2", today=TODAY)
    assert all(x.severity == Severity.OK for x in f)


def test_later_minor_is_supported_not_certified():
    assert sev(check("17.9", "12.1", today=TODAY), "CMP002") == Severity.INFO


def test_below_certified_minor_fails():
    assert sev(check("16.4", "12.1", today=TODAY), "CMP002") == Severity.FAIL


def test_unsupported_major():
    f = check("18.1", "12.0", today=TODAY)
    assert sev(f, "CMP001") == Severity.FAIL
    assert "17.5" in next(x for x in f if x.code == "CMP001").detail
    assert sev(check("13.20", "12.1", today=TODAY), "CMP001") == Severity.FAIL


@pytest.mark.parametrize(
    "arcgis,postgis,expected",
    [
        ("12.1", "3.5.3", Severity.FAIL),
        ("12.1", "3.6.0", Severity.FAIL),
        ("12.1", "3.6.1", Severity.OK),  # only the listed versions are blocked in 12.x
        ("12.1", "3.5.2", Severity.OK),
        ("11.5", "3.5.3", Severity.FAIL),
        ("11.5", "3.6.1", Severity.FAIL),  # 11.5 blocks 3.5.3 and everything after
        ("11.5", "3.5.2", Severity.OK),
    ],
)
def test_postgis_issue_5978_rules(arcgis, postgis, expected):
    major = {"12.1": "17.7", "11.5": "16.8"}[arcgis]
    assert sev(check(major, arcgis, postgis, today=TODAY), "CMP003") == expected


def test_unknown_release_and_stale_data():
    assert check("17.7", "10.9.1", today=TODAY)[0].code == "CMP000"
    later = date(2027, 6, 1)
    assert sev(check("17.7", "12.1", today=later), "CMP004") == Severity.WARN
