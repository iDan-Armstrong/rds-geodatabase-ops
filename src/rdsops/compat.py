"""Compatibility: is this engine and PostGIS combination supported by this ArcGIS release?

The support matrix is a dated data file (``data/esri_rds_postgresql.json``) copied from
Esri's documentation, with the source URL for every entry. ``check`` is pure: it takes
version strings and the matrix and returns findings, so it runs the same on a laptop, in
CI, or in a browser.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from importlib import resources

from .findings import Finding, Severity

STALE_AFTER_DAYS = 120


def vtuple(v: str) -> tuple[int, ...]:
    """'17.7' -> (17, 7); '3.5.2' -> (3, 5, 2); ignores suffixes like '3.5.2dev'."""
    out = []
    for part in v.strip().split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        out.append(int(digits))
    if not out:
        raise ValueError(f"not a version: {v!r}")
    return tuple(out)


@dataclass(frozen=True)
class Release:
    enterprise: str
    pro: str
    rds_postgresql: dict[str, str]
    checked: date
    sources: list[str]
    postgis_blocked: list[str] = field(default_factory=list)
    postgis_blocked_from: str | None = None
    postgis_blocked_note: str = ""

    def postgis_is_blocked(self, postgis: str) -> bool:
        pv = vtuple(postgis)
        if any(pv[:3] == vtuple(b)[:3] for b in self.postgis_blocked):
            return True
        return bool(self.postgis_blocked_from) and pv >= vtuple(self.postgis_blocked_from)


def load_matrix(text: str | None = None) -> list[Release]:
    if text is None:
        text = resources.files("rdsops.data").joinpath("esri_rds_postgresql.json").read_text()
    raw = json.loads(text)["releases"]
    return [
        Release(
            enterprise=r["enterprise"],
            pro=r["pro"],
            rds_postgresql=r["rds_postgresql"],
            checked=date.fromisoformat(r["checked"]),
            sources=r["sources"],
            postgis_blocked=r.get("postgis_blocked", []),
            postgis_blocked_from=r.get("postgis_blocked_from"),
            postgis_blocked_note=r.get("postgis_blocked_note", ""),
        )
        for r in raw
    ]


def find_release(matrix: list[Release], arcgis: str) -> Release | None:
    """Accepts an Enterprise version ('12.1') or a Pro version ('pro3.7', 'pro-3.7')."""
    key = arcgis.lower().replace(" ", "")
    if key.startswith("pro"):
        pro = key.removeprefix("pro").lstrip("-")
        return next((r for r in matrix if r.pro == pro), None)
    return next((r for r in matrix if r.enterprise == key), None)


def check(
    engine_version: str,
    arcgis: str,
    postgis_version: str | None = None,
    matrix: list[Release] | None = None,
    today: date | None = None,
) -> list[Finding]:
    matrix = matrix if matrix is not None else load_matrix()
    today = today or date.today()
    rel = find_release(matrix, arcgis)
    if rel is None:
        known = ", ".join(f"{r.enterprise} (Pro {r.pro})" for r in matrix)
        return [
            Finding(
                "CMP000",
                Severity.FAIL,
                f"ArcGIS {arcgis} is not in the support matrix",
                f"Known releases: {known}. Add the release to the data file from "
                "Esri's 'databases in the cloud' page.",
            )
        ]

    label = f"ArcGIS Enterprise {rel.enterprise} / Pro {rel.pro}"
    out: list[Finding] = []
    ev = vtuple(engine_version)
    major = str(ev[0])
    certified = rel.rds_postgresql.get(major)

    if certified is None:
        supported = ", ".join(sorted(rel.rds_postgresql.values(), key=vtuple))
        out.append(
            Finding(
                "CMP001",
                Severity.FAIL,
                f"PostgreSQL {major} is not supported on RDS by {label}",
                f"Supported RDS versions: {supported}.",
                {"engine_version": engine_version, "arcgis": rel.enterprise},
            )
        )
    else:
        out.append(Finding("CMP001", Severity.OK, f"PostgreSQL {major} is supported by {label}"))
        cv = vtuple(certified)
        if ev < cv:
            out.append(
                Finding(
                    "CMP002",
                    Severity.FAIL,
                    f"RDS {engine_version} is below the certified minimum {certified}",
                    f"Apply the minor upgrade to {certified} or later before relying on this "
                    "combination.",
                    {"certified_minimum": certified},
                )
            )
        elif ev[:2] == cv[:2]:
            out.append(
                Finding("CMP002", Severity.OK, f"RDS {engine_version} is the certified minor")
            )
        else:
            out.append(
                Finding(
                    "CMP002",
                    Severity.INFO,
                    f"RDS {engine_version} is supported but not certified (certified: {certified})",
                    "Esri supports later minors of a listed major without certifying them. Test in "
                    "a lower environment first.",
                    {"certified_minimum": certified},
                )
            )

    if postgis_version is None:
        out.append(
            Finding(
                "CMP003",
                Severity.INFO,
                "PostGIS version not checked",
                "Pass --postgis, or connect to the database so it can be read.",
            )
        )
    elif rel.postgis_is_blocked(postgis_version):
        out.append(
            Finding(
                "CMP003",
                Severity.FAIL,
                f"PostGIS {postgis_version} is not supported by {label}",
                rel.postgis_blocked_note or "Esri lists this PostGIS version as unsupported.",
                {"postgis": postgis_version},
            )
        )
    else:
        out.append(
            Finding("CMP003", Severity.OK, f"PostGIS {postgis_version} is not on the blocked list")
        )

    age = (today - rel.checked).days
    out.append(
        Finding(
            "CMP004",
            Severity.WARN if age > STALE_AFTER_DAYS else Severity.OK,
            f"Support data for {rel.enterprise} checked {rel.checked.isoformat()} ({age} days ago)",
            (
                "Esri updates these pages. Re-check the sources and update the data file: "
                + " ".join(rel.sources)
            )
            if age > STALE_AFTER_DAYS
            else "",
            {"sources": rel.sources},
        )
    )
    return out
