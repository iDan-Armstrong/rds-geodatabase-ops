"""Fleet: every geodatabase instance across Regions and accounts, in one view.

``gather`` lists RDS for PostgreSQL instances in each Region given (each with its own AWS
profile if needed, which is how GovCloud is reached), optionally filtered by a tag.
``evaluate`` is pure: it runs the same inventory posture check and Esri compat check
``rdsops inventory`` and ``rdsops compat`` run, per instance, and adds what only shows at
fleet level: version drift, mixed ArcGIS releases and instances nobody tagged.

Tags read from each instance:
    arcgis-release   the ArcGIS Enterprise release it serves (else --arcgis)
    environment      prod or production makes availability gaps failures
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

from . import compat
from .findings import Finding, Severity, worst
from .inventory import InstanceFacts, facts_from_api, posture_findings

RELEASE_TAG = "arcgis-release"
ENV_TAG = "environment"
PRODUCTION = {"prod", "production"}
# Per-instance findings the fleet summary leaves out: informational by nature.
QUIET = {"CMP003", "CMP004"}


@dataclass
class Member:
    region: str
    facts: InstanceFacts
    arcgis: str | None = None  # from the arcgis-release tag
    production: bool = False

    @property
    def name(self) -> str:
        return f"{self.region}/{self.facts.identifier}"


@dataclass
class FleetSnapshot:
    members: list[Member] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    default_arcgis: str | None = None
    errors: list[str] = field(default_factory=list)


def _tags(db: dict) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in db.get("TagList") or []}


def member_from_api(region: str, db: dict) -> Member:
    tags = _tags(db)
    return Member(
        region=region,
        facts=facts_from_api(db),
        arcgis=tags.get(RELEASE_TAG),
        production=tags.get(ENV_TAG, "").lower() in PRODUCTION,
    )


def gather(clients, tag: tuple[str, str] | None = None, default_arcgis: str | None = None):
    """``clients``: (region, rds client) pairs. One failing Region does not stop the rest."""
    snap = FleetSnapshot(default_arcgis=default_arcgis)
    for region, rds in clients:
        snap.regions.append(region)
        try:
            for page in rds.get_paginator("describe_db_instances").paginate():
                for db in page["DBInstances"]:
                    if db.get("Engine") != "postgres":
                        continue
                    if tag and _tags(db).get(tag[0]) != tag[1]:
                        continue
                    snap.members.append(member_from_api(region, db))
        except Exception as e:  # noqa: BLE001 - access denied in one account, and so on
            snap.errors.append(f"{region}: {e}")
    return snap


def member_findings(m: Member, default_arcgis: str | None, today: date | None = None):
    out = posture_findings(m.facts, production=m.production)
    release = m.arcgis or default_arcgis
    if release:
        out += compat.check(m.facts.engine_version, release, None, today=today)
    return out


def evaluate(s: FleetSnapshot, today: date | None = None) -> list[Finding]:
    out: list[Finding] = []
    counts = {Severity.OK: 0, Severity.INFO: 0, Severity.WARN: 0, Severity.FAIL: 0}
    per: list[Finding] = []
    for m in sorted(s.members, key=lambda x: x.name):
        found = [f for f in member_findings(m, s.default_arcgis, today) if f.code not in QUIET]
        bad = [f for f in found if f.severity >= Severity.WARN]
        sev = worst(found) if bad else Severity.OK
        counts[sev if sev >= Severity.WARN else Severity.OK] += 1
        n_fail = sum(f.severity == Severity.FAIL for f in bad)
        n_warn = len(bad) - n_fail
        per.append(
            Finding(
                "FLT001",
                sev,
                f"{m.name} PostgreSQL {m.facts.engine_version}"
                + (f": {n_fail} FAIL, {n_warn} WARN" if bad else ": clean"),
                "; ".join(
                    f"{f.code} {f.title}" for f in sorted(bad, key=lambda f: -f.severity)[:6]
                ),
                {
                    "region": m.region,
                    "instance": m.facts.identifier,
                    "codes": sorted({f.code for f in bad}),
                    "arcgis": m.arcgis or s.default_arcgis,
                    "production": m.production,
                },
            )
        )

    clean = counts[Severity.OK]
    out.append(
        Finding(
            "FLT000",
            Severity.OK if s.members else Severity.WARN,
            f"{len(s.members)} instance(s) in {len(s.regions)} Region(s): {clean} clean, "
            f"{counts[Severity.WARN]} with warnings, {counts[Severity.FAIL]} failing"
            if s.members
            else "No geodatabase instances found",
            "" if s.members else "Check the Regions, the profile for each, and the --tag filter.",
        )
    )
    out += per

    # FLT002 version drift within a major, and majors in use
    by_major: dict[int, set[str]] = defaultdict(set)
    for m in s.members:
        by_major[m.facts.engine_major].add(m.facts.engine_version)
    for major, versions in sorted(by_major.items()):
        if len(versions) > 1:
            out.append(
                Finding(
                    "FLT002",
                    Severity.INFO,
                    f"PostgreSQL {major} runs on {len(versions)} minors: "
                    + ", ".join(sorted(versions, key=compat.vtuple)),
                    "Patch to one certified minor so a fix tested on one instance holds on all.",
                    {"major": major, "versions": sorted(versions, key=compat.vtuple)},
                )
            )
    releases = {m.arcgis or s.default_arcgis for m in s.members} - {None}
    if len(releases) > 1:
        out.append(
            Finding(
                "FLT002",
                Severity.INFO,
                f"Instances serve {len(releases)} ArcGIS releases: "
                + ", ".join(sorted(releases, key=compat.vtuple)),
                "Each is checked against its own release.",
            )
        )

    # FLT003 instances nobody tagged with their ArcGIS release
    untagged = [m.name for m in s.members if not m.arcgis]
    if untagged:
        out.append(
            Finding(
                "FLT003",
                Severity.INFO,
                f"{len(untagged)} instance(s) without an {RELEASE_TAG} tag",
                (
                    f"Checked against --arcgis {s.default_arcgis}. "
                    if s.default_arcgis
                    else "No Esri compat check for these; pass --arcgis or tag them. "
                )
                + ", ".join(untagged[:10]),
                {"instances": untagged},
            )
        )

    for e in s.errors:
        out.append(Finding("FLT009", Severity.WARN, "A Region could not be read", e))
    return out
