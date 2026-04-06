"""Invariant tests for security risk reporter."""

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pandas as pd
import pytest
from analyzer import analyze


def make_events(rows):
    return pd.DataFrame(rows, columns=["timestamp", "site_id", "event_type", "severity"])


SAMPLE = [
    ("2026-01-01 08:00", "Site-A", "ACCESS_FAIL", 1),
    ("2026-01-01 09:00", "Site-A", "INTRUSION",   3),
    ("2026-01-02 10:00", "Site-B", "ALARM",        2),
    ("2026-01-03 11:00", "Site-B", "TAILGATING",   1),
    ("2026-01-04 12:00", "Site-B", "INTRUSION",    3),
    ("2026-01-05 08:00", "Site-C", "ACCESS_FAIL",  1),
]


def test_total_count_preserved():
    """Sum of per-site totals must equal total input rows."""
    df = make_events(SAMPLE)
    results = analyze(df)
    assert sum(d["total"] for d in results.values()) == len(df)


def test_risk_scores_bounded():
    """All risk scores must be in [0.0, 1.0]."""
    df = make_events(SAMPLE)
    results = analyze(df)
    for site, data in results.items():
        assert 0.0 <= data["risk_score"] <= 1.0, f"{site} score out of bounds: {data['risk_score']}"


def test_no_sites_dropped():
    """Every site in input must appear in output."""
    df = make_events(SAMPLE)
    input_sites = set(df["site_id"].unique())
    results = analyze(df)
    assert input_sites == set(results.keys())


def test_by_type_counts_sum_to_total():
    """Sum of by_type counts must equal site total for every site."""
    df = make_events(SAMPLE)
    results = analyze(df)
    for site, data in results.items():
        assert sum(data["by_type"].values()) == data["total"], \
            f"{site}: by_type sum {sum(data['by_type'].values())} != total {data['total']}"


def test_trend_valid_values():
    """Trend must be one of: up, down, stable."""
    df = make_events(SAMPLE)
    results = analyze(df)
    for site, data in results.items():
        assert data["trend"] in {"up", "down", "stable"}, \
            f"{site}: invalid trend '{data['trend']}'"


def test_high_intrusion_site_scores_higher():
    """A site with only INTRUSION events should outscore a site with only ACCESS_FAIL."""
    rows = [
        ("2026-01-01 08:00", "HighRisk", "INTRUSION", 3),
        ("2026-01-01 09:00", "HighRisk", "INTRUSION", 3),
        ("2026-01-01 08:00", "LowRisk",  "ACCESS_FAIL", 1),
        ("2026-01-01 09:00", "LowRisk",  "ACCESS_FAIL", 1),
    ]
    df = make_events(rows)
    results = analyze(df)
    assert results["HighRisk"]["risk_score"] > results["LowRisk"]["risk_score"]
