"""Security Risk Reporter — entry point.

Usage:
    python main.py [--n-events N]   # default 800
"""

import argparse
import pathlib
import random
import time
from datetime import datetime, timedelta

import pandas as pd

from analyzer import analyze
from reporter import write_excel, write_chart, write_benchmark

REPORTS = pathlib.Path("reports")
SITES = ["Site-A", "Site-B", "Site-C", "Site-D", "Site-E"]
EVENT_TYPES = ["ACCESS_FAIL", "INTRUSION", "TAILGATING", "ALARM"]
SEVERITIES = [1, 2, 3]


def generate_events(n: int, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    base = datetime(2026, 1, 1)
    rows = []
    for _ in range(n):
        rows.append({
            "timestamp": base + timedelta(days=rng.uniform(0, 89),
                                          hours=rng.uniform(0, 23)),
            "site_id": rng.choice(SITES),
            "event_type": rng.choice(EVENT_TYPES),
            "severity": rng.choice(SEVERITIES),
        })
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
    return df


def run(n_events: int = 800) -> dict:
    REPORTS.mkdir(exist_ok=True)

    t0 = time.perf_counter()
    df = generate_events(n_events)
    t_gen = time.perf_counter() - t0

    t1 = time.perf_counter()
    results = analyze(df)
    t_analyze = time.perf_counter() - t1

    t2 = time.perf_counter()
    write_excel(results, df, REPORTS / "risk_dashboard.xlsx")
    write_chart(results, REPORTS / "risk_scores.png")
    t_report = time.perf_counter() - t2

    total = time.perf_counter() - t0

    bench = {
        "n_events": n_events,
        "n_sites": len(results),
        "generate_ms": round(t_gen * 1000, 2),
        "analyze_ms": round(t_analyze * 1000, 2),
        "report_ms": round(t_report * 1000, 2),
        "total_ms": round(total * 1000, 2),
        "sites": {
            site: {"risk_score": data["risk_score"], "total": data["total"], "trend": data["trend"]}
            for site, data in sorted(results.items())
        },
    }
    write_benchmark(bench, REPORTS / "benchmark.json")

    print(f"Events processed : {n_events}")
    print(f"Sites analyzed   : {len(results)}")
    print(f"Generate         : {bench['generate_ms']} ms")
    print(f"Analyze          : {bench['analyze_ms']} ms")
    print(f"Report           : {bench['report_ms']} ms")
    print(f"Total            : {bench['total_ms']} ms")
    print("\nPer-site results:")
    for site, data in sorted(results.items()):
        trend_arrow = {"up": "↑", "down": "↓", "stable": "→"}[data["trend"]]
        print(f"  {site}: score={data['risk_score']:.4f}  incidents={data['total']}  trend={trend_arrow}")
    print(f"\nArtifacts → reports/risk_dashboard.xlsx, reports/risk_scores.png, reports/benchmark.json")
    return bench


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-events", type=int, default=800)
    args = parser.parse_args()
    run(args.n_events)
