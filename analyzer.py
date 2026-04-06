"""Per-site risk scoring and trend analysis for security event logs."""

import pandas as pd

WEIGHTS = {"INTRUSION": 3, "ALARM": 2, "ACCESS_FAIL": 1, "TAILGATING": 1}
MAX_SCORE_PER_EVENT = max(WEIGHTS.values())


def score_site(events: pd.DataFrame) -> dict:
    """Compute risk score and trend for a single site's events."""
    total = len(events)
    if total == 0:
        return {"total": 0, "by_type": {}, "risk_score": 0.0, "trend": "stable"}

    weighted_sum = events["event_type"].map(WEIGHTS).fillna(1).sum()
    # Normalize: weighted sum / (total * max possible weight)
    risk_score = round(min(weighted_sum / (total * MAX_SCORE_PER_EVENT), 1.0), 4)

    by_type = events["event_type"].value_counts().to_dict()

    # Trend: compare last 30 days vs prior 30 days
    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])
    cutoff = events["timestamp"].max() - pd.Timedelta(days=30)
    prior_cutoff = cutoff - pd.Timedelta(days=30)

    recent = len(events[events["timestamp"] >= cutoff])
    prior = len(events[(events["timestamp"] >= prior_cutoff) & (events["timestamp"] < cutoff)])

    if prior == 0:
        trend = "stable"
    elif recent > prior * 1.1:
        trend = "up"
    elif recent < prior * 0.9:
        trend = "down"
    else:
        trend = "stable"

    return {
        "total": total,
        "by_type": by_type,
        "risk_score": risk_score,
        "trend": trend,
    }


def analyze(df: pd.DataFrame) -> dict:
    """Return per-site analysis dict. Preserves all input records."""
    results = {}
    for site_id, group in df.groupby("site_id"):
        results[site_id] = score_site(group)
    return results
