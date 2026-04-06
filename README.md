# Security Risk Reporter

Ingests security event logs across multiple sites, calculates per-site risk scores and trend direction, and generates color-coded Excel risk dashboards for leadership review.

## Demo

```bash
python main.py
```

Outputs: `reports/risk_dashboard.xlsx`, `reports/risk_scores.png`, `reports/benchmark.json`

## Tests

```bash
python -m pytest tests/
```

Invariant proven: total incident count preserved across transformations, risk scores bounded [0.0, 1.0], no sites dropped.
