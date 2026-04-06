# Security Risk Reporter

Security event scoring pipeline that processes 800 events across 5 sites over a 90-day window. Produces bounded risk scores, trend analysis, and color-coded Excel dashboards.

## The Problem

Security event pipelines that aggregate across sites can silently drop records or produce unbounded scores during transformation. If the output report has fewer events than the input, or a risk score exceeds [0, 1], downstream decisions are based on wrong data -- and nothing flags it.

## How It Works

Six invariants run after every pipeline execution to guarantee data integrity through the full transformation:

| Invariant | What it proves |
|-----------|---------------|
| Count preservation | Output event count matches input -- no silent drops |
| Score bounds | All risk scores in [0.0, 1.0] |
| Site preservation | Every input site appears in the output |
| Trend consistency | Trend direction matches score deltas |
| No NaN propagation | No missing values in final output |
| Determinism | Same input produces identical output across runs |

## Benchmark

800 events | 5 sites | 90-day window | **106ms total pipeline**

## Run It

```bash
python -m venv .venv && source .venv/bin/activate
pip install pandas matplotlib openpyxl pytest

python main.py             # reports/risk_dashboard.xlsx + risk_scores.png + benchmark.json
pytest tests/              # 6 invariant tests
```

## Stack

Python, pandas, matplotlib, openpyxl
