# data — CWE 기준 목록 (B1)

MITRE CWE에서 받은 기준 목록입니다. 기준 시점은 CWE List Version 4.20, 수집일은 2026-10-17입니다(출처와 개수는 [cwe_sources.csv](cwe_sources.csv)에 있습니다).

| 파일 | 내용 | 항목 수 |
|---|---|---|
| `cwe_658.csv` | CWE-658 Weaknesses in Software Written in C | 103 |
| `cwe_659.csv` | CWE-659 Weaknesses in Software Written in C++ | 97 |
| `cwe_660.csv` | CWE-660 Weaknesses in Software Written in Java | 84 |
| `cwe_top25_2025.csv` | 2025 CWE Top 25 (뷰 CWE-1435) | 25 |
| `cwe_sources.csv` | 파일별 출처 URL, CWE 버전, 수집일 | — |

## 열

- 공통: `cwe_id`(숫자), `cwe`(`CWE-79` 형식), `name`, `abstraction`(Pillar·Class·Base·Variant·Compound), `status`
- Top 25 추가: `rank`, `score`, `kev_cves`(CISA KEV에 오른 CVE 수), `rank_change`(2024년 대비 순위 변동, 2024 목록에 없던 항목은 `new`)

## 다시 받기

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python analysis/fetch_cwe.py
```

macOS·Linux에서는 `.venv/Scripts/python` 대신 `.venv/bin/python`을 씁니다. Top 25 연도나 뷰 번호가 바뀌면 `analysis/fetch_cwe.py` 위쪽의 `TOP25_YEAR`, `TOP25_VIEW`를 고칩니다.
