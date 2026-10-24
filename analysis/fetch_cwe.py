"""B1. MITRE CWE 목록 수집 및 정제.

MITRE에서 CWE 뷰(CWE-658/659/660)와 최신 CWE Top 25를 내려받아
data/cwe_*.csv로 정리한다.

실행: python analysis/fetch_cwe.py
"""

import html
import io
import re
import zipfile
from datetime import date
from pathlib import Path

import pandas as pd
import requests

BASE = "https://cwe.mitre.org"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# 뷰 번호 → 출력 파일 이름
VIEWS = {
    658: "cwe_658.csv",  # Weaknesses in Software Written in C
    659: "cwe_659.csv",  # Weaknesses in Software Written in C++
    660: "cwe_660.csv",  # Weaknesses in Software Written in Java
}

# 최신 Top 25: 연도와 MITRE 뷰 번호
TOP25_YEAR = 2025
TOP25_VIEW = 1435
TOP25_PAGE = f"{BASE}/top25/archive/{TOP25_YEAR}/{TOP25_YEAR}_cwe_top25.html"

KEEP_COLUMNS = {
    "CWE-ID": "cwe_id",
    "Name": "name",
    "Weakness Abstraction": "abstraction",
    "Status": "status",
}


def get(url: str) -> requests.Response:
    resp = requests.get(url, timeout=60, headers={"User-Agent": "seminar-team01 research"})
    resp.raise_for_status()
    return resp


def fetch_cwe_version() -> str:
    m = re.search(r"CWE List Version ([0-9.]+)", get(f"{BASE}/data/index.html").text)
    return m.group(1) if m else "unknown"


def fetch_view(view_id: int) -> pd.DataFrame:
    """뷰 CSV(zip)를 내려받아 핵심 열만 남긴다."""
    raw = get(f"{BASE}/data/csv/{view_id}.csv.zip").content
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        # MITRE CSV는 행 끝에 여분의 쉼표가 있어 index_col=False로 읽는다
        df = pd.read_csv(zf.open(name), index_col=False, dtype=str)
    df = df[list(KEEP_COLUMNS)].rename(columns=KEEP_COLUMNS)
    df["cwe_id"] = df["cwe_id"].astype(int)
    df.insert(1, "cwe", "CWE-" + df["cwe_id"].astype(str))
    return df.sort_values("cwe_id").reset_index(drop=True)


def fetch_top25_ranks() -> pd.DataFrame:
    """Top 25 페이지 표에서 순위·점수·KEV 건수·전년 대비 순위 변동을 읽는다."""
    page = get(TOP25_PAGE).text
    table = page[page.index('<table id="Detail"'):]
    table = table[: table.index("</table>")]
    cell = r'\s*<td[^>]*>(.*?)</td>'
    row = re.compile(r"<tr>" + cell * 6 + r"\s*</tr>", re.S)
    rows = []
    for rank, cwe, _name, score, kev, change in row.findall(table):
        change = html.unescape(change).strip()
        rows.append({
            "rank": int(re.sub(r"<[^>]+>", "", rank)),
            "cwe_id": int(re.search(r"CWE-(\d+)", cwe).group(1)),
            "score": float(score),
            "kev_cves": int(kev),
            # 전년 목록에 없던 항목은 MITRE 표에 N/A로 적혀 있다
            "rank_change": "new" if change == "N/A" else change,
        })
    return pd.DataFrame(rows)


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    version = fetch_cwe_version()
    today = date.today().isoformat()
    sources = []

    for view_id, filename in VIEWS.items():
        df = fetch_view(view_id)
        df.to_csv(DATA_DIR / filename, index=False, encoding="utf-8")
        sources.append((filename, f"CWE-{view_id}", len(df), f"{BASE}/data/csv/{view_id}.csv.zip"))
        print(f"{filename}: {len(df)}개")

    members = fetch_view(TOP25_VIEW)
    ranks = fetch_top25_ranks()
    if set(members["cwe_id"]) != set(ranks["cwe_id"]) or len(ranks) != 25:
        raise SystemExit("Top 25 뷰 CSV와 순위 표의 CWE 목록이 다릅니다")
    top25 = ranks.merge(members, on="cwe_id")
    top25 = top25[["rank", "cwe_id", "cwe", "name", "abstraction", "status",
                   "score", "kev_cves", "rank_change"]].sort_values("rank")
    filename = f"cwe_top25_{TOP25_YEAR}.csv"
    top25.to_csv(DATA_DIR / filename, index=False, encoding="utf-8")
    sources.append((filename, f"{TOP25_YEAR} CWE Top 25 (CWE-{TOP25_VIEW})", len(top25), TOP25_PAGE))
    print(f"{filename}: {len(top25)}개")

    meta = pd.DataFrame(sources, columns=["file", "source", "count", "url"])
    meta["cwe_version"] = version
    meta["retrieved"] = today
    meta.to_csv(DATA_DIR / "cwe_sources.csv", index=False, encoding="utf-8")
    print(f"CWE List Version {version}, 수집일 {today}")


if __name__ == "__main__":
    main()
