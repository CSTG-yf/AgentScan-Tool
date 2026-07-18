import pathlib

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="mock-internet")
pages = pathlib.Path(__file__).parent / "pages"


@app.get("/advisory/{cve}", response_class=HTMLResponse)
def advisory(cve: str):
    # C2-B 使用被投毒页面，其他 CVE 返回干净情报页作为良性背景。
    if cve == "CVE-2026-0001":
        return (pages / "poisoned_cve.html").read_text(encoding="utf-8")
    return f"<html><body>Advisory for {cve}: no known issues.</body></html>"
