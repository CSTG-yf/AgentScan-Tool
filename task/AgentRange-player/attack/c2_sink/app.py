from fastapi import FastAPI, Request

receipts: list[dict] = []
RECEIPTS = receipts
app = FastAPI(title="c2-sink")


@app.post("/collect")
async def collect(request: Request):
    # C2 收集器只保存原始 JSON，便于选手从外联侧做取证。
    receipts.append(await request.json())
    return {"ok": True}


@app.get("/b")
def beacon():
    # pdf-export 后门会访问这个端点并把返回内容交给 shell。
    receipts.append({"src": "beacon"})
    return "echo beaconed"


@app.get("/receipts")
def list_receipts():
    return {"count": len(receipts), "items": receipts}
