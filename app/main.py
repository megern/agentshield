from .access import AccessControl
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from .core import ScanRequest, ComparisonRequest, analyze, compare

app = FastAPI(title="AgentShield", version="0.4.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index():
    return Path(__file__).with_name("index.html").read_text()


@app.post("/analyze")
def run(request: ScanRequest):
    return analyze(request)


from .guard import InputGuard

app.add_middleware(InputGuard)


app.mount(
    "/assets", StaticFiles(directory=Path(__file__).with_name("static")), name="assets"
)


@app.get("/guide", response_class=PlainTextResponse)
def user_guide():
    return Path(__file__).with_name("USER_GUIDE.md").read_text()


@app.post("/compare")
def compare_configurations(request: ComparisonRequest):
    return compare(request)


from .trace import TraceRequest, audit_trace


@app.post("/trace/audit")
def audit_execution_trace(request: TraceRequest):
    return audit_trace(request)


app.add_middleware(AccessControl)
