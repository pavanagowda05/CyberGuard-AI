import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from config import API_TITLE, API_VERSION, API_HOST, API_PORT, BASE_DIR

app = FastAPI(title=API_TITLE, version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(BASE_DIR, "dashboard", "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

import api.routes.phishing  as phishing_route
import api.routes.insider   as insider_route
import api.routes.simulate  as simulate_route
import api.routes.dashboard as dashboard_route
# import api.routes.report    as report_route

app.include_router(phishing_route.router,  prefix="/api", tags=["Phishing"])
app.include_router(insider_route.router,   prefix="/api", tags=["Insider"])
app.include_router(simulate_route.router,  prefix="/api", tags=["Simulate"])
app.include_router(dashboard_route.router, tags=["Dashboard"])
# app.include_router(report_route.router, prefix="/api", tags=["Report"])

# ── WebSocket connection manager ──────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active = []
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
    async def broadcast(self, message: str):
        for ws in self.active[:]:
            try:
                await ws.send_text(message)
            except Exception:
                self.active.remove(ws)

manager = ConnectionManager()

@app.websocket("/ws/live-feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Make manager accessible to routes
app.state.manager = manager

@app.get("/health")
def health_check():
    return {"status": "running", "app": API_TITLE, "version": API_VERSION}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host=API_HOST, port=API_PORT, reload=True)