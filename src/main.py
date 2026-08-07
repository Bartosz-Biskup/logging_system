from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from api.auth import router as auth_router
from api.user import router as user_router
from api.mfa import router as mfa_router


app = FastAPI()
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(mfa_router)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "ui", html=True), name="ui")