from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.bootstrap import create_default_admin
from app.config import SESSION_SECRET_KEY
from app.database import SessionLocal, init_db
from app.routes import admin, auth, posts, users

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="FastAPI 게시판 예제")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(posts.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    db = SessionLocal()
    try:
        create_default_admin(db)
    finally:
        db.close()
