from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="PDF Receipt Analyzer",
    description="Сервис анализа PDF-чеков и выявления признаков подделки",
    version="1.0.0",
)

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}
