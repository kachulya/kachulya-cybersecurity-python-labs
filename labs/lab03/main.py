"""Головний модуль FastAPI-застосунку"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import APP_DESCRIPTION, APP_TITLE, VARIANT_NUMBER
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import PingResponse, StudentRead
from shared import student


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Ініціалізувати таблиці бази даних під час запуску застосунку."""
    initialize_database()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)


@app.get(
    "/ping",
    response_model=PingResponse,
    tags=["System"],
    summary="Перевірка доступності API",
)
def ping() -> dict[str, str]:
    """Перевірити працездатність вебсервісу."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["System"],
    summary="Дані студента з shared/student.py",
)
def get_student() -> dict[str, str | int]:
    """Повернути ПІБ, групу та номер варіанта студента."""
    student_name = getattr(
        student,
        "STUDENT_NAME",
        getattr(student, "student_name", getattr(student, "FULL_NAME", "")),
    )
    group_name = getattr(
        student,
        "GROUP_NAME",
        getattr(student, "group_name", getattr(student, "GROUP", "")),
    )
    variant_number = getattr(
        student,
        "VARIANT_NUMBER",
        getattr(student, "variant_number", getattr(student, "VARIANT", VARIANT_NUMBER)),
    )
    return {
        "student_name": str(student_name),
        "group_name": str(group_name),
        "variant_number": int(variant_number),
    }


app.include_router(categories.router)
app.include_router(records.router)
