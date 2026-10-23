"""Pydantic-моделі запитів і відповідей для Web API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import MAX_VALUE, MIN_VALUE

RecordStatus = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Модель для створення нової категорії."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(
        min_length=2,
        max_length=40,
        description="Унікальна назва категорії (джерела повідомлення)",
    )


class CategoryRead(CategoryCreate):
    """Модель для читання категорії з бази даних."""

    id: int = Field(gt=0, description="Унікальний ідентифікатор категорії")


class RecordCreate(BaseModel):
    """Модель для створення нового запису про тривалість опрацювання."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    code: str = Field(
        min_length=3,
        max_length=40,
        description="Унікальний код запису (наприклад, V09-01)",
    )
    title: str = Field(
        min_length=3,
        max_length=120,
        description="Назва або опис вимірювання",
    )
    category_id: int = Field(
        gt=0,
        description="Ідентифікатор категорії джерела повідомлення",
    )
    value: float = Field(
        ge=MIN_VALUE,
        le=MAX_VALUE,
        allow_inf_nan=False,
        description="Тривалість перевірки повідомлення у хвилинах (minutes)",
    )
    status: RecordStatus = Field(
        description="Стан перевірки вимірювання: new, in_progress або done",
    )


class RecordReplace(RecordCreate):
    """Модель для повної заміни змінюваних полів запису (PUT)."""


class RecordRead(RecordCreate):
    """Модель відповіді з даними запису та назвою його категорії."""

    id: int = Field(gt=0, description="Унікальний ідентифікатор запису")
    category_name: str = Field(description="Назва категорії джерела повідомлення")


class SeedData(BaseModel):
    """Модель для перевірки структури початкового файлу seed.json."""

    model_config = ConfigDict(extra="forbid")

    categories: list[CategoryRead] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


class StudentRead(BaseModel):
    """Модель відповіді маршруту /student."""

    student_name: str
    group_name: str
    variant_number: int


class PingResponse(BaseModel):
    """Модель відповіді маршруту /ping."""

    status: str
