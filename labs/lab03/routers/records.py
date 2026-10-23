"""Маршрути FastAPI для керування записами часу опрацювання повідомлень."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, Response, status

from labs.lab03 import repository
from labs.lab03.config import MAX_VALUE, MIN_VALUE
from labs.lab03.schemas import (
    RecordCreate,
    RecordRead,
    RecordReplace,
    RecordStatus,
)

router = APIRouter(prefix="/records", tags=["Records"])


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами та поділом на сторінки",
)
def get_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Фільтр за додатним ідентифікатором категорії"),
    ] = None,
    status_filter: Annotated[
        RecordStatus | None,
        Query(alias="status", description="Фільтр за статусом опрацювання"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=MIN_VALUE,
            le=MAX_VALUE,
            allow_inf_nan=False,
            description="Мінімальна тривалість у хвилинах (value >= min_value)",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Максимальна кількість записів на сторінці"),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Кількість пропущених записів"),
    ] = 0,
) -> list[dict]:
    """Отримати список записів, відсортований за зростанням id."""
    try:
        return repository.list_records(
            category_id=category_id,
            status=status_filter,
            min_value=min_value,
            q=q,
            limit=limit,
            offset=offset,
        )
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів з атомарним збереженням",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Принаймні один елемент посилається на неіснуючу категорію",
        },
        status.HTTP_409_CONFLICT: {
            "description": "Дублікат code у базі або всередині пакета (транзакцію скасовано)",
        },
    },
)
def bulk_create_records_route(
    items: Annotated[
        list[RecordCreate],
        Body(
            min_length=1,
            max_length=100,
            description="Список із 1–100 нових записів для атомарного додавання",
        ),
    ],
) -> list[dict]:
    """Додати пакет записів в одній транзакції (або скасувати весь пакет при помилці)."""
    try:
        return repository.bulk_create_records(items)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримання одного запису за id",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Запис не знайдено",
        },
    },
)
def get_record(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
) -> dict:
    """Отримати один запис разом із назвою категорії за його id."""
    try:
        return repository.get_record_by_id(record_id)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення нового запису",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Вказана категорія не існує",
        },
        status.HTTP_409_CONFLICT: {
            "description": "Запис із таким code уже існує",
        },
    },
)
def create_record_route(payload: RecordCreate) -> dict:
    """Створити новий запис вимірювання часу опрацювання."""
    try:
        return repository.create_record(payload)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна змінюваних полів запису",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Запис або вказана категорія не існує",
        },
        status.HTTP_409_CONFLICT: {
            "description": "Запис із таким code уже існує",
        },
    },
)
def replace_record_route(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
    payload: RecordReplace,
) -> dict:
    """Повністю замінити всі змінювані поля наявного запису (id залишається незмінним)."""
    try:
        return repository.replace_record(record_id, payload)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення запису",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Запис не знайдено",
        },
    },
)
def delete_record_route(
    record_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор запису"),
    ],
) -> Response:
    """Видалити запис за його ідентифікатором."""
    try:
        repository.delete_record(record_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except repository.NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
