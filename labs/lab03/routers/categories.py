"""Маршрути FastAPI для керування категоріями."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій за зростанням id",
)
def get_categories() -> list[dict]:
    """Отримати всі категорії джерел повідомлень, відсортовані за зростанням id."""
    try:
        return repository.list_categories()
    except repository.RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення категорії",
    responses={
        status.HTTP_409_CONFLICT: {
            "description": "Категорія з такою назвою вже існує",
        },
    },
)
def create_category_route(payload: CategoryCreate) -> dict:
    """Створити нову категорію джерела повідомлень."""
    try:
        return repository.create_category(payload)
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
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення порожньої категорії",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Категорію не знайдено",
        },
        status.HTTP_409_CONFLICT: {
            "description": "Категорія містить пов'язані записи і не може бути видалена",
        },
    },
)
def delete_category_route(
    category_id: Annotated[
        int,
        Path(gt=0, description="Додатний ідентифікатор категорії"),
    ],
) -> Response:
    """Видалити категорію за id, якщо до неї не прив'язано жодного запису."""
    try:
        repository.delete_category(category_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
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
