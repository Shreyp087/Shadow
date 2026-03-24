from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class APIResponse(BaseModel, Generic[T]):
    data: T | None = None
    error: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

