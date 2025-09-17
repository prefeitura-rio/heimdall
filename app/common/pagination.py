"""
Common pagination models and utilities for Heimdall Admin Service.
Provides consistent pagination across all list endpoints.
"""

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar('T')


class PaginationParams(BaseModel):
    """Common pagination parameters for list endpoints."""

    skip: int = Field(
        default=0,
        ge=0,
        description="Number of items to skip (offset)",
        example=0
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum number of items to return (max 100)",
        example=50
    )


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response model."""

    items: list[T] = Field(
        ...,
        description="List of items for the current page"
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of items available",
        example=150
    )
    skip: int = Field(
        ...,
        ge=0,
        description="Number of items skipped (offset)",
        example=0
    )
    limit: int = Field(
        ...,
        ge=1,
        le=100,
        description="Maximum number of items returned",
        example=50
    )
    has_more: bool = Field(
        ...,
        description="Whether there are more items available",
        example=True
    )

    @classmethod
    def create(
        cls,
        items: list[T],
        total: int,
        skip: int,
        limit: int
    ) -> "PaginatedResponse[T]":
        """Create a paginated response with calculated has_more flag."""
        return cls(
            items=items,
            total=total,
            skip=skip,
            limit=limit,
            has_more=(skip + len(items)) < total
        )
