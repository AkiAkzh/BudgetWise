from pydantic import BaseModel, Field
from typing import Optional, Generic, TypeVar, List
from pydantic.generics import GenericModel
from datetime import datetime

T = TypeVar("T")

class APIBaseResponse(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds") + "Z")


class SuccessResponse(APIBaseResponse, Generic[T]):
    success: bool = Field(default=True)
    message: str
    data: T

class ErrorResponse(APIBaseResponse):
    success: bool = Field(default=False)
    error: str
    detail: Optional[str] = None

class PaginatedResponse(GenericModel, Generic[T]):
    items: List[T]
    total: int

class ResponseExamples:
    BAD_REQUEST = {
        "model": ErrorResponse,
        "description": "Bad Request",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Bad Request",
                    "detail": "The request could not be understood or was missing required parameters."
                }
            }
        }
    }

    UNAUTHORIZED = {
        "model": ErrorResponse,
        "description": "Unauthorized",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Unauthorized",
                    "detail": "Invalid access token"
                }
            }
        }
    }

    FORBIDDEN = {
        "model": ErrorResponse,
        "description": "Forbidden",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Forbidden",
                    "detail": "You don't have permission to access this resource."
                }
            }
        }
    }

    NOT_FOUND = {
        "model": ErrorResponse,
        "description": "Not Found",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Not Found",
                    "detail": "The resource could not be found."
                }
            }
        }
    }

    CONFLICT = {
        "model": ErrorResponse,
        "description": "Conflict",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Conflict",
                    "detail": "There was a conflict with the current state of the resource."
                }
            }
        }
    }

    UNPROCESSABLE_ENTITY = {
        "model": ErrorResponse,
        "description": "Unprocessable Entity",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Unprocessable Entity",
                    "detail": "The request was well-formed but contained invalid data."
                }
            }
        }
    }

    INTERNAL_SERVER_ERROR = {
        "model": ErrorResponse,
        "description": "Internal Server Error",
        "content": {
            "application/json": {
                "example": {
                    "timestamp": "2025-04-22T12:00:00Z",
                    "success": False,
                    "error": "Internal Server Error",
                    "detail": "An unexpected error occurred on the server."
                }
            }
        }
    }