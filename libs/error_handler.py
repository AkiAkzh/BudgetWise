import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from libs.common_models import ErrorResponse
from libs.exceptions import BadRequestError, InternalServerError, UnauthorizedError, NotFoundError, ConflictError, \
    ForbiddenError, UnprocessableEntityError


logger = logging.getLogger(__name__)

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response

        except (
            BadRequestError,
            InternalServerError,
            UnauthorizedError,
            NotFoundError,
            ConflictError,
            ForbiddenError,
            UnprocessableEntityError,
        ) as e:
            logger.warning(f"{e.__class__.__name__}: {e.detail}")
            return JSONResponse(
                status_code=e.status_code,
                content=ErrorResponse(
                    error=e.__class__.__name__,
                    detail=e.detail
                ).dict()
            )
        except Exception as e:
            logger.exception(f"Unexpected error: {str(e)}; cause: {e.__cause__ or e.__context__}")

            return JSONResponse(
                status_code=500,
                content=ErrorResponse(
                    error="InternalServerError",
                    detail="An unexpected error occurred"
                ).dict()
            )