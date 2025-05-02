from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR, HTTP_401_UNAUTHORIZED, \
    HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT, HTTP_422_UNPROCESSABLE_ENTITY


class CustomHTTPException(HTTPException):
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


#400

class BadRequestError(CustomHTTPException):
    def __init__(self, detail: str = "Bad request"):
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)

class UnauthorizedError(CustomHTTPException):
    def __init__(self, detail: str = "Unauthorized access"):
        super().__init__(status_code=HTTP_401_UNAUTHORIZED, detail=detail)

class ForbiddenError(CustomHTTPException):
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status_code=HTTP_403_FORBIDDEN,detail=detail)

class NotFoundError(CustomHTTPException):
    def __init__(self, detail: str = "Not found"):
        super().__init__(status_code=HTTP_404_NOT_FOUND, detail=detail)

class ConflictError(CustomHTTPException):
    def __init__(self, detail: str = "Conflict"):
        super().__init__(status_code=HTTP_409_CONFLICT, detail=detail)

class UnprocessableEntityError(CustomHTTPException):
    def __init__(self, detail: str = "Unprocessable entity"):
        super().__init__(status_code=HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)


#500

class InternalServerError(CustomHTTPException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)
