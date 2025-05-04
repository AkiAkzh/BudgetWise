from libs.common_models import ResponseExamples

DEFAULT_RESPONSES = {
    400: ResponseExamples.BAD_REQUEST,
    401: ResponseExamples.UNAUTHORIZED,
    403: ResponseExamples.FORBIDDEN,
    404: ResponseExamples.NOT_FOUND,
    409: ResponseExamples.CONFLICT,
    422: ResponseExamples.UNPROCESSABLE_ENTITY,
    500: ResponseExamples.INTERNAL_SERVER_ERROR,
}
