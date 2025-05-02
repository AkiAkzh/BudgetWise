from uuid import UUID

from libs.error_handler import logger
from libs.exceptions import ForbiddenError
from microservices.main_app.api.auth.schemas.auth_schema import GetMe


def verify_user(user_id : UUID, current_user : GetMe):
    if current_user.role != "admin" and user_id != current_user.user_id:
        logger.warning(f"Access denied for {current_user.user_id}")
        raise ForbiddenError(detail="Access denied")