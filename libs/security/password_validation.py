import logging

from libs.exceptions import BadRequestError
from microservices.main_app.api.auth.core.security import verify_password

logger=logging.getLogger(__name__)

def ensure_password_matches(old_password:str, hashed_password:str):
    if not verify_password(old_password, hashed_password):
        logger.warning(f"Old password mismatch")
        raise BadRequestError(detail="Old password mismatch")