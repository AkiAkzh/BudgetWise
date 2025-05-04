import logging
from microservices.main_app.api.auth.core.security import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

def create_token_pair(user_id : str , role : str) -> tuple[str, str]:
    payload = {
        "user_id": user_id,
        "role": role,
    }
    access_token = create_access_token(payload)

    logger.info(f"New access token created for {user_id}")

    refresh_token = create_refresh_token(payload)

    logger.info(f"New refresh token created for {user_id}")
    return access_token, refresh_token