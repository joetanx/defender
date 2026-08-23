import time, logging, jwt
from os import environ
from microsoft_agents.activity import load_configuration_from_env
from microsoft_agents.authentication.msal import MsalConnectionManager

logger = logging.getLogger(__name__)


agents_sdk_config = load_configuration_from_env(environ)
connection_manager = MsalConnectionManager(**agents_sdk_config)
token_provider = connection_manager.get_connection("SERVICE_CONNECTION")

_token_cache: dict[tuple[str | None, str | None, str | None, tuple[str] | None], str] = {}
REFRESH_BUFFER_SECONDS = int(environ.get("TOKEN_REFRESH_BUFFER_SECONDS", "900"))  # Default to 15 minutes buffer


async def get_token(
    tenant_id: str | None = None,
    agent_id: str | None = None,
    agent_user: str | None = None,
    scopes: list[str] | str | None = None,
) -> str:
    """Retrieve a token, handling caching and refreshing transparently."""
    cache_key = (tenant_id, agent_id, agent_user, tuple(scopes) if scopes else None)
    cached_token = _token_cache.get(cache_key)
    if cached_token:
        # Check if there is a cached token and it's not near expiration
        exp_claim = jwt.decode(cached_token, options={"verify_signature": False}).get("exp")
        if exp_claim - int(time.time()) > REFRESH_BUFFER_SECONDS:
            return cached_token
    # Reach here means no cached token or token near expiration, exchange for new token
    new_token = await token_provider.get_agentic_user_token(
        tenant_id=tenant_id,
        agent_app_instance_id=agent_id,
        agentic_user_id=agent_user,
        scopes=scopes,
    )
    _token_cache[cache_key] = new_token
    return new_token
