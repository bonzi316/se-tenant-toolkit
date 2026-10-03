from zscaler import ZscalerClient
import os
import sys
import logging
from dotenv import load_dotenv

# Define logger early so load_env_file can use it
logger = logging.getLogger("src")

def load_env_file(env_path: str = None) -> None:
    """Loads environment variables from a specific .env file, overriding existing ones."""
    # Clear previously set environment variables to avoid cross-environment pollution
    keys_to_clear = [
        "ZSCALER_CLIENT_ID",
        "ZSCALER_CLIENT_SECRET",
        "ZSCALER_VANITY_DOMAIN",
        "ZSCALER_CLOUD",
        "ZSCALER_CUSTOMER_ID",
        "ENV_NAME",
        "PRIMARY_DOMAIN"
    ]
    for key in keys_to_clear:
        if key in os.environ:
            del os.environ[key]

    if env_path:
        env_path = os.path.abspath(env_path)
        if os.path.exists(env_path):
            logger.info(f"Loading custom environment variables from: {env_path}")
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            logger.error(f"Custom environment file not found: {env_path}")
            sys.exit(1)
    else:
        load_dotenv()


# Load default .env file initially
load_env_file()

logger = logging.getLogger("src")

def get_credentials_from_env_or_prompt() -> dict:
    """Helper to collect and return credentials, prompting interactively if not found."""
    client_id = os.getenv("ZSCALER_CLIENT_ID")
    client_secret = os.getenv("ZSCALER_CLIENT_SECRET")
    vanity_domain = os.getenv("ZSCALER_VANITY_DOMAIN")
    cloud = os.getenv("ZSCALER_CLOUD", "production")
    customer_id = os.getenv("ZSCALER_CUSTOMER_ID")

    print("--- Zscaler OneAPI Credentials Setup ---")
    if not client_id:
        client_id = input("Enter Zscaler Client ID (ZSCALER_CLIENT_ID): ").strip()
    if not client_secret:
        client_secret = input("Enter Zscaler Client Secret (ZSCALER_CLIENT_SECRET): ").strip()
    if not vanity_domain:
        vanity_domain = input("Enter Zscaler Vanity Domain (e.g. vanity.zslogin.net) (ZSCALER_VANITY_DOMAIN): ").strip()
    if not customer_id:
        customer_id = input("Enter ZPA Customer ID (ZSCALER_CUSTOMER_ID): ").strip()

    if not client_id or not client_secret or not vanity_domain or not customer_id:
        print("Error: Missing required configuration parameters.", file=sys.stderr)
        sys.exit(1)

    return {
        "clientId": client_id,
        "clientSecret": client_secret,
        "vanityDomain": vanity_domain,
        "cloud": cloud,
        "customerId": customer_id
    }

def get_zscaler_client(creds: dict = None) -> ZscalerClient:
    """Instantiates and authenticates the Zscaler OneAPI Client."""
    if not creds:
        creds = get_credentials_from_env_or_prompt()
        
    client_config = {
        "clientId": creds["clientId"],
        "clientSecret": creds["clientSecret"],
        "vanityDomain": creds["vanityDomain"],
        "cloud": creds["cloud"],
        "customerId": creds["customerId"]
    }
    
    logger.info("Initializing Zscaler OneAPI Client...")
    try:
        client = ZscalerClient(client_config)
        client.authenticate()
        logger.info("Zscaler Client authenticated successfully.")
        return client
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        raise
