import asyncio
import logging
import os
import pytest
from datetime import (
    datetime,
    timedelta,
    timezone,
)

try:
    from py.core.providers.auth.r2r_auth import R2RAuthProvider, R2RException
except ImportError:

    class R2RAuthProvider:
        pass

    class R2RException(Exception):
        pass


try:
    from py.core.providers.auth.r2r_auth import (
        R2RAuthProvider,
        R2RException,
        normalize_email,
    )
except ImportError:

    class R2RAuthProvider:
        pass

    class R2RException(Exception):
        pass


class FakeAuthConfig:
    access_token_lifetime_in_minutes = 1
    refresh_token_lifetime_in_days = 1
    admin_email = "admin@example.com"
    admin_password = "adminpass"
    require_email_verification = False


class FakeCryptoProvider:

    def verify_secure_token(self, token):
        return {
            "sub": "test@example.com",
            "token_type": "access",
            "exp": (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp(),
        }

    def generate_secure_token(self, data, expiry):
        return "dummy_token"

    def generate_verification_code(self):
        return "dummy_verification_code"

    def verify_api_key(self, raw_api_key, hashed_key):
        return True

    def get_password_hash(self, password):
        return "hashed_" + password

    def verify_password(self, plain_password, hashed_password):
        return plain_password == hashed_password[len("hashed_") :]

    def generate_api_key(self):
        return ("public_key", "raw_api_key")

    def hash_api_key(self, raw_api_key):
        return "hashed_" + raw_api_key


class FakeTokenHandler:

    async def is_token_blacklisted(self, token: str):
        return False

    async def blacklist_token(self, token: str):
        pass

    async def clean_expired_blacklisted_tokens(self):
        pass


class FakeDatabaseProvider:

    def __init__(self):
        self.token_handler = FakeTokenHandler()


class FakeEmailProvider:

    async def send_verification_email(
        self, to_email, verification_code, dynamic_template_data
    ):
        return None

    async def send_password_reset_email(
        self, to_email, reset_token, dynamic_template_data
    ):
        return None

    async def send_password_changed_email(self, to_email, dynamic_template_data):
        return None


@pytest.mark.asyncio
async def test_decode_token_expired():
    """
    Test that decode_token raises a R2RException when the token is expired.
    The FakeCryptoProvider returns a token payload with an expiry time in the past.
    """
    config = FakeAuthConfig()
    crypto_provider = FakeCryptoProvider()
    database_provider = FakeDatabaseProvider()
    email_provider = FakeEmailProvider()
    auth_provider = R2RAuthProvider(
        config, crypto_provider, database_provider, email_provider
    )
    with pytest.raises(R2RException, match="Token has expired"):
        await auth_provider.decode_token("any_token_string")
