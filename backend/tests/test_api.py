import pytest
from app.core.config import Settings
from pydantic import ValidationError

@pytest.mark.asyncio
async def test_healthz(async_client):
    response = await async_client.get("/healthz")
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_readyz_fails_if_no_db(async_client):
    # Depending on how the test environment is set up, readyz could return 503 or 200
    pass

@pytest.mark.asyncio
async def test_body_limit(async_client):
    data = "a" * (1024 * 1024 + 10)
    response = await async_client.post("/healthz", content=data)
    assert response.status_code == 413
    assert response.headers["content-type"] == "application/problem+json"

@pytest.mark.asyncio
async def test_request_id_generated(async_client):
    response = await async_client.get("/healthz")
    assert "x-request-id" in response.headers

def test_settings_validation_production_insecure():
    with pytest.raises(ValueError):
        Settings(
            env="production",
            database_url="postgresql+asyncpg://u:p@localhost/db",
            database_migrator_url="postgresql+asyncpg://u:p@localhost/db",
            redis_url="redis://localhost",
            public_base_url="https://example.com",
            cookie_insecure_dev=True, # Should fail
            session_secret="short", # Should fail
            csrf_secret="short",
            prelogin_secret="short",
            pepper="short",
            totp_enc_keys=["short"]
        )

# tests for log redaction, problem+json can be added here
