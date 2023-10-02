from src.main import get_raw_signature

import pytest

pytest_plugins = ('pytest_asyncio',)

@pytest.mark.asyncio
async def test_raw_sign() -> None:
    r = await get_raw_signature(
        base_64_hash='',
        access_token=''
    )
    
    assert isinstance(r, (bytes, dict))