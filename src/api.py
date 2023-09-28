import httpx

from typing import Dict, List, Optional, Union

BASE_URL: str = 'https://psc-neoid.estaleiro.serpro.gov.br/psc/v0/oauth/{}'

async def make_post_request(
    endpoint: str, 
    params: Dict[str, str], 
    headers: Optional[Dict[str, str]] = None,
    json: bool = False
) -> Union[Dict[str, str], Dict[str, List[Dict[str, str]]], Dict[None, None]]:
    if headers is None:
        headers = {}
    async with httpx.AsyncClient() as client:
        if json:
            response = await client.post(
                url=BASE_URL.format(endpoint),
                headers=headers,
                json=params
            )
        else:
            response = await client.post(
                url=BASE_URL.format(endpoint),
                headers=headers,
                data=params 
            )
        return response