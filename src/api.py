from typing import List, Dict, Optional, Union
import httpx

BASE_URL = 'https://psc-neoid.estaleiro.serpro.gov.br/psc/v0/oauth/{}'

async def make_post_request(
    endpoint: str,
    params: Dict[str, str],
    headers: Optional[None] = None,
    json: bool = False
) -> Union[Dict[str, str], Dict[str, List[Dict[str, str]]], Dict[None, None]]:
    """
    Make a POST request to the specified API endpoint.
    :param endpoint: The specific endpoint to send the request to.
    :type endpoint: str
    :param params: The parameters to include in the request.
    :type params: Dict[str, str]
    :param headers: Optional headers to include in the request.
         Defaults to an empty dictionary.
    :type headers: Optional[None, Dict[str, str]]
    :param json: Flag indicating whether the request
        body should be in JSON format. Defaults to False.
    :type json: bool
    :return: The response from the API, 
         parsed according to the expected data types.
    :rtype: dict
    """
    if headers is None:
        headers = {}
    with httpx.Client() as request:
        if json:
            resp = request.post(
                url=BASE_URL.format(endpoint),
                headers=headers,
                json=params
            )
        else:
            resp = request.post(
                url=BASE_URL.format(endpoint),
                headers=headers,
                data=params
            )
    return resp
