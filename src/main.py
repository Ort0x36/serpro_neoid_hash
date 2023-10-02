from typing import Dict, List, Optional, Union, IO
from api import *
from io import BytesIO

from pyhanko.sign import signers, ExternalSigner
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from asn1crypto import pem
from httpx import HTTPError

import asyncio
import base64

# # OID (Object Indentifier)
hash_algorithm: Dict[str, str] = {
    'sha256': '2.16.840.1.101.3.4.2.1', 
    'sha512': '2.16.840.1.101.3.4.2.3'
}

def extract_der_bytes(pem_bytes: bytes) -> bytes:
    """
    Extracts DER-encoded bytes from a PEM-encoded byte sequence.

    This function takes a bytes object as input and checks if it is 
    PEM-encoded.
    If the input is PEM-encoded, it unarmors it and 
    returns the DER-encoded bytes.

    :param pem_bytes: A bytes object that may contain PEM-encoded data.
    :type pem_bytes: bytes

    :return: DER-encoded bytes extracted from the PEM-encoded input.
    :rtype: bytes

    :raises ValueError: If the input is not a valid bytes object 
         or does not contain PEM-encoded data.
    """
    if isinstance(pem_bytes, bytes):
        if pem.detect(pem_bytes):
            (_, _, der_bytes) = pem.unarmor(pem_bytes=pem_bytes)
            return der_bytes
    raise ValueError(
        'not a valid bytes object or does not contain PEM-encoded data.'
    )
    
def save_signed_pdf(output: Union[IO, BytesIO], pdf_out_name: str) -> None:
    """
    Saves the signed PDF to a file.

    :param output: The output buffer for the signed PDF.
    :param pdf_out_name: The filename for the signed PDF output.
    """
    with open(file=pdf_out_name, mode='wb') as outfile:
        outfile.write(output.getbuffer())

async def get_raw_signature(
    base_64_hash: str, 
    access_token: str, 
    hash_algorithm: str,
    alias: Optional[str] = 'testing',
    hash_id: Optional[int] = 1
) -> Union[bytes, Dict[str, str]]:
    """
    Signs a base64-encoded hash using the specified hash algorithm
    and access token via an HTTP POST request.

    :param str base_64_hash: The base64-encoded hash to be signed.
    :param str access_token: The access token used for authorization.
    :param str hash_algorithm: The hash algorithm to use for signing.
    :param str alias: (Optional) An alias for the hash signature. 
        Defaults to 'testing'.
    :param int hash_id: (Optional) An id for the hash signature. 
        Defaults to 1.

    :return: The raw signature bytes (PKCS7).
    :rtype: bytes

    This function sends an HTTP POST request to a remote endpoint
    to sign the provided hash with the specified algorithm and access token.
    It expects a JSON response with signature information, and if successful, 
    it extracts and returns the raw signature bytes.
    
    `Reference`: https://neoid.estaleiro.serpro.gov.br/documentacao/
    """
    headers: Dict[str, str] = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    jparams: Dict[str, List[Dict[str, str]]] = {
        "hashes": [
            {
                "id": hash_id,
                "alias": alias,
                "hash": base_64_hash,
                "hash_algorithm": hash_algorithm,
                "signature_format": "CMS"
            }
        ]
    }
    
    resp = await make_post_request(
        endpoint='signature',
        params=jparams,
        headers=headers,
        json=True
    )
    
    j_ret: Dict[str, str] = resp.json()    
    
    if resp.status_code == 200:
        if len(j_ret) > 0 and 'signatures' in j_ret:
            for data in j_ret['signatures']:
                return data['raw_signature'].encode()
    elif resp.status_code == 401:
        return {
            'error': j_ret['code'],
            'errorMsg': j_ret['msg']
        }
    else:
        raise HTTPError(
            'Exception in request -> CODE: {}'.format(
                resp.status_code
            )
        )
        
async def sign_pdf(
    output: Union[IO, BytesIO], 
    prep_digest: bytes, 
    signed_hash: bytes
) -> None:
    """
    Signs a PDF document using the given parameters.

    :param output: The output buffer for the signed PDF.
    :param prep_digest: Prepared digest for signing.
    :param signed_hash: Raw signature bytes (PKCS7).
    """
    await PdfTBSDocument.async_finish_signing(
        output=output, 
        prepared_digest=prep_digest, 
        signature_cms=extract_der_bytes(pem_bytes=signed_hash)
    )
        
async def embed_hash(
    pdf_to_sign: str, pdf_out_name: str, token: str, digest: str = 'sha256'
) -> None:
    """
    Embeds the signed hash into the PDF document.

    :param str pdf_to_sign: The filename of the PDF document to sign.
    :param str pdf_out_name: The filename for the signed PDF output.
    :param str token: The access token received from NeoId api.
    :param str digest: The algorithm used to sign prep_digest.
        default: sha256
        supported: sha256 and sha512

    :return: None

    This function reads a PDF document, prepares it for signature,
    sends a request to a SERPRO -> NEOID signature service 
    to obtain a raw signature of the sent hash,
    and then applies/mounts the hash signature to the document.
    The resulting signed PDF is saved to the specified output file.
    """
    with open(file=pdf_to_sign, mode='rb') as infile:
        buffer_io = infile.read()
        
    oid: str = hash_algorithm.get(digest, None)
    
    input_buf = BytesIO(buffer_io)
    writer = IncrementalPdfFileWriter(input_buf)
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='Signature',
            md_algorithm=digest,
        ),
        signer=ExternalSigner(
            signing_cert=None, 
            cert_registry=None,
            signature_value=256,
        )
    )

    (prep_digest, _, output) = await pdf_signer.async_digest_doc_for_signing(
        pdf_out=writer, 
        bytes_reserved=8192
    )

    signed_hash = await get_raw_signature(
        hash_algorithm=oid,
        base_64_hash=base64.b64encode(prep_digest.document_digest).decode(), 
        access_token=token
    )
    
    if isinstance(signed_hash, dict):
        print((
            'Error: \33[31m{error}\n\33[0mMessage: \33[31m'
            '{errorMsg}\33[0m'.format(**signed_hash)
        ))
        return
    
    await sign_pdf(
        output=output, 
        prep_digest=prep_digest, 
        signed_hash=signed_hash
    )
    
    save_signed_pdf(output=output, pdf_out_name=pdf_out_name)

if __name__ == "__main__":
    asyncio.run(
        embed_hash(
            pdf_to_sign='endpoints.pdf', # # replace with your pdf
            pdf_out_name='end.pdf', # # replace with your output file name,
            token='eyHFfj1' # # Replace with your token received in '/token' endpoint
        )
    )
