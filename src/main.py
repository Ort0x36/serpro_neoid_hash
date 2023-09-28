from typing import Dict, List, Optional, Union
from api import *
from io import BytesIO

from pyhanko.sign import signers, ExternalSigner
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from asn1crypto import pem

import asyncio
import base64

# # OID (Object Indentifier)
hash_algorithm: Dict[str, str] = {
    'sha256': '2.16.840.1.101.3.4.2.1', 
    'sha512': '2.16.840.1.101.3.4.2.3'
}

async def get_raw_signature(
    base_64_hash: str, 
    access_token: str, 
    hash_algorithm: Optional[str] = hash_algorithm['sha256'], 
    alias: Optional[str] = 'testing',
    hash_id: Optional[int] = 1
) -> Union[bytes, Dict[str, str]]:
    """
    Signs a base64-encoded hash using the specified hash algorithm
    and access token via an HTTP POST request.

    :param str base_64_hash: The base64-encoded hash to be signed.
    :param str access_token: The access token used for authorization.
    :param str hash_algorithm: (Optional) 
        The hash algorithm to use for signing. Defaults to 'sha256'.
    :param str alias: (Optional) An alias for the hash signature. 
        Defaults to 'testing'.

    :return: The raw signature bytes (PKCS7).
    :rtype: bytes

    This function sends an HTTP POST request to a remote endpoint
    to sign the provided hash with the specified algorithm and access token.
    It expects a JSON response with signature information, and if successful, 
    it extracts and returns the raw signature bytes.

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
        
    if (resp.status_code == 200 and len(resp.json()) > 0 and 
        'signatures' in resp.json()):
        for data in resp.json()['signatures']:
            return data['raw_signature'].encode()
    else:
        return {
            'error': resp.json()['code'],
            'errorMsg': resp.json()['msg']
        }
    
async def main(pdf_to_sign: str, pdf_out_name: str) -> None:
    """
    Sign a PDF document using a remote signing service.

    :param str pdf_to_sign: The filename of the PDF document to sign.
    :param str pdf_out_name: The filename for the signed PDF output.

    :return: None

    This function reads a PDF document, prepares it for signature,
    sends a request to a SERPRO -> NEOID signature service 
    to obtain a raw signature of the sent hash,
    and then applies/mounts the hash signature to the document.
    The resulting signed PDF is saved to the specified output file.

    """
    with open(file=pdf_to_sign, mode='rb') as infile:
        buffer_io = infile.read()
        
    input_buf = BytesIO(buffer_io)
    writer = IncrementalPdfFileWriter(input_buf)
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='Signature',
            md_algorithm='sha256',
        ),
        signer=ExternalSigner(
            signing_cert=None, 
            cert_registry=None,
            signature_value=256,
        )
    )

    prep_digest, tbs, output = await pdf_signer.async_digest_doc_for_signing(
        pdf_out=writer, 
        bytes_reserved=8192
    )

    der_bytes = await get_raw_signature(
        base_64_hash=base64.b64encode(prep_digest.document_digest).decode(), 
        access_token='' # # replace to your token received in '/token' endpoint
    )

    if pem.detect(der_bytes):
        _, _, der_bytes = pem.unarmor(der_bytes)
            
    signature_container = der_bytes

    await PdfTBSDocument.async_finish_signing(
        output=output, 
        prepared_digest=prep_digest, 
        signature_cms=signature_container
    )
    
    with open(file=pdf_out_name, mode='wb') as outfile:
        outfile.write(output.getbuffer())    

if __name__ == "__main__":
    asyncio.run(
        main(
            pdf_to_sign='/path/to/your/pdf', # # replace to your pdf
            pdf_out_name='/path/to/your/output_pdf' # # replace to your output file name
        )
    )