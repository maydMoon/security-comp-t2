import base64
import binascii

from rsa_core import RSAPrivateKey, RSAPublicKey
from rsa_pss.pss import sign, verify


def sign_and_encode(priv: RSAPrivateKey, message: bytes, **kwargs) -> str:
    """Assina e devolve a assinatura em Base64 ASCII."""
    signature = sign(priv, message, **kwargs)
    return base64.b64encode(signature).decode("ascii")


def decode_and_verify(
    pub: RSAPublicKey, message: bytes, signature_b64: str, **kwargs
) -> bool:
    """Decodifica e verifica; Base64 malformado resulta em False."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    return verify(pub, message, signature, **kwargs)
