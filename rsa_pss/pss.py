"""Esquema de assinatura RSASSA-PSS (RFC 8017, Seção 8.1) e a codificação
EMSA-PSS (Seção 9.1), sobre as chaves do pacote rsa_core.
"""

import hashlib
import hmac
import math
import secrets

from rsa_core import RSAPrivateKey, RSAPublicKey
from rsa_pss.errors import EncodingError, RSAPSSError
from utils.mgf1 import HashFactory, mgf1
from utils.primitives import i2osp, os2ip, require_bytes, xor_bytes

# fixamos/documentamos (README) sLen = hLen.
# Para SHA3-256, hLen = 32.
DEFAULT_SALT_LEN = 32


def _clear_leftmost_bits(data: bytes, em_bits: int, em_len: int) -> bytes:
    """
    Zera os (8*em_len - em_bits) bits mais significativos do primeiro byte.
    """
    n_bits_to_clear = 8 * em_len - em_bits
    if n_bits_to_clear:
        mask = 0xFF >> n_bits_to_clear
        data = bytes([data[0] & mask]) + data[1:]
    return data


def emsa_pss_encode(
    message: bytes,
    em_bits: int,
    hash_factory: HashFactory = hashlib.sha3_256,
    salt_len: int = DEFAULT_SALT_LEN,
    salt: bytes | None = None,
) -> bytes:
    """
    Monta o bloco EM = maskedDB || H || 0xbc (RFC 8017, 9.1.1).

    Params:
    - message: a mensagem M original, em bytes.
    - em_bits: modBits - 1.
    - salt: normalmente None (salt aleatório gerado aqui).
    """
    h_len = hash_factory().digest_size
    m_hash = hash_factory(message).digest()
    em_len = math.ceil(em_bits / 8)

    if em_len < h_len + salt_len + 2:
        raise EncodingError("Módulo pequeno demais para hLen + sLen escolhidos.")

    if salt is None:
        salt = secrets.token_bytes(salt_len)
    elif len(salt) != salt_len:
        raise ValueError(f"O salt deve ter {salt_len} bytes.")

    m_prime = (b"\x00" * 8) + m_hash + salt
    h = hash_factory(m_prime).digest()
    ps = bytes(em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - h_len - 1, hash_factory)
    masked_db = xor_bytes(db, db_mask)
    masked_db = _clear_leftmost_bits(masked_db, em_bits, em_len)


    return masked_db + h + b"\xbc"


def emsa_pss_verify(
    message: bytes,
    em: bytes,
    em_bits: int,
    hash_factory: HashFactory = hashlib.sha3_256,
    salt_len: int = DEFAULT_SALT_LEN,
) -> bool:
    """
    EMSA-PSS-VERIFY (RFC 8017, 9.1.2).

    Recebe a mensagem candidata 'message' e o bloco 'em' e devolve
    True ("consistent") ou False ("inconsistent").
    """
    h_len = hash_factory().digest_size
    m_hash = hash_factory(message).digest()
    em_len = math.ceil(em_bits / 8)

    if em_len < h_len + salt_len + 2 or len(em) != em_len:
        return False
    if em[-1:] != b"\xbc":
        return False

    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : -1]

    n_bits_to_clear = 8 * em_len - em_bits
    if n_bits_to_clear:
        top_mask = (0xFF << (8 - n_bits_to_clear)) & 0xFF
        if masked_db[0] & top_mask:
            return False  # bits que deveriam ser 0, mas não são

    db_mask = mgf1(h, em_len - h_len - 1, hash_factory)
    db = xor_bytes(masked_db, db_mask)
    db = _clear_leftmost_bits(db, em_bits, em_len)

    ps_len = em_len - salt_len - h_len - 2
    if db[:ps_len] != bytes(ps_len) or db[ps_len : ps_len + 1] != b"\x01":
        return False
    salt = db[ps_len + 1 :]

    m_prime = (b"\x00" * 8) + m_hash + salt
    h_prime = hash_factory(m_prime).digest()

    return hmac.compare_digest(h, h_prime)  # a comparação de fato


def rsasp1(priv: RSAPrivateKey, m: int) -> int:
    """
    RSASP1 (RFC 8017, §5.2.1): s = m^d mod n.
    m esta entre 0 e n - 1.
    """
    if not (0 <= m < priv.n):
        raise RSAPSSError("message representative out of range")
    return priv.rsa_dp(m)


def rsavp1(pub: RSAPublicKey, s: int) -> int:
    """
    RSAVP1 (RFC 8017, 5.2.2): m = s^e mod n.
    s está entre 0 e n - 1.
    """
    if not (0 <= s < pub.n):
        raise RSAPSSError("signature representative out of range")
    return pub.rsa_ep(s)


def sign(
    priv: RSAPrivateKey,
    message: bytes,
    hash_factory: HashFactory = hashlib.sha3_256,
    salt_len: int = DEFAULT_SALT_LEN,
    salt: bytes | None = None,
) -> bytes:
    """RSASSA-PSS-SIGN (RFC 8017, 8.1.1)."""
    message = require_bytes(message, "message")
    em_bits = priv.modulus_bits - 1
    em = emsa_pss_encode(message, em_bits, hash_factory, salt_len, salt)
    m = os2ip(em)
    s = rsasp1(priv, m)
    k = math.ceil(priv.modulus_bits / 8)
    return i2osp(s, k)


def verify(
    pub: RSAPublicKey,
    message: bytes,
    signature: bytes,
    hash_factory: HashFactory = hashlib.sha3_256,
    salt_len: int = DEFAULT_SALT_LEN,
) -> bool:
    """RSASSA-PSS-VERIFY (RFC 8017, 8.1.2)."""
    message = require_bytes(message, "message")
    signature = require_bytes(signature, "signature")

    k = math.ceil(pub.modulus_bits / 8)
    if len(signature) != k:
        return False
    s = os2ip(signature)
    try:
        m = rsavp1(pub, s)
    except RSAPSSError:
        return False

    em_bits = pub.modulus_bits - 1
    em_len = math.ceil(em_bits / 8)
    try:
        em = i2osp(m, em_len)
    except ValueError:
        return False
    return emsa_pss_verify(message, em, em_bits, hash_factory, salt_len)