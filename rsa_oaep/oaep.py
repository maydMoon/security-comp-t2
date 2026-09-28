"""Esquema de cifragem RSAES-OAEP (RFC 8017, Seção 7.1)."""

import hashlib
import hmac
import math
import secrets

from rsa_core.keys import RSAPrivateKey, RSAPublicKey
from rsa_core.math_utils import gcd, mod_inverse
from rsa_oaep.errors import DecryptionError, MessageTooLongError
from rsa_oaep.mgf1 import HashFactory, mgf1
from rsa_oaep.primitives import i2osp, os2ip, xor_bytes


def _require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"'{name}' deve ser bytes ou bytearray, recebido {type(value).__name__}.")
    return bytes(value)


def _block_size(modulus_bits: int) -> int:
    return math.ceil(modulus_bits / 8)


def max_message_length(k: int, hash_factory: HashFactory = hashlib.sha3_256) -> int:
    """Tamanho máximo da mensagem em bytes: k - 2*hLen - 2."""
    return k - 2 * hash_factory().digest_size - 2


def eme_oaep_encode(
    message: bytes,
    k: int,
    label: bytes = b"",
    hash_factory: HashFactory = hashlib.sha3_256,
    seed: bytes | None = None,
) -> bytes:
    """Codifica a mensagem no bloco EM = 0x00 || maskedSeed || maskedDB."""
    message = _require_bytes(message, "message")
    label = _require_bytes(label, "label")
    h_len = hash_factory().digest_size

    max_len = max_message_length(k, hash_factory)
    if len(message) > max_len:
        raise MessageTooLongError(
            f"Mensagem de {len(message)} bytes excede o máximo de {max_len} bytes."
        )

    if seed is None:
        seed = secrets.token_bytes(h_len)
    elif len(seed) != h_len:
        raise ValueError(f"A seed deve ter {h_len} bytes.")

    l_hash = hash_factory(label).digest()
    ps = bytes(k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    masked_db = xor_bytes(db, mgf1(seed, k - h_len - 1, hash_factory))
    masked_seed = xor_bytes(seed, mgf1(masked_db, h_len, hash_factory))
    return b"\x00" + masked_seed + masked_db


def eme_oaep_decode(
    em: bytes,
    k: int,
    label: bytes = b"",
    hash_factory: HashFactory = hashlib.sha3_256,
) -> bytes:
    """Decodifica o bloco EM e devolve a mensagem; qualquer falha gera DecryptionError."""
    em = _require_bytes(em, "em")
    label = _require_bytes(label, "label")
    h_len = hash_factory().digest_size

    if len(em) != k or k < 2 * h_len + 2:
        raise DecryptionError()

    l_hash = hash_factory(label).digest()
    y = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    seed = xor_bytes(masked_seed, mgf1(masked_db, h_len, hash_factory))
    db = xor_bytes(masked_db, mgf1(seed, k - h_len - 1, hash_factory))

    l_hash_ok = int(hmac.compare_digest(db[:h_len], l_hash))

    # A varredura percorre todo o DB sem break: a posição do 0x01 não pode
    # influenciar o tempo de execução (ataque de Manger).
    found = 0
    sep_index = 0
    bad_ps = 0
    for i in range(h_len, len(db)):
        b = db[i]
        is_zero = ((b - 1) >> 8) & 1
        is_one = (((b ^ 1) - 1) >> 8) & 1
        not_found = found ^ 1
        sep_index += i * (not_found & is_one)
        bad_ps |= not_found & (is_zero ^ 1) & (is_one ^ 1)
        found |= is_one

    y_ok = ((y - 1) >> 8) & 1
    good = y_ok & l_hash_ok & found & (bad_ps ^ 1)

    # Um único erro para todas as causas: distinguir Y != 0 de padding
    # inválido abre um oráculo de decifragem (Manger / Bleichenbacher).
    if not good:
        raise DecryptionError()

    return db[sep_index + 1 :]


def _rsa_dp_protected(priv: RSAPrivateKey, c: int) -> int:
    """RSADP com checagem de intervalo, blinding e verificação do resultado."""
    n, e = priv.n, priv.e
    if not 0 <= c < n:
        raise DecryptionError()

    # Blinding: a exponenciação privada opera sobre c * r^e, desacoplando
    # o tempo do CRT do ciphertext escolhido pelo atacante.
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1:
            break
    c_blind = (c * pow(r, e, n)) % n
    m = (priv.rsa_dp(c_blind) * mod_inverse(r, n)) % n

    # Uma falha no CRT (ex.: fault injection) vazaria um fator de n se o
    # resultado incorreto fosse usado adiante.
    if pow(m, e, n) != c:
        raise DecryptionError()
    return m


def encrypt(
    pub: RSAPublicKey,
    message: bytes,
    label: bytes = b"",
    hash_factory: HashFactory = hashlib.sha3_256,
) -> bytes:
    """RSAES-OAEP-ENCRYPT: devolve o ciphertext com exatamente k bytes."""
    if not isinstance(pub, RSAPublicKey):
        raise TypeError(f"Esperado RSAPublicKey, recebido {type(pub).__name__}.")
    message = _require_bytes(message, "message")
    label = _require_bytes(label, "label")

    k = _block_size(pub.modulus_bits)
    em = eme_oaep_encode(message, k, label, hash_factory)
    c = pub.rsa_ep(os2ip(em))
    return i2osp(c, k)


def decrypt(
    priv: RSAPrivateKey,
    ciphertext: bytes,
    label: bytes = b"",
    hash_factory: HashFactory = hashlib.sha3_256,
) -> bytes:
    """RSAES-OAEP-DECRYPT: devolve a mensagem ou lança DecryptionError."""
    if not isinstance(priv, RSAPrivateKey):
        raise TypeError(f"Esperado RSAPrivateKey, recebido {type(priv).__name__}.")
    ciphertext = _require_bytes(ciphertext, "ciphertext")
    label = _require_bytes(label, "label")

    k = _block_size(priv.modulus_bits)
    h_len = hash_factory().digest_size
    if len(ciphertext) != k or k < 2 * h_len + 2:
        raise DecryptionError()

    m = _rsa_dp_protected(priv, os2ip(ciphertext))
    em = i2osp(m, k)
    return eme_oaep_decode(em, k, label, hash_factory)
