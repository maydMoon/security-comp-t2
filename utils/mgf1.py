"""Função geradora de máscara MGF1 (RFC 8017, Seção B.2.1)."""

import hashlib
from typing import Any, Callable

from utils.primitives import i2osp

HashFactory = Callable[..., Any]


def mgf1(seed: bytes, mask_len: int, hash_factory: HashFactory = hashlib.sha3_256) -> bytes:
    """Gera mask_len bytes concatenando Hash(seed || I2OSP(counter, 4))."""
    h_len = hash_factory().digest_size
    if mask_len < 0:
        raise ValueError("MGF1: tamanho de máscara negativo.")
    if mask_len > (1 << 32) * h_len:
        raise ValueError("MGF1: máscara longa demais.")

    blocks = -(-mask_len // h_len)
    t = b"".join(hash_factory(seed + i2osp(counter, 4)).digest() for counter in range(blocks))
    return t[:mask_len]
