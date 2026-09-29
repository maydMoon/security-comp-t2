"""Primitivas de conversão de dados da RFC 8017 (Seção 4)."""


def i2osp(x: int, length: int) -> bytes:
    """Converte um inteiro não negativo em octet string big-endian de tamanho fixo."""
    if x < 0:
        raise ValueError("I2OSP: inteiro negativo.")
    if x >= 256 ** length:
        raise ValueError("I2OSP: inteiro grande demais.")
    return x.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    """Converte uma octet string big-endian em inteiro não negativo."""
    return int.from_bytes(octets, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de duas sequências de mesmo tamanho."""
    if len(a) != len(b):
        raise ValueError("xor_bytes: sequências de tamanhos diferentes.")
    return bytes(x ^ y for x, y in zip(a, b))

def require_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"'{name}' deve ser bytes ou bytearray, recebido {type(value).__name__}.")
    return bytes(value)