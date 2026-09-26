"""Serialização e deserialização de chaves RSA em formato JSON conforme convenções."""

import json
import math
from pathlib import Path
from typing import Any, Union
from rsa_core.exceptions import InvalidHexError, SerializationError
from rsa_core.keys import RSAPrivateKey, RSAPublicKey

_HEX_DIGITS = set("0123456789abcdef")


def int_to_hex(val: int, exact_bytes: int | None = None) -> str:
    """
    Converte um inteiro para string hexadecimal em minúsculas, big-endian, sem prefixo 0x.

    - Se exact_bytes for especificado: ocupa exatamente exact_bytes * 2 caracteres,
      com zeros à esquerda se necessário (casos de 'n' e 'd').
    - Se exact_bytes for None: ocupa o menor número possível de bytes (número par de caracteres),
      sem padding supérfluo (casos de 'e', 'p', 'q', 'dp', 'dq', 'qInv').
    """
    if val < 0:
        raise ValueError(f"Não é permitido valor negativo para conversão hexadecimal: {val}")

    if val == 0:
        raw_hex = "00"
    else:
        raw_hex = format(val, "x").lower()
        if len(raw_hex) % 2 != 0:
            raw_hex = "0" + raw_hex

    if exact_bytes is not None:
        target_len = exact_bytes * 2
        if len(raw_hex) > target_len:
            raise SerializationError(
                f"Valor ({val}) excede o tamanho máximo de {exact_bytes} bytes ({target_len} caracteres hex)."
            )
        return raw_hex.zfill(target_len)

    return raw_hex


def hex_to_int(hex_str: str, exact_bytes: int | None = None, field_name: str = "") -> int:
    """
    Converte e valida uma string hexadecimal estrita para inteiro.

    Regras validadas:
    - Deve ser string sem espaços e sem prefixo '0x'.
    - Apenas caracteres hexadecimais em minúsculas [0-9a-f].
    - Número par de dígitos (cada par representa um byte).
    - Se exact_bytes for fornecido, deve ter exatamente exact_bytes * 2 caracteres.
    - Se exact_bytes for None, não deve ter padding supérfluo (não pode iniciar com byte nulo '00' se > 2).
    """
    if not isinstance(hex_str, str):
        raise InvalidHexError(f"Campo '{field_name}' deve ser uma string, recebido {type(hex_str).__name__}")

    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        raise InvalidHexError(f"Campo '{field_name}' não deve conter prefixo '0x'")

    if any(c.isspace() for c in hex_str):
        raise InvalidHexError(f"Campo '{field_name}' não deve conter espaços")

    if len(hex_str) % 2 != 0:
        raise InvalidHexError(
            f"Campo '{field_name}' tem comprimento ímpar ({len(hex_str)} dígitos). Esperado número par de dígitos."
        )

    if not all(c in _HEX_DIGITS for c in hex_str):
        raise InvalidHexError(
            f"Campo '{field_name}' contém caracteres inválidos. Deve conter apenas hexadecimais em minúsculas."
        )

    if exact_bytes is not None:
        expected_len = exact_bytes * 2
        if len(hex_str) != expected_len:
            raise InvalidHexError(
                f"Campo '{field_name}' deve ocupar exatamente {exact_bytes} bytes ({expected_len} dígitos hex), "
                f"mas possui {len(hex_str)} dígitos."
            )
    else:
        if hex_str.startswith("00") and len(hex_str) > 2:
            raise InvalidHexError(
                f"Campo '{field_name}' possui padding de zeros à esquerda desnecessário."
            )

    return int(hex_str, 16)


def export_public_key(key: RSAPublicKey) -> str:
    """
    Serializa uma RSAPublicKey em string JSON codificada em conformidade com o README.md.
    """
    k = math.ceil(key.modulus_bits / 8)
    data = {
        "algorithm": "RSA",
        "modulus_bits": key.modulus_bits,
        "n": int_to_hex(key.n, exact_bytes=k),
        "e": int_to_hex(key.e),
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def export_public_key_file(key: RSAPublicKey, filepath: Union[str, Path]) -> None:
    """
    Salva uma RSAPublicKey em arquivo JSON UTF-8.
    """
    path = Path(filepath)
    path.write_text(export_public_key(key), encoding="utf-8")


def export_private_key(key: RSAPrivateKey) -> str:
    """
    Serializa uma RSAPrivateKey em string JSON codificada em conformidade com o README.md.
    """
    k = math.ceil(key.modulus_bits / 8)
    data = {
        "algorithm": "RSA",
        "modulus_bits": key.modulus_bits,
        "n": int_to_hex(key.n, exact_bytes=k),
        "e": int_to_hex(key.e),
        "d": int_to_hex(key.d, exact_bytes=k),
        "p": int_to_hex(key.p),
        "q": int_to_hex(key.q),
        "dp": int_to_hex(key.dp),
        "dq": int_to_hex(key.dq),
        "qInv": int_to_hex(key.qInv),
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def export_private_key_file(key: RSAPrivateKey, filepath: Union[str, Path]) -> None:
    """
    Salva uma RSAPrivateKey em arquivo JSON UTF-8.
    """
    path = Path(filepath)
    path.write_text(export_private_key(key), encoding="utf-8")


def _parse_json_dict(data: Union[str, dict[str, Any]]) -> dict[str, Any]:
    """Valida e extrai um dicionário de uma string JSON ou dicionário de entrada."""
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise SerializationError(f"Formato JSON inválido: {exc}") from exc
    elif isinstance(data, dict):
        parsed = data
    else:
        raise SerializationError(
            f"Esperado string JSON ou dict, recebido {type(data).__name__}"
        )

    if not isinstance(parsed, dict):
        raise SerializationError("O conteúdo JSON raiz deve ser um objeto/dicionário.")

    return parsed


def import_public_key(data: Union[str, dict[str, Any]]) -> RSAPublicKey:
    """
    Importa uma RSAPublicKey a partir de uma string JSON ou dicionário.
    """
    obj = _parse_json_dict(data)

    required_fields = ["algorithm", "modulus_bits", "n", "e"]
    for field in required_fields:
        if field not in obj:
            raise SerializationError(f"Campo obrigatório ausente na chave pública: '{field}'")

    if obj["algorithm"] != "RSA":
        raise SerializationError(
            f"Algoritmo não suportado: '{obj['algorithm']}'. Esperado 'RSA'."
        )

    modulus_bits = obj["modulus_bits"]
    if not isinstance(modulus_bits, int) or isinstance(modulus_bits, bool):
        raise SerializationError("O campo 'modulus_bits' deve ser um número inteiro sem aspas.")

    k = math.ceil(modulus_bits / 8)
    n = hex_to_int(obj["n"], exact_bytes=k, field_name="n")
    e = hex_to_int(obj["e"], field_name="e")

    return RSAPublicKey(n=n, e=e, modulus_bits=modulus_bits)


def import_public_key_file(filepath: Union[str, Path]) -> RSAPublicKey:
    """
    Carrega uma RSAPublicKey a partir de um arquivo JSON UTF-8.
    """
    path = Path(filepath)
    content = path.read_text(encoding="utf-8")
    return import_public_key(content)


def import_private_key(data: Union[str, dict[str, Any]]) -> RSAPrivateKey:
    """
    Importa uma RSAPrivateKey a partir de uma string JSON ou dicionário e valida sua integridade.
    """
    obj = _parse_json_dict(data)

    required_fields = ["algorithm", "modulus_bits", "n", "e", "d", "p", "q", "dp", "dq", "qInv"]
    for field in required_fields:
        if field not in obj:
            raise SerializationError(f"Campo obrigatório ausente na chave privada: '{field}'")

    if obj["algorithm"] != "RSA":
        raise SerializationError(
            f"Algoritmo não suportado: '{obj['algorithm']}'. Esperado 'RSA'."
        )

    modulus_bits = obj["modulus_bits"]
    if not isinstance(modulus_bits, int) or isinstance(modulus_bits, bool):
        raise SerializationError("O campo 'modulus_bits' deve ser um número inteiro sem aspas.")

    k = math.ceil(modulus_bits / 8)
    n = hex_to_int(obj["n"], exact_bytes=k, field_name="n")
    e = hex_to_int(obj["e"], field_name="e")
    d = hex_to_int(obj["d"], exact_bytes=k, field_name="d")
    p = hex_to_int(obj["p"], field_name="p")
    q = hex_to_int(obj["q"], field_name="q")
    dp = hex_to_int(obj["dp"], field_name="dp")
    dq = hex_to_int(obj["dq"], field_name="dq")
    qInv = hex_to_int(obj["qInv"], field_name="qInv")

    return RSAPrivateKey(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=dp,
        dq=dq,
        qInv=qInv,
        modulus_bits=modulus_bits,
    )


def import_private_key_file(filepath: Union[str, Path]) -> RSAPrivateKey:
    """
    Carrega uma RSAPrivateKey a partir de um arquivo JSON UTF-8.
    """
    path = Path(filepath)
    content = path.read_text(encoding="utf-8")
    return import_private_key(content)
