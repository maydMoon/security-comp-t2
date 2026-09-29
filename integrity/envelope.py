"""Codificacao e parsing do envelope JSON de um documento assinado."""

import base64
import binascii
import json
from typing import Any

from rsa_core import RSAPublicKey
from rsa_pss import RSAPSSError
from rsa_pss.signed_document import decode_and_verify

_FORMAT = "RSA-PSS-SHA3-256"


class EnvelopeError(ValueError):
    """Envelope invalido ou malformado."""


def encode_envelope(content: bytes, signature_b64: str) -> bytes:
    envelope = {
        "format": _FORMAT,
        "content": base64.b64encode(content).decode("ascii"),
        "signature": signature_b64,
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def parse_envelope(document: bytes) -> tuple[bytes, str]:
    """Devolve o conteudo em bytes e a assinatura em Base64."""
    if not isinstance(document, bytes):
        raise EnvelopeError("O documento precisa ser bytes.")
    try:
        envelope: Any = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("O documento nao e JSON UTF-8 valido.") from exc
    if not isinstance(envelope, dict) or set(envelope) != {
        "format",
        "content",
        "signature",
    }:
        raise EnvelopeError("Estrutura do envelope invalida.")
    if envelope["format"] != _FORMAT:
        raise EnvelopeError("Formato do envelope nao suportado.")
    if not isinstance(envelope["content"], str) or not isinstance(
        envelope["signature"], str
    ):
        raise EnvelopeError("Conteudo e assinatura devem estar em Base64.")
    try:
        content = base64.b64decode(envelope["content"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise EnvelopeError("Base64 invalido.") from exc
    if base64.b64encode(content).decode("ascii") != envelope["content"]:
        raise EnvelopeError("O conteudo nao usa Base64 canonico.")
    if base64.b64encode(signature).decode("ascii") != envelope["signature"]:
        raise EnvelopeError("A assinatura nao usa Base64 canonico.")
    return content, envelope["signature"]


def verify_document(document: bytes, public_key: RSAPublicKey) -> bool:
    """Verifica o envelope; entradas malformadas ou assinaturas invalidas retornam False."""
    try:
        content, signature_b64 = parse_envelope(document)
        return decode_and_verify(public_key, content, signature_b64)
    except (EnvelopeError, TypeError, ValueError, ArithmeticError, RSAPSSError):
        return False
