"""Exceções do esquema RSA-OAEP."""

from rsa_core import RSAError


class DecryptionError(RSAError):
    """Falha genérica de decifragem; a mensagem é fixa para não revelar a causa."""

    def __init__(self) -> None:
        super().__init__("decryption error")


class MessageTooLongError(RSAError, ValueError):
    """Lançada quando a mensagem excede o limite k - 2*hLen - 2 bytes."""
    pass
