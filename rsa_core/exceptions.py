"""Exceções para a biblioteca de operações e chaves RSA."""


class RSAError(Exception):
    """Exceção base para todas as falhas e erros do pacote RSA."""
    pass


class InvalidKeyError(RSAError):
    """Lançada quando os parâmetros de uma chave violam propriedades matemáticas ou integridade."""
    pass


class KeyLengthError(RSAError):
    """Lançada quando o tamanho do módulo é inferior ao mínimo exigido (2048 bits) ou inconsistente."""
    pass


class SerializationError(RSAError):
    """Lançada quando ocorre erro de decodificação, campos ausentes ou algoritmos divergentes."""
    pass


class InvalidHexError(SerializationError):
    """Lançada para strings hexadecimais com formato, tamanho ímpar ou padding inválidos."""
    pass
