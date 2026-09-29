class RSAPSSError(Exception):
    """Classe base para erros do pacote rsa_pss."""
 
 
class EncodingError(RSAPSSError):
    """
    EMSA-PSS-ENCODE falhou (RFC 8017, 9.1.1, passo 2):
    """