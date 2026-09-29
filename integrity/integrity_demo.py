"""Parte IV - Verificacao de integridade com RSA-PSS (demonstracao).

Quatro cenarios, cada um mostrando O QUE MUDOU e QUAL FOI O RESULTADO:

  Caso 0 (sucesso): arquivo, assinatura e chave publica originais.
  Caso A (falha)  : 1 byte do ARQUIVO alterado.
  Caso B (falha)  : 1 byte da ASSINATURA alterado.
  Caso C (falha)  : verificacao com a CHAVE PUBLICA errada.
"""

import argparse
import base64
import hashlib
from pathlib import Path

from rsa_core import (
    RSAError,
    RSAPublicKey,
    export_private_key_file,
    generate_key_pair,
    import_private_key_file,
)
from rsa_pss import sign_and_encode

from .envelope import encode_envelope, verify_document

_LINE = "=" * 68


# --------------------------------------------------------------------------
# Chaves da demo (persistidas para nao gerar 2048 bits a cada execucao)
# --------------------------------------------------------------------------
def _key_directory() -> Path:
    return Path(__file__).resolve().parent / ".demo_keys"


def _load_or_create_key(name: str, directory: Path):
    key_path = directory / name
    try:
        return import_private_key_file(key_path)
    except (OSError, UnicodeError, RSAError, ValueError):
        key = generate_key_pair()
        export_private_key_file(key, key_path)
        return key


def _fingerprint(public_key: RSAPublicKey) -> str:
    """Impressao digital da chave: 16 primeiros hex do SHA3-256 do modulo n."""
    n = public_key.n  # ajuste o nome do atributo se o seu RSAPublicKey usar outro
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return hashlib.sha3_256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------
# Saida
# --------------------------------------------------------------------------
def _case_header(title: str, pause: bool, first: bool = False) -> None:
    if pause and not first:
        input("\nEnter para o proximo caso...")
    print(f"\n{_LINE}\n{title}\n{_LINE}")


def _status(file: bool = False, signature: bool = False, key: bool = False) -> None:
    """Mostra o que foi alterado neste caso e o que continua original."""

    def label(changed: bool) -> str:
        return "ALTERADO  <<<" if changed else "original"

    print(f"  arquivo       : {label(file)}")
    print(f"  assinatura    : {label(signature)}")
    print(f"  chave publica : {label(key)}")


def _wrap(text: str, width: int = 64) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)]


def _print_signature(signature_b64: str) -> None:
    for n, line in enumerate(_wrap(signature_b64), 1):
        print(f"  {n} | {line}")


def _print_signature_diff(before_b64: str, after_b64: str) -> None:
    """Mostra so as linhas da assinatura que mudaram, marcando com ^ o caractere."""
    for n, (a, b) in enumerate(zip(_wrap(before_b64), _wrap(after_b64)), 1):
        if a != b:
            marks = "".join("^" if x != y else " " for x, y in zip(a, b))
            print(f"  linha {n}:")
            print(f"    antes : {a}")
            print(f"    depois: {b}")
            print(f"            {marks}")


def _result(
    actual: bool,
    expected: bool,
    results: list[tuple[str, bool]],
    label: str,
    compared: str,
    cause: str,
) -> None:
    """compared = o que o verificador conferiu; cause = o que a demo alterou."""
    got = "ARQUIVO INTEGRO" if actual else "ASSINATURA INVALIDA"
    ok = actual is expected
    print(f"\n  Verificador : {got}  [{'OK' if ok else 'FALHA'}]")
    print(f"                {compared}")
    print(f"  Causa real  : {cause}")
    results.append((label, ok))


def _flip_one_bit(data: bytes, index: int) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 0x01
    return bytes(changed)


# --------------------------------------------------------------------------
# Demonstracao
# --------------------------------------------------------------------------
def main(pause: bool = True) -> int:
    content = b"Este e o arquivo de exemplo para a demonstracao em aula."
    results: list[tuple[str, bool]] = []

    directory = _key_directory()
    directory.mkdir(parents=True, exist_ok=True)
    author_private = _load_or_create_key("author_private_key.json", directory)
    alternate_private_key = _load_or_create_key("alternate_private_key.json", directory)
    author_public = author_private.get_public_key()
    # Chave alternativa valida para o caso de verificacao com chave incorreta.
    alternate_public_key = alternate_private_key.get_public_key()

    signature_b64 = sign_and_encode(author_private, content)
    signature = base64.b64decode(signature_b64, validate=True)
    signed_file = encode_envelope(content, signature_b64)

    print(f"{_LINE}\nPREPARACAO\n{_LINE}")
    print(f"  arquivo       : {content.decode('utf-8')!r}")
    print(f"  assinatura    : {len(signature)} bytes, assinada com a chave do autor")
    print(f"  chave do autor: {_fingerprint(author_public)}")
    print("\n  assinatura original (Base64, linhas de 64 caracteres):")
    _print_signature(signature_b64)

    original_hash = hashlib.sha3_256(content).hexdigest()
    author_fp = _fingerprint(author_public)

    # ---- Caso 0: sucesso -------------------------------------------------
    _case_header("CASO 0 - SUCESSO: nada foi alterado", pause, first=True)
    _status()
    _result(
        verify_document(signed_file, author_public),
        True,
        results,
        "Caso 0 - original",
        f"a assinatura confere com o arquivo (SHA3-256 {original_hash[:16]}...) "
        f"e com a chave {author_fp}",
        "nenhuma, nada foi alterado",
    )

    # ---- Caso A: 1 byte do arquivo --------------------------------------
    _case_header("CASO A - 1 byte do ARQUIVO alterado", pause)
    _status(file=True)
    index = 0
    altered_content = _flip_one_bit(content, index)
    altered_hash = hashlib.sha3_256(altered_content).hexdigest()
    print(f"\n  antes : {content.decode('utf-8')}")
    print(f"  depois: {altered_content.decode('utf-8')}")
    altered_file = encode_envelope(altered_content, signature_b64)
    _result(
        verify_document(altered_file, author_public),
        False,
        results,
        "Caso A - arquivo",
        f"a assinatura foi feita para o arquivo com SHA3-256 {original_hash[:16]}..., "
        f"mas o arquivo recebido tem {altered_hash[:16]}...",
        f"byte {index} do arquivo: {content[index]:#04x} ({chr(content[index])!r}) "
        f"-> {altered_content[index]:#04x} ({chr(altered_content[index])!r})",
    )

    # ---- Caso B: 1 byte da assinatura -----------------------------------
    _case_header("CASO B - 1 byte da ASSINATURA alterado", pause)
    _status(signature=True)
    index = len(signature) // 2
    altered_signature = _flip_one_bit(signature, index)
    altered_signature_b64 = base64.b64encode(altered_signature).decode("ascii")
    char_pos = next(
        i
        for i, (x, y) in enumerate(zip(signature_b64, altered_signature_b64))
        if x != y
    )
    print()
    _print_signature_diff(signature_b64, altered_signature_b64)
    altered_signature_file = encode_envelope(content, altered_signature_b64)
    _result(
        verify_document(altered_signature_file, author_public),
        False,
        results,
        "Caso B - assinatura",
        f"o arquivo esta intacto (SHA3-256 {original_hash[:16]}...), mas a assinatura "
        "recebida nao e uma assinatura valida dele para a chave do autor",
        f"byte {index} da assinatura: {signature[index]:#04x} -> {altered_signature[index]:#04x} "
        f"(caractere {char_pos + 1} do Base64: {signature_b64[char_pos]!r} -> {altered_signature_b64[char_pos]!r})",
    )

    # ---- Caso C: chave publica errada -----------------------------------
    _case_header("CASO C - CHAVE PUBLICA errada", pause)
    _status(key=True)
    alternate_fp = _fingerprint(alternate_public_key)
    print(f"\n  chave do autor (correta): {author_fp}")
    print(f"  chave usada (errada)    : {alternate_fp}")
    _result(
        verify_document(signed_file, alternate_public_key),
        False,
        results,
        "Caso C - chave",
        f"a assinatura foi feita pela chave {author_fp}, mas a verificacao usou a chave {alternate_fp}",
        f"chave publica trocada: {author_fp} -> {alternate_fp}",
    )

    # ---- Resumo ----------------------------------------------------------
    print(f"\n{_LINE}\nRESUMO\n{_LINE}")
    for label, ok in results:
        print(f"  {'OK   ' if ok else 'FALHA'}  {label}")
    passed = sum(ok for _, ok in results)
    print(f"\n  {passed}/{len(results)} casos com o resultado esperado.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="executa todos os casos sem aguardar Enter",
    )
    raise SystemExit(main(pause=not parser.parse_args().no_pause))
