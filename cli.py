#!/usr/bin/env python3
"""Script de CLI simples para demonstrar os módulos da biblioteca de criptografia.

Uso:
    python cli.py             (modo interativo com menu)
    python cli.py core        (demonstração do rsa_core: Miller-Rabin, chaves e CRT)
    python cli.py oaep        (demonstração do rsa_oaep: cifragem e decifragem)
    python cli.py pss         (demonstração do rsa_pss: assinatura e verificação PSS)
    python cli.py integrity   (demonstração de envelope e verificação de integridade)
    python cli.py all         (executa todas as demonstrações)
"""

import argparse
import base64
import sys
from pathlib import Path

from integrity.envelope import encode_envelope, parse_envelope, verify_document
from rsa_core import (
    RSAPrivateKey,
    export_private_key,
    export_public_key,
    generate_key_pair,
    import_private_key,
    import_private_key_file,
    import_public_key,
    is_prime_miller_rabin,
)
from rsa_oaep import DecryptionError, decrypt, encrypt, max_message_length
from rsa_pss.pss import sign, verify
from rsa_pss.signed_document import decode_and_verify, sign_and_encode


DEMO_KEY_PATH = Path(__file__).resolve().parent / "integrity" / ".demo_keys" / "author_private_key.json"
DIVIDER = "-" * 60


def get_or_create_key(force_new: bool = False) -> RSAPrivateKey:
    """Carrega uma chave salva ou gera um novo par de 2048 bits."""
    if not force_new and DEMO_KEY_PATH.exists():
        try:
            return import_private_key_file(DEMO_KEY_PATH)
        except Exception:
            pass

    print("  [i] Gerando novo par de chaves RSA de 2048 bits (Miller-Rabin)...", flush=True)
    key = generate_key_pair(modulus_bits=2048)
    DEMO_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEMO_KEY_PATH.write_text(export_private_key(key), encoding="utf-8")
    return key


def format_hex_preview(hex_str: str, max_chars: int = 40) -> str:
    """Encurta hexadecimais longos para exibição limpa."""
    if len(hex_str) <= max_chars:
        return hex_str
    return f"{hex_str[:max_chars//2]}...{hex_str[-max_chars//2:]} ({len(hex_str)//2} bytes)"


# ---------------------------------------------------------------------------
# Demonstrações de cada módulo
# ---------------------------------------------------------------------------

def demo_core(force_new: bool = True) -> None:
    """Demonstração da Parte I: rsa_core."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_core (Chaves, Miller-Rabin e CRT)")
    print(DIVIDER)

    print("1. Gerando novo par de chaves RSA de 2048 bits...")
    key = generate_key_pair(modulus_bits=2048)
    pub = key.get_public_key()

    print("\n2. Parâmetros gerados:")
    print(f"   - Tamanho do módulo n : {key.modulus_bits} bits")
    print(f"   - Expoente público e  : {key.e}")
    print(f"   - Primo p             : {format_hex_preview(format(key.p, 'x'))}")
    print(f"   - Primo q             : {format_hex_preview(format(key.q, 'x'))}")
    print(f"   - Expoente privado d  : {format_hex_preview(format(key.d, 'x'))}")
    print(f"   - Parâmetro CRT dp    : {format_hex_preview(format(key.dp, 'x'))}")
    print(f"   - Parâmetro CRT dq    : {format_hex_preview(format(key.dq, 'x'))}")
    print(f"   - Parâmetro CRT qInv  : {format_hex_preview(format(key.qInv, 'x'))}")

    print("\n3. Verificando teste de primalidade Miller-Rabin:")
    p_prime = is_prime_miller_rabin(key.p, rounds=64)
    q_prime = is_prime_miller_rabin(key.q, rounds=64)
    print(f"   - p é primo? {p_prime}")
    print(f"   - q é primo? {q_prime}")

    print("\n4. Serialização e desserialização JSON:")
    pub_json = export_public_key(pub)
    priv_json = export_private_key(key)
    reloaded_pub = import_public_key(pub_json)
    reloaded_priv = import_private_key(priv_json)
    print(f"   - Chave pública exportada ({len(pub_json)} caracteres): OK")
    print(f"   - Chave privada exportada ({len(priv_json)} caracteres): OK")
    print(f"   - Importação preserva chaves: {reloaded_pub.n == pub.n and reloaded_priv.d == key.d}")
    print("-> rsa_core funcionando perfeitamente.")


def demo_oaep(message: str = "Segurança Computacional 2026/2 - RSA-OAEP") -> None:
    """Demonstração da Parte II: rsa_oaep."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_oaep (Cifragem RSAES-OAEP com SHA3-256 e MGF1)")
    print(DIVIDER)

    key = get_or_create_key()
    pub = key.get_public_key()

    msg_bytes = message.encode("utf-8")
    k = (pub.modulus_bits + 7) // 8
    max_len = max_message_length(k)
    print(f"1. Informações de capacidade:")
    print(f"   - Chave: {pub.modulus_bits} bits ({k} bytes)")
    print(f"   - Tamanho máximo permitido da mensagem: {max_len} bytes")
    print(f"   - Mensagem original ({len(msg_bytes)} bytes): {message!r}")


    print("\n2. Cifrando mensagem com chave pública (encrypt)...")
    ciphertext = encrypt(pub, msg_bytes)
    print(f"   - Texto cifrado gerado ({len(ciphertext)} bytes):")
    print(f"     {format_hex_preview(ciphertext.hex())}")

    print("\n3. Decifrando com chave privada (decrypt com CRT)...")
    decrypted = decrypt(key, ciphertext)
    print(f"   - Texto decifrado: {decrypted.decode('utf-8')!r}")
    print(f"   - Sucesso na recuperação: {decrypted == msg_bytes}")

    print("\n4. Testando detecção de adulteração de ciphertext:")
    tampered = bytearray(ciphertext)
    tampered[10] ^= 0x01
    try:
        decrypt(key, bytes(tampered))
        print("   [!] Erro: falha na detecção de adulteração!")
    except DecryptionError as exc:
        print(f"   - Exceção capturada com sucesso: {exc.__class__.__name__} ({exc})")
    print("-> rsa_oaep funcionando perfeitamente.")


def demo_pss(message: str = "Documento importante para assinatura digital") -> None:
    """Demonstração da Parte III: rsa_pss."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_pss (Assinatura RSASSA-PSS com SHA3-256 e Salt)")
    print(DIVIDER)

    key = get_or_create_key()
    pub = key.get_public_key()
    msg_bytes = message.encode("utf-8")

    print(f"1. Mensagem a ser assinada: {message!r}")

    print("\n2. Gerando duas assinaturas da MESMA mensagem (demonstração do salt):")
    sig1 = sign(key, msg_bytes)
    sig2 = sign(key, msg_bytes)
    print(f"   - Assinatura 1 ({len(sig1)} bytes): {format_hex_preview(sig1.hex())}")
    print(f"   - Assinatura 2 ({len(sig2)} bytes): {format_hex_preview(sig2.hex())}")
    print(f"   - Assinaturas são diferentes devido ao salt? {sig1 != sig2}")

    print("\n3. Verificando assinaturas com a chave pública:")
    v1 = verify(pub, msg_bytes, sig1)
    v2 = verify(pub, msg_bytes, sig2)
    print(f"   - Assinatura 1 válida? {v1}")
    print(f"   - Assinatura 2 válida? {v2}")

    print("\n4. Teste de assinatura e verificação em Base64:")
    sig_b64 = sign_and_encode(key, msg_bytes)
    print(f"   - Assinatura Base64: {sig_b64[:40]}... ({len(sig_b64)} chars)")
    print(f"   - decode_and_verify(pub, msg, b64): {decode_and_verify(pub, msg_bytes, sig_b64)}")

    print("\n5. Teste de rejeição por adulteração de conteúdo:")
    altered_msg = msg_bytes + b" (alterado)"
    print(f"   - Verificação com documento alterado: {verify(pub, altered_msg, sig1)}")
    print("-> rsa_pss funcionando perfeitamente.")


def demo_integrity(filename: str = "contrato.txt", content: str = "Conteudo integro do arquivo.") -> None:
    """Demonstração da Parte IV: integrity (envelope JSON e verificação)."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: integrity (Envelope JSON e Integridade de Arquivo)")
    print(DIVIDER)

    key = get_or_create_key()
    pub = key.get_public_key()
    content_bytes = content.encode("utf-8")

    print(f"1. Arquivo simulado: {filename!r}")
    print(f"   - Conteúdo: {content!r}")

    print("\n2. Criando assinatura PSS e empacotando em envelope JSON:")
    sig_b64 = sign_and_encode(key, content_bytes)
    envelope = encode_envelope(content_bytes, sig_b64)
    print("   - Estrutura do envelope gerado:")
    print("     " + envelope.decode("utf-8").replace("\n", "\n     "))

    print("\n3. Verificando envelope com verify_document:")
    integro = verify_document(envelope, pub)
    print(f"   - Documento íntegro? {integro}")

    print("\n4. Parsing do envelope com parse_envelope:")
    parsed_content, parsed_sig = parse_envelope(envelope)
    print(f"   - Conteúdo recuperado: {parsed_content.decode('utf-8')!r}")
    print(f"   - Assinatura recuperada confere? {parsed_sig == sig_b64}")

    print("\n5. Simulando adulteração de 1 byte no envelope:")
    tampered_envelope = bytearray(envelope)
    # Altera um caractere no meio do documento
    tampered_envelope[tampered_envelope.find(b"Conteudo")] = ord(b"X")
    print(f"   - verify_document com documento adulterado: {verify_document(bytes(tampered_envelope), pub)}")
    print("-> integrity funcionando perfeitamente.")


def demo_all() -> None:
    """Executa a demonstração de todos os módulos sequencialmente."""
    demo_core(force_new=False)
    demo_oaep()
    demo_pss()
    demo_integrity()
    print(f"\n{DIVIDER}")
    print("Todas as demonstrações concluídas com sucesso!")
    print(f"{DIVIDER}\n")


# ---------------------------------------------------------------------------
# Menu Interativo e Ponto de Entrada CLI
# ---------------------------------------------------------------------------

def interactive_menu() -> None:
    """Menu interativo simples via terminal."""
    while True:
        print("\n" + "=" * 60)
        print("   DEMONSTRAÇÃO DA BIBLIOTECA DE CRIPTOGRAFIA (RSA)")
        print("=" * 60)
        print("1. rsa_core   - Geração de Chaves, Miller-Rabin e CRT")
        print("2. rsa_oaep   - Cifragem e Decifragem (RSAES-OAEP)")
        print("3. rsa_pss    - Assinatura e Verificação (RSASSA-PSS)")
        print("4. integrity  - Envelope JSON e Testes de Integridade")
        print("5. todos      - Executar todas as demonstrações")
        print("0. Sair")
        print("-" * 60)

        choice = input("Escolha uma opção (0-5): ").strip()
        if choice == "1":
            demo_core(force_new=True)
        elif choice == "2":
            demo_oaep()
        elif choice == "3":
            demo_pss()
        elif choice == "4":
            demo_integrity()
        elif choice == "5":
            demo_all()
        elif choice in ("0", "q", "quit", "exit"):
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CLI simples para demonstração dos módulos de criptografia RSA.",
        epilog="Execute sem argumentos para abrir o menu interativo.",
    )
    parser.add_argument(
        "modulo",
        nargs="?",
        choices=["core", "oaep", "pss", "integrity", "all"],
        help="Módulo a ser demonstrado (core, oaep, pss, integrity, all)",
    )
    parser.add_argument(
        "--msg",
        default=None,
        help="Mensagem personalizada para as demonstrações de OAEP e PSS",
    )
    parser.add_argument(
        "--new-key",
        action="store_true",
        help="Força a geração de um novo par de chaves RSA em vez de usar a chave de demonstração",
    )

    args = parser.parse_args()

    if args.modulo is None:
        interactive_menu()
        return

    msg = args.msg or "Segurança Computacional 2026/2 - Demonstracao CLI"

    if args.modulo == "core":
        demo_core(force_new=True)
    elif args.modulo == "oaep":
        demo_oaep(message=msg)
    elif args.modulo == "pss":
        demo_pss(message=msg)
    elif args.modulo == "integrity":
        demo_integrity(content=msg)
    elif args.modulo == "all":
        demo_all()


if __name__ == "__main__":
    main()
