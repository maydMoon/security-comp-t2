#!/usr/bin/env python3
"""Script de CLI simples para demonstrar os módulos da biblioteca de criptografia.

Uso:
    python cli.py             (modo interativo com menu)
    python cli.py core        (demonstração do rsa_core: Miller-Rabin, chaves e CRT)
    python cli.py oaep        (demonstração do rsa_oaep: cifragem e decifragem)
    python cli.py pss         (demonstração do rsa_pss: assinatura e verificação PSS)
    python cli.py integrity   (demonstração de envelope e verificação de integridade)
    python cli.py all         (executa todas as demonstrações)

Operações com arquivos:
    python cli.py keygen  --save-key privada.json --save-public-key publica.json
    python cli.py encrypt --public-key-file publica.json --input mensagem.txt --output cifrado.bin
    python cli.py decrypt --key-file privada.json --input cifrado.bin --output recuperada.txt
    python cli.py sign    --key-file privada.json --input mensagem.txt --output assinatura.b64
    python cli.py verify  --public-key-file publica.json --input mensagem.txt --signature assinatura.b64
    python cli.py envelope-sign --key-file privada.json --input mensagem.txt --output documento.json
    python cli.py envelope-verify --public-key-file publica.json --input documento.json

Opções de chave:
    --save-key ARQUIVO       salva a chave privada usada na demonstração
    --key-file ARQUIVO       usa uma chave privada JSON existente
"""

import argparse
import base64
import sys
from pathlib import Path

from integrity.envelope import encode_envelope, parse_envelope, verify_document
from rsa_core import (
    RSAPrivateKey,
    export_private_key,
    export_private_key_file,
    export_public_key,
    export_public_key_file,
    generate_key_pair,
    import_private_key,
    import_private_key_file,
    import_public_key,
    import_public_key_file,
    is_prime_miller_rabin,
)
from rsa_core.exceptions import RSAError
from rsa_oaep import DecryptionError, decrypt, encrypt, max_message_length
from rsa_pss.pss import sign, verify
from rsa_pss.signed_document import decode_and_verify, sign_and_encode


DEMO_KEY_PATH = Path(__file__).resolve().parent / "integrity" / ".demo_keys" / "author_private_key.json"
DIVIDER = "-" * 60


def get_or_create_key(
    force_new: bool = False, key_file: Path | None = None
) -> RSAPrivateKey:
    """Carrega uma chave privada indicada, a chave de demonstração ou gera uma nova."""
    if key_file is not None:
        try:
            key = import_private_key_file(key_file)
        except (OSError, ValueError, RSAError) as exc:
            raise ValueError(f"Não foi possível carregar a chave em '{key_file}': {exc}") from exc
        print(f"  [i] Usando a chave privada de '{key_file}'.")
        return key

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


def save_private_key(key: RSAPrivateKey, key_file: Path) -> None:
    """Persiste uma chave privada JSON, criando o diretório de destino se necessário."""
    key_file.parent.mkdir(parents=True, exist_ok=True)
    export_private_key_file(key, key_file)
    print(f"  [i] Chave privada salva em '{key_file}'.")


def save_public_key(key: RSAPrivateKey, key_file: Path) -> None:
    """Persiste a chave pública correspondente à chave privada fornecida."""
    key_file.parent.mkdir(parents=True, exist_ok=True)
    export_public_key_file(key.get_public_key(), key_file)
    print(f"  [i] Chave pública salva em '{key_file}'.")


def read_file(path: Path, description: str) -> bytes:
    """Lê um arquivo de entrada e acrescenta contexto a falhas de E/S."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Não foi possível ler {description} em '{path}': {exc}") from exc


def write_file(path: Path, data: bytes, description: str) -> None:
    """Grava uma saída binária, criando o diretório de destino se necessário."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise ValueError(f"Não foi possível salvar {description} em '{path}': {exc}") from exc


def load_public_key(key_file: Path):
    """Carrega uma chave pública JSON para operações públicas independentes."""
    try:
        return import_public_key_file(key_file)
    except (OSError, ValueError, RSAError) as exc:
        raise ValueError(f"Não foi possível carregar a chave pública em '{key_file}': {exc}") from exc


def command_keygen(private_file: Path, public_file: Path) -> None:
    """Gera e persiste um par de chaves RSA para as operações por arquivo."""
    print("  [i] Gerando novo par de chaves RSA de 2048 bits (Miller-Rabin)...", flush=True)
    key = generate_key_pair(modulus_bits=2048)
    save_private_key(key, private_file)
    save_public_key(key, public_file)


def command_encrypt(public_key, input_file: Path, output_file: Path) -> None:
    """Cifra o conteúdo de um arquivo e persiste o ciphertext binário."""
    plaintext = read_file(input_file, "a mensagem")
    try:
        ciphertext = encrypt(public_key, plaintext)
    except ValueError as exc:
        raise ValueError(f"Não foi possível cifrar a mensagem: {exc}") from exc
    write_file(output_file, ciphertext, "o texto cifrado")
    print(f"Texto cifrado salvo em '{output_file}' ({len(ciphertext)} bytes).")


def command_decrypt(private_key: RSAPrivateKey, input_file: Path, output_file: Path) -> None:
    """Decifra um ciphertext binário e persiste a mensagem recuperada."""
    ciphertext = read_file(input_file, "o texto cifrado")
    try:
        plaintext = decrypt(private_key, ciphertext)
    except DecryptionError as exc:
        raise ValueError(f"Não foi possível decifrar o texto: {exc}") from exc
    write_file(output_file, plaintext, "a mensagem recuperada")
    print(f"Mensagem recuperada salva em '{output_file}' ({len(plaintext)} bytes).")


def command_sign(private_key: RSAPrivateKey, input_file: Path, output_file: Path) -> None:
    """Assina um arquivo e persiste a assinatura como Base64 UTF-8."""
    message = read_file(input_file, "a mensagem")
    signature_b64 = sign_and_encode(private_key, message)
    write_file(output_file, (signature_b64 + "\n").encode("ascii"), "a assinatura")
    print(f"Assinatura Base64 salva em '{output_file}'.")


def command_verify(public_key, input_file: Path, signature_file: Path) -> bool:
    """Verifica uma assinatura Base64 persistida contra o conteúdo de um arquivo."""
    message = read_file(input_file, "a mensagem")
    try:
        signature_b64 = read_file(signature_file, "a assinatura").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"A assinatura em '{signature_file}' não está em Base64 ASCII.") from exc

    valid = decode_and_verify(public_key, message, signature_b64)
    print("ASSINATURA VÁLIDA" if valid else "ASSINATURA INVÁLIDA")
    return valid


def command_envelope_sign(private_key: RSAPrivateKey, input_file: Path, output_file: Path) -> None:
    """Assina uma mensagem e persiste um envelope JSON com conteúdo e assinatura."""
    message = read_file(input_file, "a mensagem")
    envelope = encode_envelope(message, sign_and_encode(private_key, message))
    write_file(output_file, envelope, "o envelope assinado")
    print(f"Envelope assinado salvo em '{output_file}'.")


def command_envelope_verify(public_key, input_file: Path) -> bool:
    """Verifica um envelope JSON persistido, inclusive se ele tiver sido adulterado."""
    envelope = read_file(input_file, "o envelope assinado")
    valid = verify_document(envelope, public_key)
    print("DOCUMENTO ÍNTEGRO" if valid else "DOCUMENTO INVÁLIDO")
    return valid


def format_hex_preview(hex_str: str, max_chars: int = 40) -> str:
    """Encurta hexadecimais longos para exibição limpa."""
    if len(hex_str) <= max_chars:
        return hex_str
    return f"{hex_str[:max_chars//2]}...{hex_str[-max_chars//2:]} ({len(hex_str)//2} bytes)"


# ---------------------------------------------------------------------------
# Demonstrações de cada módulo
# ---------------------------------------------------------------------------

def demo_core(key: RSAPrivateKey | None = None) -> None:
    """Demonstração da Parte I: rsa_core."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_core (Chaves, Miller-Rabin e CRT)")
    print(DIVIDER)

    if key is None:
        print("1. Gerando novo par de chaves RSA de 2048 bits...")
        key = generate_key_pair(modulus_bits=2048)
    else:
        print("1. Usando o par de chaves RSA selecionado...")
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


def demo_oaep(
    message: str = "Segurança Computacional 2026/2 - RSA-OAEP",
    key: RSAPrivateKey | None = None,
) -> None:
    """Demonstração da Parte II: rsa_oaep."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_oaep (Cifragem RSAES-OAEP com SHA3-256 e MGF1)")
    print(DIVIDER)

    key = key or get_or_create_key()
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


def demo_pss(
    message: str = "Documento importante para assinatura digital",
    key: RSAPrivateKey | None = None,
) -> None:
    """Demonstração da Parte III: rsa_pss."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: rsa_pss (Assinatura RSASSA-PSS com SHA3-256 e Salt)")
    print(DIVIDER)

    key = key or get_or_create_key()
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


def demo_integrity(
    filename: str = "contrato.txt",
    content: str = "Conteudo integro do arquivo.",
    key: RSAPrivateKey | None = None,
) -> None:
    """Demonstração da Parte IV: integrity (envelope JSON e verificação)."""
    print(f"\n{DIVIDER}")
    print("MÓDULO: integrity (Envelope JSON e Integridade de Arquivo)")
    print(DIVIDER)

    key = key or get_or_create_key()
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


def demo_all(key: RSAPrivateKey | None = None) -> None:
    """Executa a demonstração de todos os módulos sequencialmente."""
    if key is None:
        # Mantém o comportamento original: a demonstração de core cria seu
        # próprio par e as demais compartilham a chave de demonstração.
        demo_core()
        demo_oaep()
        demo_pss()
        demo_integrity()
    else:
        demo_core(key=key)
        demo_oaep(key=key)
        demo_pss(key=key)
        demo_integrity(key=key)
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
            demo_core()
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
        choices=[
            "core", "oaep", "pss", "integrity", "all",
            "keygen", "encrypt", "decrypt", "sign", "verify",
            "envelope-sign", "envelope-verify",
        ],
        help="Demonstração ou operação de arquivo",
    )
    parser.add_argument(
        "--msg",
        default=None,
        help="Mensagem personalizada para as demonstrações de OAEP e PSS",
    )
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        "--key-file",
        type=Path,
        metavar="ARQUIVO",
        help="Carrega uma chave privada JSON",
    )
    key_group.add_argument(
        "--new-key",
        action="store_true",
        help="Força a geração de um novo par de chaves RSA em vez de usar a chave de demonstração",
    )
    parser.add_argument(
        "--public-key-file",
        type=Path,
        metavar="ARQUIVO",
        help="Carrega uma chave pública JSON para cifrar ou verificar",
    )
    parser.add_argument(
        "--save-key",
        type=Path,
        metavar="ARQUIVO",
        help="Salva a chave privada usada em um arquivo JSON (a chave pública é derivada dela)",
    )
    parser.add_argument(
        "--save-public-key",
        type=Path,
        metavar="ARQUIVO",
        help="Salva a chave pública JSON correspondente à chave gerada",
    )
    parser.add_argument(
        "--input",
        type=Path,
        metavar="ARQUIVO",
        help="Arquivo de entrada: mensagem em encrypt/sign/verify ou ciphertext em decrypt",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="ARQUIVO",
        help="Arquivo de saída: ciphertext, mensagem recuperada ou assinatura",
    )
    parser.add_argument(
        "--signature",
        type=Path,
        metavar="ARQUIVO",
        help="Arquivo de assinatura Base64 para a operação verify",
    )

    args = parser.parse_args()

    if args.modulo is None:
        interactive_menu()
        return

    operations = {
        "keygen", "encrypt", "decrypt", "sign", "verify",
        "envelope-sign", "envelope-verify",
    }
    if args.modulo in operations:
        try:
            if args.modulo == "keygen":
                if args.save_key is None or args.save_public_key is None:
                    parser.error("keygen exige --save-key e --save-public-key.")
                command_keygen(args.save_key, args.save_public_key)
                return

            if args.input is None:
                parser.error(f"{args.modulo} exige --input ARQUIVO.")

            if args.modulo == "encrypt":
                if args.output is None:
                    parser.error("encrypt exige --output ARQUIVO.")
                if args.public_key_file is not None:
                    public_key = load_public_key(args.public_key_file)
                elif args.key_file is not None:
                    public_key = get_or_create_key(key_file=args.key_file).get_public_key()
                else:
                    parser.error("encrypt exige --public-key-file ou --key-file.")
                command_encrypt(public_key, args.input, args.output)
                return

            if args.modulo == "decrypt":
                if args.key_file is None or args.output is None:
                    parser.error("decrypt exige --key-file e --output ARQUIVO.")
                command_decrypt(get_or_create_key(key_file=args.key_file), args.input, args.output)
                return

            if args.modulo == "sign":
                if args.key_file is None or args.output is None:
                    parser.error("sign exige --key-file e --output ARQUIVO.")
                command_sign(get_or_create_key(key_file=args.key_file), args.input, args.output)
                return

            if args.modulo == "envelope-sign":
                if args.key_file is None or args.output is None:
                    parser.error("envelope-sign exige --key-file e --output ARQUIVO.")
                command_envelope_sign(get_or_create_key(key_file=args.key_file), args.input, args.output)
                return

            if args.public_key_file is not None:
                public_key = load_public_key(args.public_key_file)
            elif args.key_file is not None:
                public_key = get_or_create_key(key_file=args.key_file).get_public_key()
            else:
                parser.error(f"{args.modulo} exige --public-key-file ou --key-file.")

            if args.modulo == "envelope-verify":
                command_envelope_verify(public_key, args.input)
                return

            if args.signature is None:
                parser.error("verify exige --signature ARQUIVO.")
            command_verify(public_key, args.input, args.signature)
            return
        except ValueError as exc:
            parser.error(str(exc))

    msg = args.msg or "Segurança Computacional 2026/2 - Demonstracao CLI"

    # Sem uma opção de chave, preserva o comportamento original de `core`, que
    # sempre gera um par novo. Os demais módulos reutilizam a chave de demonstração.
    selected_key: RSAPrivateKey | None = None
    if args.key_file is not None:
        try:
            selected_key = get_or_create_key(key_file=args.key_file)
        except ValueError as exc:
            parser.error(str(exc))
    elif args.new_key:
        selected_key = get_or_create_key(force_new=True)
    elif args.modulo == "core" and args.save_key is not None:
        selected_key = get_or_create_key(force_new=True)
    elif args.modulo in ("oaep", "pss", "integrity") or (
        args.modulo == "all" and args.save_key is not None
    ):
        selected_key = get_or_create_key()

    if selected_key is not None and args.save_key is not None:
        save_private_key(selected_key, args.save_key)

    if args.modulo == "core":
        demo_core(key=selected_key)
    elif args.modulo == "oaep":
        demo_oaep(message=msg, key=selected_key)
    elif args.modulo == "pss":
        demo_pss(message=msg, key=selected_key)
    elif args.modulo == "integrity":
        demo_integrity(content=msg, key=selected_key)
    elif args.modulo == "all":
        demo_all(key=selected_key)


if __name__ == "__main__":
    main()
