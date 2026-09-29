# Parte V – Análise de segurança

## Por que RSA sem padding seguro não deve ser usado

RSA "puro" calcula apenas `c = m^e mod n` (cifragem) ou `s = m^d mod n` (assinatura). Isso tem vários problemas:

- **Determinismo:** a mesma mensagem gera sempre o mesmo `c`. Quem suspeita do conteúdo (por exemplo, "sim" ou "não") cifra os palpites com a chave pública e compara.
- **Maleabilidade:** como `(m1 · m2)^e = c1 · c2 mod n`, é possível alterar um ciphertext de forma controlada, obtendo o texto claro multiplicado por um valor escolhido, sem conhecer a chave privada.
- **Mensagens pequenas:** se `m^e < n`, o módulo nunca é aplicado e `m` sai da raiz `e`-ésima inteira de `c`.
- **Forja de assinaturas:** o produto de duas assinaturas válidas é uma assinatura válida do produto das mensagens. Além disso, sem hash nem estrutura, qualquer `s` escolhido pelo atacante é assinatura válida de `m = s^e mod n`.
- **Nenhuma redundância verificável:** qualquer inteiro menor que `n` é "válido", então nada detecta adulteração.

Por isso se usa sempre um esquema de codificação padronizado: OAEP para cifrar e PSS para assinar.

## Função do OAEP na cifragem e do PSS na assinatura

**OAEP.** Antes da operação pública, a mensagem é embutida no bloco `EM = 0x00 || maskedSeed || maskedDB`, com `DB = lHash || PS || 0x01 || M`. Uma `seed` aleatória e duas rodadas de MGF1 (estrutura tipo Feistel) misturam tudo. Efeitos:

- a cifragem passa a ser **probabilística**: a mesma mensagem gera ciphertexts diferentes;
- a estrutura (`0x00` inicial, `lHash`, `PS` de zeros, separador `0x01`) faz com que blocos adulterados normalmente sejam rejeitados na decifragem; OAEP, sozinho, **não autentica a origem** da mensagem;
- a implementação devolve **um único erro** para falhas de decifragem, dificultando um oráculo de padding baseado em respostas diferentes (como no ataque de Manger). Isso não garante execução em tempo constante nem elimina todo canal lateral; o código usa `DecryptionError` e tenta reduzir esse risco.

**PSS.** Em vez de assinar diretamente o hash, o PSS mistura o hash da mensagem com um `salt` aleatório (`M' = 0x00*8 || mHash || salt`, `H = SHA3-256(M')`) e mascara o resultado com MGF1. Efeitos:

- a assinatura é **probabilística**: ao assinar o mesmo arquivo duas vezes, espera-se obter assinaturas diferentes e válidas; uma colisão do salt aleatório de 32 bytes é extremamente improvável;
- a estrutura codificada frustra a forja multiplicativa direta do RSA puro, pois uma assinatura válida precisa decodificar para o formato PSS esperado;
- há provas de segurança que relacionam a forjabilidade do esquema à dificuldade do problema RSA, sob hipóteses e no modelo do oráculo aleatório.

Na verificação não se "decifra um hash": aplica-se a operação pública à assinatura para recuperar o bloco codificado, valida-se sua estrutura e compara-se `H` com `H'`, calculado a partir do arquivo recebido e do salt extraído. Por isso RSA-PSS não é "cifrar o hash com a chave privada".

## RSA-PSS versus Ed25519

| Aspecto | RSA-PSS (2048 bits) | Ed25519 |
|---|---|---|
| Base matemática | fatoração de inteiros | logaritmo discreto em curva elíptica (Curve25519) |
| Material público (sem codificação) | módulo `n`: 256 bytes (a chave serializada é maior) | chave bruta: 32 bytes |
| Assinatura | 256 bytes | 64 bytes |
| Geração de chaves | lenta (busca de primos) | praticamente instantânea |
| Assinar | mais lento | muito rápido |
| Verificar | muito rápido (`e = 65537`) | rápido |
| Aleatoriedade | salt aleatório a cada assinatura | **determinístico**: o nonce é derivado da chave e da mensagem |
| Nível de segurança | ~112 bits | ~128 bits |
| Parâmetros do chamador | hash, MGF1, tamanho do salt | nenhum (parâmetros fixos) |
| Adoção | muito ampla, infraestrutura legada | ampla e crescente |

Ed25519 é mais compacto, gera chaves e assina mais depressa e é mais difícil de usar errado: como o nonce é determinístico, um gerador aleatório ruim não compromete a chave, e não há parâmetros a escolher. RSA-PSS continua adequado quando há exigência de compatibilidade ou de conformidade com padrões e infraestrutura existentes (o NIST FIPS 186-5 admite os dois). Nenhum dos dois resiste a um computador quântico de grande escala (algoritmo de Shor).

## Limitações desta implementação

O projeto serve ao estudo dos esquemas e não substitui uma biblioteca criptográfica auditada em produção. O código tenta reduzir vazamentos por temporização (`hmac.compare_digest`, varredura completa do `DB`, blinding na operação privada), mas Python e suas operações com inteiros grandes não garantem execução em tempo constante.