import base64
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from integrity import envelope
from rsa_core import generate_key_pair
from rsa_pss import decode_and_verify, sign_and_encode


class RSAPSSDocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_key_pair()
        cls.public_key = cls.private_key.get_public_key()
        cls.other_public_key = generate_key_pair().get_public_key()
        cls.content = b"Arquivo para verificacao de integridade."
        cls.signature = sign_and_encode(cls.private_key, cls.content)
        cls.signed = envelope.encode_envelope(cls.content, cls.signature)

    def _verify_signature(self, public_key, content, signature):
        return decode_and_verify(public_key, content, signature)

    def test_parse_and_verify_valid_document(self):
        parsed_content, parsed_signature = envelope.parse_envelope(self.signed)
        self.assertEqual(parsed_content, self.content)
        self.assertEqual(parsed_signature, self.signature)
        self.assertTrue(
            self._verify_signature(self.public_key, parsed_content, parsed_signature)
        )

    def _with_field(self, field, transform):
        envelope = json.loads(self.signed)
        envelope[field] = transform(envelope[field])
        return json.dumps(envelope).encode("utf-8")

    def _flip_signature_byte(self, index):
        def flip(encoded_signature):
            signature = bytearray(base64.b64decode(encoded_signature, validate=True))
            signature[index] ^= 0x01
            return base64.b64encode(signature).decode("ascii")

        return self._with_field("signature", flip)

    def test_one_file_byte_tampering_is_rejected(self):
        original_content, signature = envelope.parse_envelope(self.signed)
        modified_content = bytearray(original_content)
        modified_content[0] ^= 0x01
        changed = envelope.encode_envelope(bytes(modified_content), signature)
        parsed_content, parsed_signature = envelope.parse_envelope(changed)
        self.assertEqual(
            sum(left != right for left, right in zip(original_content, parsed_content)),
            1,
        )
        self.assertFalse(
            self._verify_signature(self.public_key, parsed_content, parsed_signature)
        )

    def test_one_signature_byte_tampering_is_rejected(self):
        signature_length = len(base64.b64decode(self.signature, validate=True))
        for index in (0, 1, signature_length // 2, signature_length - 1):
            with self.subTest(byte=index):
                changed = self._flip_signature_byte(index)
                content, signature = envelope.parse_envelope(changed)
                self.assertFalse(
                    self._verify_signature(self.public_key, content, signature)
                )

    def test_invalid_signature_base64_is_rejected(self):
        changed = self._with_field("signature", lambda _: "!!!")
        self.assertFalse(envelope.verify_document(changed, self.public_key))

    def test_different_public_key_is_rejected(self):
        self.assertFalse(
            self._verify_signature(self.other_public_key, self.content, self.signature)
        )

    def test_modified_modulus_is_rejected(self):
        modified_key = replace(self.public_key, n=self.public_key.n ^ 2)
        self.assertFalse(
            self._verify_signature(modified_key, self.content, self.signature)
        )

    def test_malformed_inputs_are_rejected_without_exception(self):
        signed_document = json.loads(self.signed)
        missing_signature = {
            key: value for key, value in signed_document.items() if key != "signature"
        }
        cases = {
            "vazio": b"",
            "nao_json": b"isto nao e json",
            "json_lista": b"[]",
            "objeto_vazio": b"{}",
            "sem_assinatura": json.dumps(missing_signature).encode("utf-8"),
            "base64_invalido": self._with_field("signature", lambda _: "!!!"),
            "assinatura_truncada": self._with_field(
                "signature", lambda signature: signature[:40]
            ),
            "assinatura_zerada": self._with_field(
                "signature",
                lambda signature: base64.b64encode(
                    bytes(len(base64.b64decode(signature, validate=True)))
                ).decode("ascii"),
            ),
        }
        for case, data in cases.items():
            with self.subTest(caso=case):
                self.assertFalse(envelope.verify_document(data, self.public_key))

    def test_signing_twice_gives_different_valid_signatures(self):
        another_signature = sign_and_encode(self.private_key, self.content)
        original_signature = self.signature
        self.assertNotEqual(original_signature, another_signature)
        self.assertTrue(
            decode_and_verify(self.public_key, self.content, another_signature)
        )

    def test_base64_helpers_sign_and_verify(self):
        signature_b64 = sign_and_encode(self.private_key, self.content)
        self.assertIsInstance(signature_b64, str)
        self.assertTrue(decode_and_verify(self.public_key, self.content, signature_b64))
        self.assertFalse(decode_and_verify(self.public_key, self.content, "!!!"))

    def test_verify_document_catches_verification_exception(self):
        with patch.object(
            envelope,
            "decode_and_verify",
            side_effect=ValueError("falha simulada"),
        ):
            result = envelope.verify_document(self.signed, self.public_key)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
