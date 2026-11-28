"""Real RSA verification through google-auth with offline mock certificate transport."""
import json
import time
import unittest

from aegis.google_oidc import GOOGLE_CERTS_URL, verify_google_id_token


class TestGoogleOIDC(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from google.auth import crypt
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        self.signer = crypt.RSASigner.from_string(pem)
        self.public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.audience = "urn:vulnix:cloud-run-proof:" + "a" * 64

    def token(self, **updates):
        from google.auth import jwt
        now = int(time.time())
        claims = {"iss": "https://accounts.google.com", "aud": self.audience,
                  "sub": "service-account-123", "iat": now - 5, "exp": now + 120}
        claims.update(updates)
        return jwt.encode(self.signer, claims, key_id="test-key").decode()

    def request(self, url, **_kwargs):
        self.assertEqual(url, GOOGLE_CERTS_URL)
        class Response:
            status = 200
            data = json.dumps({"test-key": self.public}).encode()
        return Response()

    def test_valid_signature_and_claims(self):
        self.assertEqual(verify_google_id_token(self.token(), self.audience,
                                                request=self.request)["sub"], "service-account-123")

    def test_wrong_issuer_audience_subject_expiry_and_iam_audience(self):
        now = int(time.time())
        for token, aud in ((self.token(**{"iss": "evil"}), self.audience),
                           (self.token(aud="https://service.run.app"), self.audience),
                           (self.token(sub=""), self.audience),
                           (self.token(exp=now - 1), self.audience),
                           (self.token(), "https://service.run.app")):
            with self.subTest(token=token[:16], audience=aud), self.assertRaises(Exception):
                verify_google_id_token(token, aud, request=self.request)

    def test_bad_signature_and_cert_fetch_failure(self):
        token = self.token()
        corrupted = token[:-8] + "AAAAAAAA"
        with self.assertRaises(Exception):
            verify_google_id_token(corrupted, self.audience, request=self.request)
        with self.assertRaises(Exception):
            verify_google_id_token(token, self.audience,
                                   request=lambda *_a, **_k: (_ for _ in ()).throw(OSError("offline")))
