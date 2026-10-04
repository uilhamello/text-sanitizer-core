"""Core rules and engine. All data here is fictitious."""
import time
import unittest

from text_sanitizer_core import CORE_MASKS_AFTER, CORE_MASKS_BEFORE, Sanitizer, sanitize


class Masks(unittest.TestCase):
    CASES = [
        ("cliente fulano@example.com reclamou", "<EMAIL>", "fulano@"),
        ("documento sem máscara 12345678909", "<N>", "12345678909"),
        ("origem 10.0.0.7 porta 6033", "<IP>", "10.0.0.7"),
        ("GET https://api.example.com/x?token=abc&id=9", "?<QUERY>", "token=abc"),
        ("senha=Hunter2 e password: 'x y'", "<SECRET>", "Hunter2"),
        ("Authorization: Bearer abcDEF123456789xyz", "<TOKEN>", "abcDEF"),
        ("cookie SID=deadbeef1234", "<SECRET>", "deadbeef"),
        ("id_empresa=48213 e user_id: 77", "id_empresa=<N>", "48213"),
        ("req 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b", "<UUID>", "3f2b8c1e"),
        ("jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "<JWT>", "eyJhbGci"),
        ('{"password": "hunter2", "api_key": "k1"}', '"password": <SECRET>', "hunter2"),
        ("a senha é hunter2", "senha é <SECRET>", "hunter2"),
        ("o token de acesso ficou Abc123xyz", "<SECRET>", "Abc123xyz"),
        ("http://admin:s3cret@192.168.0.1/admin", "<USERINFO>@<IP>", "s3cret"),
        ("cartão 4111 1111 1111 1111 recusado", "<CARD>", "1111"),
        ("cartão 4111-1111-1111-1111", "<CARD>", "4111"),
        ("amex 3782 822463 10005", "<CARD>", "822463"),
        # Fake tokens built at runtime so secret scanners (e.g. GitHub push protection) do not flag the source.
        ("slack " + "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "<TOKEN>", "AbCdEf"),
        ("use " + "gh" + "p_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5 no CI", "<TOKEN>", "p_aB3dE5"),
        ("stripe " + "sk" + "_live_51HxYzAbCdEfGhIjKlMnOpQr", "<TOKEN>", "_live_"),
    ]

    def test_masks(self):
        for text, expected, leaked in self.CASES:
            with self.subTest(text=text):
                clean, report = sanitize(text)
                self.assertIn(expected, clean)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok, report.blocked)

    def test_digits_failing_luhn_are_not_a_card(self):
        self.assertNotIn("<CARD>", sanitize("pedido 1234 5678 9012 3456")[0])


class Blocks(unittest.TestCase):
    CASES = [
        ("aws AKIAABCDEFGHIJKLMNOP", "aws_key"),
        ('{"private_key": "x"}', "gcp_key"),
        ("-----BEGIN CERTIFICATE-----", "pem_header"),
        ("dsn mysql://root@db/app", "conn_string"),
        ("loose aZ9kQ2xP7mL4vB8nR3tY6wE1", "high_entropy"),
        ("x" * 20001, "too_long>20000"),
        (None, "not_text"),
    ]

    def test_blocks(self):
        for text, reason in self.CASES:
            with self.subTest(reason=reason):
                self.assertIn(reason, sanitize(text)[1].blocked)

    def test_oversized_input_is_blocked_before_the_regexes(self):
        start = time.monotonic()
        clean, report = sanitize("x@" * 100000)  # took ~20 s when the size check ran last
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(clean, "")
        self.assertIn("too_long>20000", report.blocked)


class KeepsMetrics(unittest.TestCase):
    def test_metrics_untouched(self):
        text = "p95 624 s; CPU 1-3%; Rows_examined 30M-51M; 51.000.000 rows; 180 conns; 17:30-18:05; latency=310ms; 2026-09-27"
        clean, report = sanitize(text)
        self.assertEqual(clean, text)
        self.assertTrue(report.ok)

    def test_secret_words_without_value_untouched(self):
        for text in ("auth failed for user", "session timeout 30s", "cookie expirado", "token inválido"):
            with self.subTest(text=text):
                self.assertEqual(sanitize(text)[0], text)


class Regions(unittest.TestCase):
    def test_region_masks_run_between_core_before_and_after(self):
        doc = ("doc", r"\bDOC-\d{6}\b", "<DOC>")
        clean, report = Sanitizer(region_masks=[doc]).sanitize("ver DOC-123456 e fulano@example.com")
        self.assertEqual(clean, "ver <DOC> e <EMAIL>")  # without the slot, long_number would eat it first
        self.assertEqual(report.masks, {"doc": 1, "email": 1})

    def test_core_order_is_fixed(self):
        names = [n for n, *_ in CORE_MASKS_BEFORE + CORE_MASKS_AFTER]
        self.assertLess(names.index("card"), names.index("long_number"))
        self.assertLess(names.index("email"), names.index("uuid"))

    def test_extra_patterns(self):
        s = Sanitizer(extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")], extra_blocks=[("internal", r"(?i)confidencial")])
        self.assertEqual(s.sanitize("TCK-42 aberto")[0], "<TICKET> aberto")
        self.assertIn("internal", s.sanitize("doc CONFIDENCIAL")[1].blocked)

    def test_missing_ner_model_blocks_everything(self):
        clean, report = Sanitizer(ner_models=["modelo_que_nao_existe"]).sanitize("texto")
        self.assertEqual(clean, "")
        self.assertTrue(report.blocked[0].startswith("ner_unavailable"))


if __name__ == "__main__":
    unittest.main()
