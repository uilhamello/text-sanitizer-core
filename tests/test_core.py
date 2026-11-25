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
        ("Authorization: Bearer abcDEF123456789xyz", "<SECRET>", "abcDEF"),  # whole header since auth_header
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


class Leaks(unittest.TestCase):
    """Leaks found by the dry-run of 2026-10-15. All data is fictitious."""
    CASES = [
        ("Cookie APP_SID=a8f3k2m9q1x7", "a8f3k2m9q1x7"),
        # Second adversarial pass (secrets).
        ("Authorization: Token abc123def456ghi", "abc123def456ghi"),
        ("curl -H 'Authorization: Bearer abc' -u admin:Senh@123 https://api.example.com", "Senh@123"),
        ('{"credentials": "user:Pa55word"}', "Pa55word"),
        ("credencial: batatinha99", "batatinha99"),
        ("chave: AbC123xyZ789", "AbC123xyZ789"),
        ("cookie APP_SID abc123def", "abc123def"),
        ("mysql -u root -pSenh4Forte -h db", "Senh4Forte"),
        ("GET /api/reset/token/abc123def456 HTTP/1.1", "abc123def456"),
        ("a senha do banco é batata", "batata"),
        ("a senha dele: batata", "batata"),
        ("api key AIzaSyFAKEFAKEFAKEFAKE", "FAKEFAKE"),
        ("OTP: 4829", "4829"),
        ("MYSQL_ROOT_PW=batata123", "batata123"),
        ("cartão 4111.1111.1111.1111", "4111.1111"),
        ("card cvv 123 exp 12/29", "123"),
        ("card cvv 123 exp 12/29", "12/29"),
        ("totp 482913", "482913"),
        ('{"passwd":"sol123"}', "sol123"),
        ('"pwd_hash": "$2y$10$abcdefghijklmnopqrstuv"', "abcdefghij"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("chassi 9bwzzz377vt004251", "377vt"),
        ("cliente_id 4521", "4521"),
        ("Cookie: PHPSESSID=abcdefghijklmn; lang=pt", "abcdefghijklmn"),
        ("Set-Cookie: sess=qwertyuiopas; Path=/", "qwertyuiopas"),
        ("APP_TOKEN=semdigitoaqui", "semdigitoaqui"),
        ("a senha é passarinhoazul", "passarinhoazul"),
        ("the password is bluebird", "bluebird"),
        ("tentou logar com Tr0ub4dor&3 e falhou", "Tr0ub4dor&3"),
        ("chassi 9BWZZZ377VT004251 com sinistro", "377VT"),
        ("contato fulano%40example.com", "fulano"),
        ("escreva para fulano[at]example.com", "fulano"),
        ("fulano (at) example (dot) com", "fulano"),
        ("origem 2001:db8::1 ok", "2001:db8"),
        ("link-local fe80::1ff:fe23:4567:890a", "fe80"),
        ("localhost ::1 recusou", "::1"),
        ("user 4521 and order 98765", "4521"),
        # Third pass: IDs and logins.
        ("userId=4521", "4521"),
        ('{"user_id": 4521}', "4521"),
        ("uid=4521", "4521"),
        ("cod_cliente=4521", "4521"),
        ("GET /users/4521/orders HTTP/1.1", "4521"),
        # A user id in a path is an <ID>, never a <SECRET> (path_token must not take it).
        ("GET /api/users/42 HTTP/1.1", "<SECRET>"),
        ("login=fsilva", "fsilva"),
        ("username: fulano.silva", "fulano"),
        ("@fulano.silva pode ver?", "fulano"),
        ("by fulano.silva on 2026-11-20", "fulano"),
        # Fifth pass: spelled-out and encoded e-mail, IP inside a hostname.
        ("fulano.silva at example dot com", "fulano"),
        ("fulano.silva@intranet", "fulano"),
        ("mailto:fulano%2esilva%40example%2ecom", "fulano"),
        ("IP 203-0-113-45.example.net", "203-0-113-45"),
        ("ip-10-0-0-5.ec2.internal", "10-0-0-5"),
    ]

    def test_no_leak(self):
        for text, leaked in self.CASES:
            with self.subTest(text=text):
                clean, report = sanitize(text)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok, report.blocked)

    def test_secrets_masked_before_names(self):
        """A name model that eats the keyword ("Cookie" -> <PERSON>) must not unmask the value."""
        class Ent:
            def __init__(self, start, end):
                self.start_char, self.end_char, self.label_ = start, end, "PER"

        class EatsCookie:
            def __call__(self, text):
                i = text.find("Cookie")
                return type("Doc", (), {"ents": [Ent(i, i + 6)] if i >= 0 else []})()

        s = Sanitizer()
        s._nlps = [EatsCookie()]
        clean, _ = s.sanitize("Cookie: sid=a8f3k2m9q1x7")
        self.assertNotIn("a8f3k2m9q1x7", clean)

    def test_false_positives_kept(self):
        for text in ("Db::add chamado em Cache::get", "a senha do usuário expirou", "o token expirou ontem",
                     "erro 500 às 10:30", "token_ttl=3600", "auth: ok", "sid: null", "memory_limit=512M, max_execution_time=600",
                     "pedido 1234.5678.9012.3456", "51.000.000 rows", "o token expira em 3600 segundos",
                     "a senha expirou ontem", "docker run -p 8080:80 app", "GET /api/v2/health/42 HTTP/1.1", "porta 8080 e versão 5.6", "std::vector e ::operator", "max 4521 rows",
                     "@Override public void run()", "@app.route('/x')", "@pytest.mark.slow", "npm i @types/node",
                     "@login_required", "login: not found", "user: null", "valid=1", "paid = 3", "codigo_erro=500",
                     "build by gradle.plugin", "user agent Mozilla/5.0",
                     "npm i react@latest", "node@sha256:ab", "npm i lodash.debounce@4.0.8", "python3.12@venv",
                     "server at node1 dot internal", "build 1-2-3-4.tar.gz", "2026-11-25.log", "%2e%2e/etc/passwd"):
            with self.subTest(text=text):
                self.assertEqual(sanitize(text)[0], text)


class ExtraMasks(unittest.TestCase):
    def test_caller_rule_wins_over_generic(self):
        """A caller rule must not lose to a generic one: "TCK-4521" is a ticket, not an ID or a plate."""
        s = Sanitizer(region_masks=[("plate", r"\b[A-Z]{3}-\d{4}\b", "<PLATE>")],
                      extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")])
        self.assertEqual(s.sanitize("TCK-4521 aberto")[0], "<TICKET> aberto")

    def test_secret_still_masked_with_broad_caller_rule(self):
        """A broad caller rule runs after the secrets, so it cannot strip the keyword before the value is masked."""
        s = Sanitizer(extra_masks=[("palavra", r"\bsenha\b", "<X>")])
        self.assertNotIn("batata123", s.sanitize("senha: batata123")[0])


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
