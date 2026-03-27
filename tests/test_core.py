import subprocess
from unittest.mock import MagicMock, patch

from passbolt_audit import core


class TestRunCli:
    def test_run_cli_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="test output")
            result = core.run_cli(["list", "resource"])
            assert result == "test output"

    def test_run_cli_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            result = core.run_cli(["list", "resource"])
            assert result is None

    def test_run_cli_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = core.run_cli(["list", "resource"])
            assert result is None

    def test_run_cli_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("", 0)):
            result = core.run_cli(["list", "resource"])
            assert result is None


class TestGetAllResources:
    def test_get_all_resources_success(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = '[{"id": "1", "name": "Test"}]'
            result = core.get_all_resources()
            assert len(result) == 1
            assert result[0]["id"] == "1"

    def test_get_all_resources_empty_output(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = None
            result = core.get_all_resources()
            assert result == []

    def test_get_all_resources_invalid_json(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = "not valid json"
            result = core.get_all_resources()
            assert result == []


class TestGetSecret:
    def test_get_secret_success(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = '{"password": "secret123"}'
            result = core.get_secret("resource-id")
            assert result == "secret123"

    def test_get_secret_secret_field(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = '{"secret": "secret456"}'
            result = core.get_secret("resource-id")
            assert result == "secret456"

    def test_get_secret_empty(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = '{"password": ""}'
            result = core.get_secret("resource-id")
            assert result is None

    def test_get_secret_failure(self):
        with patch.object(core, "run_cli") as mock_run_cli:
            mock_run_cli.return_value = None
            result = core.get_secret("resource-id")
            assert result is None


class TestEvaluatePassword:
    def test_evaluate_password_empty(self):
        result = core.evaluate_password("", "resource", "user")
        assert result["score"] == -1
        assert result["debil"] is True
        assert result["label"] == "No password"

    def test_evaluate_password_none(self):
        result = core.evaluate_password(None, "resource", "user")
        assert result["score"] == -1
        assert result["debil"] is True

    def test_evaluate_password_strong(self, mock_zxcvbn_strong):
        with patch("zxcvbn.zxcvbn", return_value=mock_zxcvbn_strong):
            result = core.evaluate_password("Tr0ub4dor&3Password", "resource", "user")
            assert result["score"] == 4
            assert result["debil"] is False
            assert result["crack_time"] == "centuries"
            assert result["longitud"] == 19

    def test_evaluate_password_weak(self, mock_zxcvbn_weak):
        with patch("zxcvbn.zxcvbn", return_value=mock_zxcvbn_weak):
            result = core.evaluate_password("password", "resource", "user")
            assert result["score"] == 1
            assert result["debil"] is True
            assert "zxcvbn score" in result["razon"]
            assert "top-10 common password" in result["razon"]

    def test_evaluate_password_short(self, mock_zxcvbn_strong):
        with patch("zxcvbn.zxcvbn", return_value=mock_zxcvbn_strong):
            result = core.evaluate_password("short", "resource", "user")
            assert result["longitud"] == 5
            assert result["debil"] is True
            assert "Length" in result["razon"]

    def test_evaluate_password_warning(self, mock_zxcvbn_weak):
        with patch("zxcvbn.zxcvbn", return_value=mock_zxcvbn_weak):
            result = core.evaluate_password("weakpass", "resource", "user")
            assert (
                "warning" in result["razon"].lower()
                or "zxcvbn score" in result["razon"]
            )


class TestConsultarHibpBulk:
    def test_consultar_hibp_bulk_empty(self):
        resultados = []
        result = core.consultar_hibp_bulk(resultados, delay=0.1)
        assert result == 0
        assert len(resultados) == 0

    def test_consultar_hibp_bulk_no_passwords(self):
        resultados = [{"_password_raw": "", "debil": False}]
        result = core.consultar_hibp_bulk(resultados, delay=0.1)
        assert result == 0
        assert resultados[0]["pwned"] is None

    @patch("urllib.request.urlopen")
    def test_consultar_hibp_bulk_found(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"5BA61:100\nABCD1:50\n"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        resultados = [
            {"_password_raw": "password123", "debil": False},
            {"_password_raw": "password123", "debil": False},
        ]
        result = core.consultar_hibp_bulk(resultados, delay=0.1)
        assert result >= 0

    @patch("urllib.request.urlopen")
    def test_consultar_hibp_bulk_http_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "", 404, "Not Found", {}, None
        )

        resultados = [{"_password_raw": "test123", "debil": False}]
        result = core.consultar_hibp_bulk(resultados, delay=0.1)
        assert result == 0
        assert resultados[0]["pwned"] is None
        assert resultados[0]["pwned_count"] is None


class TestDetectReusedPasswords:
    def test_detect_reused_passwords_none(self):
        resultados = [
            {"_password_raw": "pass1", "debil": False},
            {"_password_raw": "pass2", "debil": False},
        ]
        total, grupos = core.detect_reused_passwords(resultados)
        assert total == 0
        assert grupos == 0

    def test_detect_reused_passwords_found(self):
        resultados = [
            {"_password_raw": "samepass", "debil": False, "nombre": "A"},
            {"_password_raw": "samepass", "debil": False, "nombre": "B"},
            {"_password_raw": "other", "debil": False, "nombre": "C"},
        ]
        total, grupos = core.detect_reused_passwords(resultados)
        assert total == 2
        assert grupos == 1

    def test_detect_reused_passwords_adds_fields(self):
        resultados = [
            {"_password_raw": "samepass", "debil": False},
            {"_password_raw": "samepass", "debil": False},
        ]
        core.detect_reused_passwords(resultados)
        assert resultados[0]["reutilizada"] is True
        assert resultados[0]["grupo_reutilizacion"] == 1
        assert resultados[0]["veces_reutilizada"] == 2

    def test_detect_reused_passwords_marks_debil(self):
        resultados = [
            {"_password_raw": "samepass", "debil": False},
            {"_password_raw": "samepass", "debil": False},
        ]
        core.detect_reused_passwords(resultados)
        assert resultados[0]["debil"] is True


class TestGenerateCsvReport:
    def test_generate_csv_report(self, tmp_path):
        resultados = [
            {
                "id": "1",
                "nombre": "Test",
                "usuario": "user",
                "uri": "http://test.com",
                "score": 4,
                "label": "Strong",
                "longitud": 10,
                "debil": False,
                "razon": "",
                "crack_time": "centuries",
                "sugerencias": [],
                "reutilizada": False,
                "grupo_reutilizacion": "",
                "veces_reutilizada": 1,
                "pwned": False,
                "pwned_count": 0,
            }
        ]
        csv_path = tmp_path / "test.csv"
        core.generate_csv_report(resultados, str(csv_path))
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "Test" in content
        assert "user" in content


class TestPrintSummary:
    def test_print_summary_basic(self, capsys):
        resultados = [
            {
                "score": 2,
                "debil": True,
                "nombre": "Test1",
                "usuario": "user1",
                "longitud": 8,
                "razon": "weak",
                "reutilizada": False,
            },
            {
                "score": 4,
                "debil": False,
                "nombre": "Test2",
                "usuario": "user2",
                "longitud": 15,
                "razon": "",
                "reutilizada": False,
            },
            {
                "score": -1,
                "debil": True,
                "nombre": "Test3",
                "usuario": "user3",
                "longitud": 0,
                "razon": "empty",
                "reutilizada": False,
            },
        ]
        core.print_summary(resultados, 0, 0, 0)
        captured = capsys.readouterr()
        assert "PASSBOLT" in captured.out
        assert "Total resources audited" in captured.out


class TestScoreLabels:
    def test_score_labels_complete(self):
        assert 0 in core.SCORE_LABELS
        assert 1 in core.SCORE_LABELS
        assert 2 in core.SCORE_LABELS
        assert 3 in core.SCORE_LABELS
        assert 4 in core.SCORE_LABELS
        assert core.SCORE_LABELS[0] == "Very weak"
        assert core.SCORE_LABELS[4] == "Very strong"


class TestConstants:
    def test_umbral_debil(self):
        assert core.UMBRAL_DEBIL == 2

    def test_longitud_minima(self):
        assert core.LONGITUD_MINIMA == 12


class TestConfigurePassbolt:
    def test_configure_passbolt_shows_instructions(self, capsys):
        result = core.configure_passbolt("https://passbolt.test", "password", "/tmp/key.asc")
        assert result is False
        captured = capsys.readouterr()
        assert "go-passbolt-cli must be configured manually" in captured.out
