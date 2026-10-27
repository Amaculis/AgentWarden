"""Tests for agentwarden.redact (spec 009): secrets stripped before anything is sent
to a model. We only assert the secret value is gone and a `[REDACTED:` marker is
present -- the exact `<kind>` label is an implementation detail.
"""

from __future__ import annotations

import pytest

from agentwarden.redact import redact, redact_obj


def _redacted_and_marked(original: str, secret: str) -> str:
    out = redact(original)
    assert secret not in out
    assert "[REDACTED:" in out
    return out


def test_aws_access_key_id_redacted():
    text = "AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE1234 in the env file"
    secret = "AKIAFAKEFAKEFAKE1234"
    out = _redacted_and_marked(text, secret)
    assert "AWS_ACCESS_KEY_ID" in out


def test_private_key_block_redacted():
    pem = (
        "-----BEGIN RSA " "PRIVATE KEY-----\n"
        "MIIFAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATA==\n"
        "-----END RSA " "PRIVATE KEY-----"
    )
    text = f"Here is the key:\n{pem}\nplease rotate it"
    out = redact(text)
    assert "MIIFAKEKEYDATAFAKEKEYDATAFAKEKEYDATAFAKEKEYDATA==" not in out
    assert "[REDACTED:" in out


def test_github_token_redacted():
    secret = "ghp_" + "A" * 36
    text = f"token: {secret}"
    _redacted_and_marked(text, secret)


def test_sk_style_api_key_redacted():
    secret = "sk-ant-" "FAKE1234567890123456789012"
    text = f"export ANTHROPIC_API_KEY={secret}"
    _redacted_and_marked(text, secret)


def test_slack_token_redacted():
    secret = "xoxb-" + "123456789012-1234567890123-" + "FAKE" * 6
    text = f"slack token is {secret}"
    _redacted_and_marked(text, secret)


def test_jwt_redacted():
    secret = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"Authorization header carried {secret} last time"
    _redacted_and_marked(text, secret)


def test_bearer_token_redacted():
    secret = "FAKEBEARERTOKENVALUE12345"
    text = f"Authorization: Bearer {secret}"
    out = _redacted_and_marked(text, secret)
    assert "Bearer" in out


def test_url_credentials_redacted_keeps_scheme_and_host():
    text = "clone from https://user:pass@host.example.com/repo.git"
    out = redact(text)
    assert "user:pass" not in out
    assert "[REDACTED:" in out
    assert "https://" in out
    assert "host.example.com" in out


def test_password_env_assignment_redacted():
    secret = "supersecretvalue1234"
    text = f"PASSWORD={secret}"
    out = _redacted_and_marked(text, secret)
    assert "PASSWORD" in out


def test_api_key_yaml_assignment_redacted():
    secret = "abcdef1234567890"
    text = f"api_key: {secret}"
    out = _redacted_and_marked(text, secret)
    assert "api_key" in out


def test_json_token_field_redacted():
    secret = "abcdef1234567890"
    text = f'{{"token": "{secret}"}}'
    out = _redacted_and_marked(text, secret)
    assert '"token"' in out


def test_credential_name_variant_redacted():
    secret = "topsecretcredvalue"
    text = f'"credential": "{secret}"'
    out = _redacted_and_marked(text, secret)
    assert '"credential"' in out


def test_normal_code_untouched():
    for line in [
        "npm install",
        'git commit -m "fix token parsing"',
        "export PATH=/usr/local/bin:/usr/bin:/bin",
    ]:
        assert redact(line) == line


def test_redact_obj_recursive_over_dict_and_list():
    secret = "AKIAFAKEFAKEFAKE1234"
    obj = {
        "task": f"rotate {secret} now",
        "history": [
            {"tool_name": "Bash", "tool_input": {"command": f"echo {secret}"}},
            "plain string",
        ],
    }
    out = redact_obj(obj)
    assert secret not in str(out)
    assert out["history"][1] == "plain string"
    assert "[REDACTED:" in out["task"]
    assert "[REDACTED:" in out["history"][0]["tool_input"]["command"]


def test_redact_obj_non_str_values_unchanged():
    obj = {"risk": 42, "confidence": 0.5, "flag": True, "nothing": None, "items": [1, 2, 3]}
    out = redact_obj(obj)
    assert out == obj


@pytest.mark.parametrize(
    ("unit", "count"),
    [
        ("key", 20000),
        ("token_", 10000),
        ("Bearer ", 8000),
        ("AKIA", 15000),
        ("a-", 25000),
        ("a.", 25000),
        ("ab+", 17000),
        ("mysql ", 8000),
        ('"token": "', 5000),
    ],
)
def test_redact_is_linear_on_adversarial_input(unit, count):
    # An attacker-controlled file must not stall the judge (quadratic regex backtracking).
    import time

    start = time.perf_counter()
    redact(unit * count + "=value1234")
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('PASSWORD="correct horse battery"', "correct horse battery"),
        ("password='abc def'", "abc def"),
        ("curl -u admin:S3cretPass https://example.invalid", "S3cretPass"),
        ("mysql -u root -pS3cretPass db", "S3cretPass"),
        ("psql --password S3cretPass", "S3cretPass"),
        ("Authorization: Basic YWRtaW46cGFzcw==", "YWRtaW46cGFzcw=="),
        ("STRIPE=sk_" "live_FAKEFAKEFAKE1234", "sk_" "live_FAKEFAKEFAKE1234"),
        ("AIza" + "F" * 35, "AIza" + "F" * 35),
        ("hf_" + "F" * 25, "hf_" + "F" * 25),
        ("npm_" + "F" * 36, "npm_" + "F" * 36),
    ],
)
def test_redact_review_shapes(text, secret):
    _redacted_and_marked(text, secret)


def test_redact_json_value_with_escaped_quote():
    out = redact('{"password": "ab' + chr(92) + '"cdefgh"}')
    assert "cdefgh" not in out


def test_redact_obj_uses_dict_keys():
    obj = {
        "password": "hunter2",
        "api_key": "plainvalue123",
        "Authorization": "Basic abcdefgh",
        "nested": [{"token": 12345}],
        "file_path": "src/app.py",
    }
    out = redact_obj(obj)
    for secret in ("hunter2", "plainvalue123", "abcdefgh", "12345"):
        assert secret not in str(out)
    assert out["file_path"] == "src/app.py"


def test_redact_leaves_mkdir_p_alone():
    assert redact("mkdir -p build/out") == "mkdir -p build/out"
