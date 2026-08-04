"""Settings resolution, browser hardening flags, and the scope fence."""

from __future__ import annotations

import pytest

from config import Settings, playwright_args
from main import _origin, _phase_instructions
from skills import SKILLS, load_reference, load_skill, skill


@pytest.fixture
def clean_env(monkeypatch):
    for name in (
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "DAST_MODEL",
        "DAST_MAX_TURNS",
        "DAST_MCP_TIMEOUT",
        "DAST_BROWSER_NO_SANDBOX",
        "DAST_IGNORE_HTTPS_ERRORS",
        "DAST_PROXY_SERVER",
    ):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestSettings:
    def test_blank_base_url_means_the_default_endpoint(self, clean_env):
        # .env.example ships OPENAI_API_BASE= blank; passing "" through to the
        # OpenAI client makes every request fail.
        clean_env.setenv("OPENAI_API_BASE", "")
        assert Settings.from_env().base_url is None

    def test_base_url_is_used_when_set(self, clean_env):
        clean_env.setenv("OPENAI_API_BASE", "https://gw.example.com/v1")
        assert Settings.from_env().base_url == "https://gw.example.com/v1"

    def test_api_key_is_not_in_the_repr(self, clean_env):
        settings = Settings(api_key="sk-super-secret", base_url=None, model="m")
        assert "sk-super-secret" not in repr(settings)

    def test_non_integer_turn_budget_fails_with_a_readable_message(self, clean_env):
        clean_env.setenv("DAST_MAX_TURNS", "lots")
        with pytest.raises(SystemExit, match="DAST_MAX_TURNS"):
            Settings.from_env()

    def test_turn_budget_is_read(self, clean_env):
        clean_env.setenv("DAST_MAX_TURNS", "12")
        assert Settings.from_env().max_turns == 12


class TestBrowserHardening:
    def test_sandbox_is_on_by_default(self, clean_env):
        assert "--no-sandbox" not in playwright_args()

    def test_sandbox_can_be_disabled_explicitly(self, clean_env):
        clean_env.setenv("DAST_BROWSER_NO_SANDBOX", "1")
        assert "--no-sandbox" in playwright_args()

    def test_tls_errors_are_not_ignored_by_default(self, clean_env):
        assert "--ignore-https-errors" not in playwright_args()

    def test_headless_and_isolated_are_always_set(self, clean_env):
        args = playwright_args()
        assert "--headless" in args
        assert "--isolated" in args

    def test_scope_fence_is_passed_to_the_browser(self, clean_env):
        args = playwright_args("https://staging.example.com")
        assert "--allowed-origins=https://staging.example.com" in args

    def test_no_fence_when_no_origin_given(self, clean_env):
        assert not any(a.startswith("--allowed-origins") for a in playwright_args())

    def test_proxy_is_opt_in(self, clean_env):
        clean_env.setenv("DAST_PROXY_SERVER", "http://127.0.0.1:8080")
        assert "--proxy-server=http://127.0.0.1:8080" in playwright_args()


class TestOriginParsing:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://staging.example.com", "https://staging.example.com"),
            ("https://staging.example.com/app/login", "https://staging.example.com"),
            ("http://localhost:3000/x?y=1", "http://localhost:3000"),
        ],
    )
    def test_origin_is_scheme_host_port(self, url, expected):
        assert _origin(url) == expected

    @pytest.mark.parametrize("bad", ["example.com", "ftp://example.com", "", "/relative"])
    def test_non_absolute_http_urls_are_rejected(self, bad):
        with pytest.raises(SystemExit, match="--base-url"):
            _origin(bad)


class TestSkillsAndReferences:
    def test_every_skill_and_cited_reference_exists(self):
        for item in SKILLS:
            assert load_skill(item.skill_path).strip()
            for name in item.references:
                assert load_reference(name).strip()

    def test_path_escape_is_refused(self):
        with pytest.raises(ValueError, match="escaped"):
            load_skill("../config.py")
        with pytest.raises(ValueError, match="escaped"):
            load_reference("../main.py")

    def test_unknown_phase_names_are_reported(self):
        with pytest.raises(KeyError, match="walk"):
            skill("nope")

    @pytest.mark.parametrize("phase", ["walk", "pentest"])
    def test_cited_references_are_inlined_into_the_prompt(self, phase):
        # The bug this guards: skills told the model to consult references/*.md,
        # but nothing ever put those files where the model could read them.
        prompt = _phase_instructions(phase)
        for name in skill(phase).references:
            assert f"### references/{name}" in prompt
            first_heading = next(
                line for line in load_reference(name).splitlines() if line.startswith("#")
            )
            assert first_heading in prompt

    @pytest.mark.parametrize("phase", ["walk", "pentest"])
    def test_prompts_carry_the_untrusted_input_warning(self, phase):
        assert "Untrusted input" in _phase_instructions(phase)
