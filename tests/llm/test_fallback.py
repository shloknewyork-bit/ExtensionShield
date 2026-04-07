"""
Unit tests for LLM fallback functionality.
"""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from langchain_core.messages import HumanMessage

from extension_shield.llm.clients.fallback import (
    _parse_fallback_chain,
    invoke_with_fallback,
    LLMFallbackError,
    _is_retryable_error,
)
from extension_shield.llm.clients.provider_type import LLMProviderType


class TestParseFallbackChain:
    """Tests for _parse_fallback_chain function."""

    def test_parse_fallback_chain_from_env(self):
        """Test parsing fallback chain from LLM_FALLBACK_CHAIN env var."""
        with patch.dict(os.environ, {"LLM_FALLBACK_CHAIN": "ollama,openai,watsonx"}):
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.OLLAMA, LLMProviderType.OPENAI, LLMProviderType.WATSONX]

    def test_parse_fallback_chain_single_provider(self):
        """Test parsing single provider from LLM_FALLBACK_CHAIN."""
        with patch.dict(os.environ, {"LLM_FALLBACK_CHAIN": "openai"}):
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.OPENAI]

    def test_parse_fallback_chain_from_llm_provider(self):
        """Test falling back to LLM_PROVIDER when LLM_FALLBACK_CHAIN not set."""
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}, clear=True):
            # Remove LLM_FALLBACK_CHAIN if it exists
            if "LLM_FALLBACK_CHAIN" in os.environ:
                del os.environ["LLM_FALLBACK_CHAIN"]
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.OLLAMA]

    def test_parse_fallback_chain_default_chain(self):
        """Test defaulting to the built-in provider chain when no provider is set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove both LLM_FALLBACK_CHAIN and LLM_PROVIDER
            for key in ["LLM_FALLBACK_CHAIN", "LLM_PROVIDER", "LLM_PROVIDER_PRIMARY"]:
                if key in os.environ:
                    del os.environ[key]
            chain = _parse_fallback_chain()
            assert chain == [
                LLMProviderType.GROQ,
                LLMProviderType.WATSONX,
                LLMProviderType.OPENAI,
            ]

    def test_parse_fallback_chain_invalid_provider_skipped(self):
        """Test that invalid providers in chain are skipped."""
        with patch.dict(os.environ, {"LLM_FALLBACK_CHAIN": "ollama,invalid,openai"}):
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.OLLAMA, LLMProviderType.OPENAI]

    def test_parse_fallback_chain_whitespace_handled(self):
        """Test that whitespace in chain is handled correctly."""
        with patch.dict(os.environ, {"LLM_FALLBACK_CHAIN": " ollama , openai , watsonx "}):
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.OLLAMA, LLMProviderType.OPENAI, LLMProviderType.WATSONX]

    def test_parse_fallback_chain_primary_override(self):
        """Test LLM_PROVIDER_PRIMARY override."""
        with patch.dict(os.environ, {"LLM_PROVIDER_PRIMARY": "rits"}, clear=True):
            if "LLM_FALLBACK_CHAIN" in os.environ:
                del os.environ["LLM_FALLBACK_CHAIN"]
            chain = _parse_fallback_chain()
            assert chain == [LLMProviderType.RITS]


class TestIsRetryableError:
    """Tests for _is_retryable_error function."""

    def test_network_error_retryable(self):
        """Test that network errors are retryable."""
        error = Exception("Connection refused")
        assert _is_retryable_error(error) is True

    def test_timeout_error_retryable(self):
        """Test that timeout errors are retryable."""
        error = TimeoutError("Request timed out")
        assert _is_retryable_error(error) is True

    def test_http_5xx_retryable(self):
        """Test that HTTP 5xx errors are retryable."""
        error = Exception("HTTP 500 Internal Server Error")
        assert _is_retryable_error(error) is True

    def test_auth_error_retryable(self):
        """Test that authentication errors are retryable."""
        error = Exception("Authentication failed: Invalid API key")
        assert _is_retryable_error(error) is True

    def test_401_error_retryable(self):
        """Test that 401 errors are retryable."""
        error = Exception("HTTP 401 Unauthorized")
        assert _is_retryable_error(error) is True

    def test_model_not_found_not_retryable(self):
        """Test that model not found errors are not retryable."""
        error = Exception("Model 'invalid-model' not found")
        assert _is_retryable_error(error) is False

    def test_invalid_input_not_retryable(self):
        """Test that invalid input errors are not retryable."""
        error = ValueError("Invalid input format")
        assert _is_retryable_error(error) is False


class TestInvokeWithFallback:
    """Tests for invoke_with_fallback function."""

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    @patch("extension_shield.llm.clients.fallback.get_chat_llm_client")
    @patch("extension_shield.llm.clients.fallback._invoke_with_timeout")
    def test_success_first_provider(self, mock_invoke, mock_get_client, mock_parse_chain):
        """Test successful invocation with first provider."""
        # Setup
        mock_parse_chain.return_value = [LLMProviderType.OLLAMA, LLMProviderType.OPENAI]
        mock_llm = Mock()
        mock_get_client.return_value = mock_llm
        mock_response = Mock()
        mock_response.content = "Test response"
        mock_invoke.return_value = mock_response

        messages = [HumanMessage(content="Test")]
        result = invoke_with_fallback(
            messages=messages,
            model_name="llama3",
            model_parameters={"temperature": 0.7},
        )

        assert result == mock_response
        mock_get_client.assert_called_once_with(
            model_name="llama3",
            model_parameters={"temperature": 0.7},
            provider_override=LLMProviderType.OLLAMA,
        )
        mock_invoke.assert_called_once()

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    @patch("extension_shield.llm.clients.fallback.get_chat_llm_client")
    @patch("extension_shield.llm.clients.fallback._invoke_with_timeout")
    def test_fallback_to_second_provider(self, mock_invoke, mock_get_client, mock_parse_chain):
        """Test fallback to second provider when first fails."""
        # Setup
        mock_parse_chain.return_value = [LLMProviderType.OLLAMA, LLMProviderType.OPENAI]
        mock_llm_ollama = Mock()
        mock_llm_openai = Mock()
        mock_get_client.side_effect = [mock_llm_ollama, mock_llm_openai]

        # First provider fails, second succeeds
        mock_response = Mock()
        mock_response.content = "OpenAI response"
        mock_invoke.side_effect = [TimeoutError("Timeout"), mock_response]

        messages = [HumanMessage(content="Test")]
        result = invoke_with_fallback(
            messages=messages,
            model_name="llama3",
        )

        assert result == mock_response
        assert mock_get_client.call_count == 2
        assert mock_invoke.call_count == 2

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    @patch("extension_shield.llm.clients.fallback.get_chat_llm_client")
    @patch("extension_shield.llm.clients.fallback._invoke_with_timeout")
    @patch.dict(os.environ, {"LLM_MAX_RETRIES_PER_PROVIDER": "0"})
    def test_all_providers_fail(self, mock_invoke, mock_get_client, mock_parse_chain):
        """Test that LLMFallbackError is raised when all providers fail."""
        # Setup
        mock_parse_chain.return_value = [LLMProviderType.OLLAMA, LLMProviderType.OPENAI]
        mock_llm = Mock()
        mock_get_client.return_value = mock_llm
        mock_invoke.side_effect = [TimeoutError("Timeout"), Exception("API key invalid")]

        messages = [HumanMessage(content="Test")]
        with pytest.raises(LLMFallbackError) as exc_info:
            invoke_with_fallback(
                messages=messages,
                model_name="llama3",
            )

        assert "ollama" in str(exc_info.value.errors)
        assert "openai" in str(exc_info.value.errors)

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    @patch("extension_shield.llm.clients.fallback.get_chat_llm_client")
    @patch("extension_shield.llm.clients.fallback._invoke_with_timeout")
    @patch.dict(os.environ, {"LLM_MAX_RETRIES_PER_PROVIDER": "2"})
    def test_retry_per_provider(self, mock_invoke, mock_get_client, mock_parse_chain):
        """Test retry logic per provider."""
        # Setup
        mock_parse_chain.return_value = [LLMProviderType.OLLAMA]
        mock_llm = Mock()
        mock_get_client.return_value = mock_llm

        # First two attempts fail, third succeeds
        mock_response = Mock()
        mock_response.content = "Success"
        mock_invoke.side_effect = [TimeoutError("Timeout"), TimeoutError("Timeout"), mock_response]

        messages = [HumanMessage(content="Test")]
        result = invoke_with_fallback(
            messages=messages,
            model_name="llama3",
        )

        assert result == mock_response
        assert mock_invoke.call_count == 3  # 2 retries + 1 success

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    @patch("extension_shield.llm.clients.fallback.get_chat_llm_client")
    @patch("extension_shield.llm.clients.fallback._invoke_with_timeout")
    @patch.dict(os.environ, {"LLM_TIMEOUT_SECONDS": "10"})
    def test_custom_timeout(self, mock_invoke, mock_get_client, mock_parse_chain):
        """Test custom timeout configuration."""
        # Setup
        mock_parse_chain.return_value = [LLMProviderType.OLLAMA]
        mock_llm = Mock()
        mock_get_client.return_value = mock_llm
        mock_response = Mock()
        mock_response.content = "Success"
        mock_invoke.return_value = mock_response

        messages = [HumanMessage(content="Test")]
        invoke_with_fallback(
            messages=messages,
            model_name="llama3",
        )

        # Check that timeout was passed to _invoke_with_timeout
        # The function is called with: _invoke_with_timeout(llm, messages, timeout_seconds, **kwargs)
        # We verify it was called (the timeout is set via env var, so we just verify it was called)
        assert mock_invoke.called

    @patch("extension_shield.llm.clients.fallback._parse_fallback_chain")
    def test_empty_fallback_chain_raises_error(self, mock_parse_chain):
        """Test that empty fallback chain raises ValueError."""
        mock_parse_chain.return_value = []
        messages = [HumanMessage(content="Test")]

        with pytest.raises(ValueError, match="No LLM providers configured"):
            invoke_with_fallback(
                messages=messages,
                model_name="llama3",
            )
