"""LLM client module for different providers."""

import os
from typing import Dict, Optional, Any
from dotenv import load_dotenv
from extension_shield.llm.clients.provider_type import LLMProviderType

load_dotenv()

LLM_PROVIDER = LLMProviderType(os.getenv("LLM_PROVIDER", LLMProviderType.WATSONX.value))


def _get_base_llm_settings(
    model_name: str, model_parameters: Optional[Dict], provider: Optional[LLMProviderType] = None
) -> Dict:
    """Get base LLM settings for a specific provider.

    Args:
        model_name: The name of the model to use.
        model_parameters: Optional model parameters.
        provider: Optional provider override. If None, uses global LLM_PROVIDER.

    Returns:
        Dictionary of settings for the LLM client.
    """
    if model_parameters is None:
        model_parameters = {}

    current_provider = provider if provider is not None else LLM_PROVIDER

    if current_provider == LLMProviderType.OLLAMA:
        parameters = {
            "num_predict": model_parameters.get("max_tokens", 1024),
            "temperature": model_parameters.get("temperature", 0.05),
        }

        settings = {
            "model": model_name,
            **parameters,
        }

        # Add base_url if configured (for remote Ollama instances)
        ollama_base_url = os.getenv("OLLAMA_BASE_URL")
        if ollama_base_url:
            settings["base_url"] = ollama_base_url

        return settings

    if current_provider == LLMProviderType.WATSONX:
        parameters = {
            "max_new_tokens": model_parameters.get("max_tokens", 100),
            "decoding_method": model_parameters.get("decoding_method", "greedy"),
            "temperature": model_parameters.get("temperature", 0.9),
            "repetition_penalty": model_parameters.get("repetition_penalty", 1.0),
            "top_k": model_parameters.get("top_k", 50),
            "top_p": model_parameters.get("top_p", 1.0),
            "stop_sequences": model_parameters.get("stop_sequences", []),
        }

        return {
            "url": os.getenv("WATSONX_API_ENDPOINT"),
            "project_id": os.getenv("WATSONX_PROJECT_ID"),
            "apikey": os.getenv("WATSONX_API_KEY"),
            "model_id": model_name,
            "params": parameters,
        }

    if current_provider == LLMProviderType.RITS:
        rits_base_url = os.getenv("RITS_API_BASE_URL")

        parameters = {
            "max_tokens": model_parameters.get("max_tokens", 100),
            "temperature": model_parameters.get("temperature", 0.9),
            "repetition_penalty": model_parameters.get("repetition_penalty", 1.0),
            "top_k": model_parameters.get("top_k", 50),
            "top_p": model_parameters.get("top_p", 1.0),
            "stop": model_parameters.get("stop_sequences", []),
        }

        return {
            "base_url": f"{rits_base_url}/v1",
            "model": model_name,
            "api_key": os.getenv("RITS_API_KEY"),
            "extra_body": parameters,
        }

    if current_provider == LLMProviderType.OPENAI:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is not set. "
                "Please set it in your .env file or environment variables."
            )
        # Validate OpenAI API key format
        if not api_key.startswith("sk-"):
            raise ValueError(
                f"Invalid OpenAI API key format. OpenAI API keys should start with 'sk-', "
                f"but got '{api_key[:10]}...'. "
                "Please check your API key at https://platform.openai.com/api-keys"
            )
        # Reject keys starting with 'sk-proj-' as they are not valid OpenAI API keys
        if api_key.startswith("sk-proj-"):
            raise ValueError(
                f"Invalid API key format detected. Keys starting with 'sk-proj-' are not valid OpenAI API keys. "
                f"Your key appears to be: '{api_key[:15]}...' "
                "Please get a valid API key from https://platform.openai.com/api-keys. "
                "Valid OpenAI API keys start with 'sk-' but NOT 'sk-proj-'."
            )
        return {
            "model": model_name,
            "api_key": api_key,
            "max_tokens": model_parameters.get("max_tokens", 4096),
            "temperature": model_parameters.get("temperature", 0.7),
        }

    raise ValueError(f"Incorrect LLM provider: {current_provider}")


def get_chat_llm_client(
    model_name: str = "meta-llama/llama-3-3-70b-instruct",
    model_parameters: Optional[Dict] = None,
    provider_override: Optional[LLMProviderType] = None,
) -> Any:
    """Get a chat LLM client based on the configured provider.

    Args:
        model_name: The name of the model to use.
        model_parameters: Optional model parameters.
        provider_override: Optional provider to use instead of env config.

    Returns:
        The LLM client instance.
    """
    current_provider = provider_override if provider_override is not None else LLM_PROVIDER

    if current_provider == LLMProviderType.OLLAMA:
        from langchain_ollama import (
            ChatOllama,
        )  # pylint: disable=import-outside-toplevel

        return ChatOllama(
            **_get_base_llm_settings(
                model_name=model_name, model_parameters=model_parameters, provider=current_provider
            )
        )

    if current_provider == LLMProviderType.RITS:
        from langchain_openai import (
            ChatOpenAI,
        )  # pylint: disable=import-outside-toplevel

        return ChatOpenAI(
            **_get_base_llm_settings(
                model_name=model_name, model_parameters=model_parameters, provider=current_provider
            )
        )

    if current_provider == LLMProviderType.WATSONX:
        from langchain_ibm import ChatWatsonx  # pylint: disable=import-outside-toplevel

        return ChatWatsonx(
            **_get_base_llm_settings(
                model_name=model_name, model_parameters=model_parameters, provider=current_provider
            )
        )

    if current_provider == LLMProviderType.OPENAI:
        from langchain_openai import ChatOpenAI  # pylint: disable=import-outside-toplevel

        return ChatOpenAI(
            **_get_base_llm_settings(
                model_name=model_name, model_parameters=model_parameters, provider=current_provider
            )
        )

    raise ValueError(f"Unsupported LLM provider: {current_provider}")
