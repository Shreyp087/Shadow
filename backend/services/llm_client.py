from __future__ import annotations

from typing import Any


async def request_text(
    client: Any,
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    temperature: float = 0,
) -> str:
    if hasattr(client, "chat") and hasattr(client.chat, "completions"):
        response = await client.chat.completions.create(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return _extract_openai_text(response)

    if hasattr(client, "messages") and hasattr(client.messages, "create"):
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt},
            ],
        )
        return _extract_anthropic_text(response)

    raise TypeError("Unsupported LLM client. Expected OpenAI or Anthropic compatible client.")


def _extract_openai_text(response: Any) -> str:
    choices = getattr(response, "choices", None) or []
    if not choices:
        return ""

    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", "")

    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
                continue

            text_value = getattr(item, "text", None)
            if isinstance(text_value, str) and text_value.strip():
                parts.append(text_value.strip())
                continue

            if isinstance(item, dict):
                dict_text = item.get("text")
                if isinstance(dict_text, str) and dict_text.strip():
                    parts.append(dict_text.strip())

        return "\n".join(parts)

    return str(content).strip()


def _extract_anthropic_text(message: Any) -> str:
    parts: list[str] = []
    for block in getattr(message, "content", []):
        text_value = getattr(block, "text", None)
        if isinstance(text_value, str) and text_value.strip():
            parts.append(text_value.strip())
    return "\n".join(parts)
