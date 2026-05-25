import requests
import os

FREELLM_BASE = os.environ.get("FREELLM_BASE_URL", "http://localhost:3001/v1")
FREELLM_KEY  = os.environ.get("FREELLM_API_KEY", "freellmapi-83f24f76e86246e5ecef6dec3f08491926bed08a64002793")

def chat_completion(system_prompt: str, user_message: str, max_tokens: int = 500) -> str:
    """Call FreeLLMAPI with OpenAI-compatible format.
    
    Timeout is set high (90s) because FreeLLMAPI may need to cycle through
    multiple rate-limited free-tier providers before finding one that responds.
    """
    resp = requests.post(
        f"{FREELLM_BASE}/chat/completions",
        headers={"Authorization": f"Bearer {FREELLM_KEY}", "Content-Type": "application/json"},
        json={
            "model": "auto",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7
        },
        timeout=5
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]

