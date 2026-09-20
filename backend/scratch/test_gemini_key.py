import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

from google import genai
from google.genai import types

client = genai.Client(api_key=api_key)

for m in ["gemini-2.5-flash", "gemini-3.6-flash", "gemini-3.5-flash", "gemini-2.5-flash-lite"]:
    try:
        print("Testing:", m)
        resp = client.models.generate_content(
            model=m,
            contents="Respond with JSON {\"status\": \"ok\"}",
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.0,
            ),
        )
        print(f"SUCCESS with {m}: {resp.text}")
        break
    except Exception as e:
        print(f"Failed {m}: {e}")
