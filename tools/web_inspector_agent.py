import requests
from typing import Dict, Any
from tools.base_agent import BaseAgent

class WebInspectorAgent(BaseAgent):
    name = "web_inspector"
    description = "Inspects a web URL by making an HTTP request and returning headers and body preview."

    def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url")
        method = params.get("method", "GET")

        if not url.startswith("http"):
            url = "http://" + url

        try:
            response = requests.request(method, url, timeout=10)
            return {
                "tool": "web_inspector",
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_preview": response.text[:1000] # Limit body size
            }
        except Exception as e:
            return {"error": str(e)}

    @classmethod
    def get_schema(cls) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": cls.name,
                "description": cls.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to inspect."
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method (GET, POST, HEAD). Default: GET"
                        }
                    },
                    "required": ["url"]
                }
            }
        }
