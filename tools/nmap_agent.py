import subprocess
import shutil
from typing import Dict, Any
from tools.base_agent import BaseAgent

class NmapAgent(BaseAgent):
    name = "nmap"
    description = "Executes an Nmap network scan on a target."

    def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target")
        options = params.get("options", "-sV")

        if not shutil.which("nmap"):
            return {"error": "nmap is not installed."}

        command = ["nmap"] + options.split() + [target]
        try:
            # Running with a timeout to prevent hanging
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            return {
                "tool": "nmap",
                "target": target,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Nmap scan timed out."}
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
                        "target": {
                            "type": "string",
                            "description": "The target hostname or IP address."
                        },
                        "options": {
                            "type": "string",
                            "description": "Nmap command line options (default: -sV)."
                        }
                    },
                    "required": ["target"]
                }
            }
        }
