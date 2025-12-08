import subprocess
import shutil
from tools.base_agent import BaseAgent

class NmapAgent(BaseAgent):
    def run(self, params):
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
