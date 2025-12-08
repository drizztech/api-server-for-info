import os
import json
import logging
import google.generativeai as genai
from knowledge_base import log_knowledge

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Brain")

class Brain:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # Use a model that supports function calling if needed, or just text generation
            self.model = genai.GenerativeModel('gemini-1.5-pro')
            self.enabled = True
        else:
            logger.warning("GEMINI_API_KEY not found. Brain is running in MOCK mode.")
            self.enabled = False

    def think(self, context, goal):
        """
        Uses the LLM to decide on the next steps based on the context and goal.
        """
        if not self.enabled:
            return self._mock_think(context, goal)

        prompt = f"""
        You are an autonomous AI security researcher agent named 'White Fatalis'.
        Your goal is: {goal}

        Current Context:
        {json.dumps(context, indent=2)}

        Based on this context, what should be the next steps?
        Provide a JSON response with a list of tasks.
        Each task should have a 'tool' (e.g., nmap, ffuf, wpscan, analyze) and 'params' (dictionary).

        Example Response:
        {{
            "thought": "I need to scan the target for open ports.",
            "plan": [
                {{"tool": "nmap", "params": {{"target": "example.com", "options": "-sV"}}}},
                {{"tool": "analyze", "params": {{"focus": "ports"}}}}
            ]
        }}
        """

        try:
            response = self.model.generate_content(prompt)
            # Simple cleanup to ensure JSON parsing if the model adds markdown
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            logger.error(f"Error during thinking: {e}")
            return self._mock_think(context, goal)

    def _mock_think(self, context, goal):
        """
        Fallback logic when LLM is unavailable.
        """
        logger.info("Using mock brain logic.")
        target = context.get("target")

        # Simple state machine
        if not context.get("scan_results"):
             return {
                "thought": "No scan results found. Starting with Recon.",
                "plan": [
                    {"tool": "nmap", "params": {"target": target, "options": "-F"}}
                ]
            }
        else:
             return {
                "thought": "Scan complete. Analyzing results.",
                "plan": [
                    {"tool": "analyze", "params": {"data": "scan_results"}}
                ]
            }

    def learn(self, finding):
        """
        Process a finding and summarize it into the knowledge base.
        """
        if self.enabled:
             prompt = f"Summarize this security finding and suggest future attack vectors:\n{json.dumps(finding)}"
             try:
                 response = self.model.generate_content(prompt)
                 summary = response.text
                 log_knowledge("Vulnerability Analysis", summary, source="Gemini")
                 return summary
             except Exception as e:
                 logger.error(f"Error learning: {e}")

        log_knowledge("Finding", finding, source="Tool Output")
        return "Logged finding to database."
