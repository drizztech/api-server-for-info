import os
import json
import logging
import google.generativeai as genai
from knowledge_base import log_knowledge, search_knowledge, add_lesson
from tools.registry import get_tool_schemas

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Brain")

# --- PLACEHOLDER FOR SYSTEM PROMPT ---
# This is where the core personality and operating instructions for the AI reside.
# The prompt should define the AI's role (White Fatalis), its ethical boundaries,
# its goal to be autonomous, and its ability to learn from past actions.
SYSTEM_PROMPT = """
You are White Fatalis, an advanced, autonomous AI security researcher.
Your primary directive is to identify security vulnerabilities in authorized targets.

OPERATIONAL GUIDELINES:
1.  **autonomy**: You are capable of planning and executing multi-step security assessments.
2.  **Learning**: You must learn from your actions. If a tool fails, analyze why and try a different approach. If you find a vulnerability, remember the pattern.
3.  **Tool Use**: You have access to a suite of security tools. Use them precisely.
4.  **Reporting**: Your final output must be a clear, actionable report.

You will operate in a loop: THINK -> ACT -> OBSERVE -> REFLECT.
"""
# -------------------------------------

class Brain:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-1.5-pro')
            self.enabled = True
        else:
            logger.warning("GEMINI_API_KEY not found. Brain is running in MOCK mode.")
            self.enabled = False

    def think(self, context, goal):
        """
        Uses the LLM to decide on the next steps based on the context, goal, and retrieved knowledge.
        """
        if not self.enabled:
            return self._mock_think(context, goal)

        # 1. Retrieval (RAG-lite)
        # Search for past lessons relevant to the current goal/target
        relevant_knowledge = search_knowledge(f"{goal} {context.get('target', '')}")
        knowledge_snippet = "\n".join([f"- {k['content']}" for k in relevant_knowledge])

        prompt = f"""
        {SYSTEM_PROMPT}

        GOAL: {goal}

        CURRENT CONTEXT:
        {json.dumps(context, indent=2)}

        RELEVANT PAST KNOWLEDGE:
        {knowledge_snippet}

        AVAILABLE TOOLS:
        {json.dumps(get_tool_schemas(), indent=2)}

        INSTRUCTIONS:
        Based on the context and goal, decide on the next set of actions.
        Return a JSON object with:
        - "thought": Your reasoning process.
        - "plan": A list of tool calls. Each call has "tool" (name) and "params" (dict).
        - "status": "CONTINUE" if more work is needed, "COMPLETE" if the goal is met.

        Example Response:
        {{
            "thought": "The target is a web server. I should check for open ports first.",
            "plan": [
                {{"tool": "nmap", "params": {{"target": "example.com", "options": "-F"}}}}
            ],
            "status": "CONTINUE"
        }}
        """

        try:
            response = self.model.generate_content(prompt)
            text = self._clean_json(response.text)
            return json.loads(text)
        except Exception as e:
            logger.error(f"Error during thinking: {e}")
            return self._mock_think(context, goal)

    def reflect(self, target, tool_name, result):
        """
        Analyzes the result of a tool execution to store a 'Lesson'.
        """
        if not self.enabled:
            return

        prompt = f"""
        {SYSTEM_PROMPT}

        Analyze the following tool execution result:
        Target: {target}
        Tool: {tool_name}
        Result: {json.dumps(result)}

        Did it succeed? What did we learn?
        If it failed, suggest a correction.
        If it succeeded, summarize the finding.

        Return a JSON object:
        {{
            "success": true/false,
            "lesson": "The main takeaway...",
            "next_suggested_action": "What to do next based on this..."
        }}
        """
        try:
            response = self.model.generate_content(prompt)
            text = self._clean_json(response.text)
            analysis = json.loads(text)

            # Store the lesson
            if analysis.get("lesson"):
                add_lesson(
                    trigger_keywords=f"{tool_name} {target}",
                    lesson_text=analysis["lesson"],
                    confidence=1.0 if analysis.get("success") else 0.5
                )
            return analysis
        except Exception as e:
            logger.error(f"Error during reflection: {e}")

    def _clean_json(self, text):
        return text.replace("```json", "").replace("```", "").strip()

    def _mock_think(self, context, goal):
        """
        Fallback logic when LLM is unavailable.
        """
        logger.info("Using mock brain logic.")
        target = context.get("target")
        previous_results = context.get("history", [])

        # Simple state machine for testing
        if not previous_results:
             return {
                "thought": "Starting with Recon.",
                "plan": [
                    {"tool": "nmap", "params": {"target": target, "options": "-F"}}
                ],
                "status": "CONTINUE"
            }

        # If we have nmap results, try web inspection
        has_nmap = any(r['tool'] == 'nmap' for r in previous_results)
        if has_nmap and not any(r['tool'] == 'web_inspector' for r in previous_results):
             return {
                "thought": "Nmap complete. Checking web headers.",
                "plan": [
                    {"tool": "web_inspector", "params": {"url": target}}
                ],
                 "status": "CONTINUE"
            }

        return {
            "thought": "All steps complete.",
            "plan": [],
            "status": "COMPLETE"
        }
