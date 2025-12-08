from typing import Dict, Any

class BaseAgent:
    """
    Base class for all tools/agents.
    """
    name: str = "base_agent"
    description: str = "Base tool description."

    def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the tool logic.
        """
        raise NotImplementedError("Subclasses must implement run()")

    @classmethod
    def get_schema(cls) -> Dict[str, Any]:
        """
        Returns the JSON schema of the tool for the LLM.
        Override this in subclasses.
        """
        return {
            "type": "function",
            "function": {
                "name": cls.name,
                "description": cls.description,
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        }
