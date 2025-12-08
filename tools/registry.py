from tools.nmap_agent import NmapAgent
from tools.web_inspector_agent import WebInspectorAgent

# Registry of all available tools
TOOL_REGISTRY = {
    "nmap": NmapAgent,
    "web_inspector": WebInspectorAgent
}

def get_tool_schemas():
    """
    Returns a list of JSON schemas for all registered tools.
    """
    return [agent_cls.get_schema() for agent_cls in TOOL_REGISTRY.values()]

def get_tool_instance(tool_name):
    """
    Returns an instance of the requested tool.
    """
    agent_cls = TOOL_REGISTRY.get(tool_name)
    if agent_cls:
        return agent_cls()
    return None
