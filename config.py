# config.py

# Tool paths (update these to your specific installations)
TOOL_PATHS = {
    "nmap": "/usr/bin/nmap",
    "nuclei": "~/go/bin/nuclei",
    "ffuf": "~/go/bin/ffuf",
    "sqlmap": "/usr/bin/sqlmap", # or wherever sqlmap is installed
    "whatweb": "/usr/bin/whatweb",
    "subfinder": "~/go/bin/subfinder",
    "httpx": "~/go/bin/httpx",
    "aquatone": "~/go/bin/aquatone",
    "dirb": "/usr/bin/dirb",
    "wapiti": "/usr/bin/wapiti",
    # Add other tools here
}

# Common wordlists
WORDLISTS = {
    "dirb_common": "/usr/share/wordlists/dirb/common.txt",
    "fuzz_medium": "/usr/share/wordlists/dirb/common.txt", # Placeholder, replace with a proper fuzzing wordlist
    # Add other wordlists here
}

# Nuclei templates directory (if custom templates are used)
NUCLEI_TEMPLATES = "~/.nuclei-templates/"

# Default output directory names
OUTPUT_DIRS = {
    "reconnaissance": "reconnaissance",
    "scanning": "scanning",
    "exploitation": "exploitation",
    "reports": "reports",
    "data": "data" # For structured data storage
}

# AI/LLM settings (placeholders)
AI_SETTINGS = {
    "enabled": False,
    "api_key": "YOUR_OPENAI_API_KEY", # Replace with actual API key
    "model_name": "gpt-4",
    "temperature": 0.7
}

# Other general settings
GENERAL_SETTINGS = {
    "verbose": True,
    "log_file": "bugsleuth.log"
}
