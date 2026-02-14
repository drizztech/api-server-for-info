import sys
import json
import logging
import requests
import os
import argparse

# Add parent directory to path to import brain
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain import Brain

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ReconAnalyzer")

def analyze_with_ollama(data, model="llama3"):
    """
    Sends data to a local Ollama instance for analysis.
    """
    url = "http://localhost:11434/api/generate"
    prompt = f"""
    You are a security analyst. Analyze the following reconnaissance data for potential security issues, misconfigurations, or interesting vectors.
    Data:
    {json.dumps(data, indent=2)}

    Provide a concise summary of findings.
    """

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "No response from Ollama")
    except Exception as e:
        logger.error(f"Ollama analysis failed: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Analyze recon data with AI")
    parser.add_argument("--ollama-model", default="llama3", help="Ollama model to use")
    parser.add_argument("--use-gemini", action="store_true", help="Enable Gemini analysis")
    parser.add_argument("--use-ollama", action="store_true", help="Enable Ollama analysis")
    args = parser.parse_args()

    brain = None
    if args.use_gemini:
        brain = Brain()

    logger.info("Starting Recon Analyzer. Waiting for input on stdin...")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON line: {line}")
            continue

        # Extract interesting parts to avoid token limits or noise
        analysis_target = {
            "url": data.get("url"),
            "headers": data.get("headers"),
            "vulns": data.get("vulns")
        }

        # Gemini Analysis
        if brain and brain.enabled:
            logger.info(f"Analyzing {data.get('url')} with Gemini...")
            gemini_analysis = brain.learn(analysis_target)
            data["gemini_analysis"] = gemini_analysis

        # Ollama Analysis
        if args.use_ollama:
             logger.info(f"Analyzing {data.get('url')} with Ollama ({args.ollama_model})...")
             ollama_analysis = analyze_with_ollama(analysis_target, model=args.ollama_model)
             if ollama_analysis:
                 data["ollama_analysis"] = ollama_analysis

        # Output enriched data
        print(json.dumps(data))
        sys.stdout.flush()

if __name__ == "__main__":
    main()
