import unittest
import json
import os
from brain import Brain
from tools.nmap_agent import NmapAgent

class TestAgents(unittest.TestCase):
    def test_nmap_agent_initialization(self):
        agent = NmapAgent()
        self.assertIsInstance(agent, NmapAgent)

    def test_brain_mock_think(self):
        brain = Brain()
        # Force disable to test mock logic
        brain.enabled = False
        decision = brain.think({"target": "127.0.0.1"}, "Scan")
        self.assertIn("plan", decision)
        self.assertEqual(decision["plan"][0]["tool"], "nmap")

if __name__ == '__main__':
    unittest.main()
