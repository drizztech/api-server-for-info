import unittest
import json
import time
from brain import Brain
from knowledge_base import init_db, add_lesson, search_knowledge
from tools.registry import get_tool_schemas, get_tool_instance

class TestFramework(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_tool_registry(self):
        schemas = get_tool_schemas()
        tool_names = [s['function']['name'] for s in schemas]
        self.assertIn('nmap', tool_names)
        self.assertIn('web_inspector', tool_names)

        tool = get_tool_instance("web_inspector")
        self.assertIsNotNone(tool)

    def test_brain_mock_logic(self):
        brain = Brain()
        brain.enabled = False # Force mock

        context = {"target": "example.com", "history": []}
        decision = brain.think(context, "Test Mission")

        self.assertEqual(decision['status'], 'CONTINUE')
        self.assertEqual(decision['plan'][0]['tool'], 'nmap')

    def test_knowledge_base_search(self):
        add_lesson("test keywords", "Always check robots.txt", 1.0)
        results = search_knowledge("robots")
        self.assertTrue(len(results) > 0)
        self.assertIn("robots.txt", results[0]['content'])

if __name__ == '__main__':
    unittest.main()
