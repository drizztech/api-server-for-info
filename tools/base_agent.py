class BaseAgent:
    def __init__(self):
        pass

    def run(self, params):
        raise NotImplementedError("Subclasses must implement run()")
