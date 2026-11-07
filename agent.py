
from librarian import Librarian


class WebThreatAgent:

    def __init__(self):
        print("\n[AI Agent] Initializing Web Threat Detection Agent...")

        self.librarian = Librarian()

        print("[AI Agent] Librarian connected successfully!")
        print("[AI Agent] Agent is ready.")

    def investigate(self, url):
        print("\n[AI Agent] Starting website investigation...")

        result = self.librarian.inspect_website(url)

        print("[AI Agent] Librarian inspection completed.")

        return result
