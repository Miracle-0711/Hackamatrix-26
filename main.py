

from agent import WebThreatAgent
import json


def main():
    print("=" * 50)
    print("       WEB THREAT DETECTION AI AGENT")
    print("=" * 50)

    agent = WebThreatAgent()

    while True:
        url = input("\nEnter website URL (or 'exit' to quit): ").strip()

        if url.lower() == "exit":
            print("AI Agent stopped.")
            break

        if not url:
            print("Please enter a website URL.")
            continue

        report = agent.investigate(url)

        print("\n-------------- INVESTIGATION REPORT ---------------")
        print(json.dumps(report, indent=4))
        print("-----------------------------------")


if __name__ == "__main__":
    main()





