
from semantic_analyzer import SemanticAnalyzer
import json

analyzer = SemanticAnalyzer()

test_messages = [
    {
        "type": "NORMAL MESSAGE",
        "text": "Hello! Your appointment is confirmed for tomorrow at 10 AM."
    },
    {
        "type": "SPAM MESSAGE",
        "text": "URGENT! You have won a free prize. Click this link immediately to claim your reward!"
    }
]

for message in test_messages:
    print("\n" + "=" * 50)
    print("TEST:", message["type"])
    print("=" * 50)

    result = analyzer.analyze_text(message["text"])
    print(json.dumps(result, indent=4))
