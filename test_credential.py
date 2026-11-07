from tools.credential_inspector import inspect_html
import json

html = """
<form action="https://other-site.com/login">
    <input type="password" name="password">
    <input type="text" name="otp">
</form>
"""

result = inspect_html("https://example.com", html)

print(json.dumps(result, indent=4))