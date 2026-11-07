
from brand_mismatch import inspect_brand
import json


result1 = inspect_brand(
    "https://google.com",
    "google"
)


result2 = inspect_brand(
    "https://g00gle-login.com",
    "google"
)

print("TEST 1: Official Website")
print(json.dumps(result1, indent=4))

print("\nTEST 2: Suspicious Website")
print(json.dumps(result2, indent=4))
