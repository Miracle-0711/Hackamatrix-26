import os
import time

import jwt


now = int(time.time())

token = jwt.encode(
    {
        "sub": "local-developer",
        "iss": "bouncer-auth",
        "aud": "bouncer-api",
        "iat": now,
        "exp": now + 3600,
        "scope": "scan:basic",
    },
    os.environ["JWT_SECRET"],
    algorithm="HS256",
)

print(token)
