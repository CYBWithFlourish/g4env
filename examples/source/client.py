"""A small client that talks to a third party API.

The headers below are hardcoded, which is what the
``env.hardcoded-auth-header`` rule reports.
"""

import urllib.request

PARTNER_API_KEY = "8Kd2mQp7LxR4vNc9TbW1yZf6HjA3sE5g"

HEADERS = {
    "Authorization": "Bearer b7Qk4Mz9Xp2Lv6Rt1Wn8Cy3Hd5Jf0Sa",
    "X-Api-Key": "c9Tr7Yw2Kq5Mn8Bp4Vx1Lr9Zt6Hd3Jf0",
}


def fetch(url: str) -> bytes:
    """Fetch ``url`` with the hardcoded credentials."""
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request) as response:
        return response.read()
