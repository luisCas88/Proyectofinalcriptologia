"""Cliente HTTP mínimo hacia el servidor."""
import requests


class ApiError(Exception):
    pass


class Api:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.token: str | None = None

    def _call(self, method: str, path: str, **kw):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        r = requests.request(method, self.base + path, headers=headers, timeout=15, **kw)
        if r.status_code >= 400:
            raise ApiError(f"{r.status_code}: {r.json().get('detail', r.text)}")
        return r.json()

    def register(self, username, password, bundle: dict):
        return self._call("POST", "/register", json={"username": username, "password": password, "bundle": bundle})

    def login(self, username, password):
        self.token = self._call("POST", "/login", json={"username": username, "password": password})["token"]

    def get_bundle(self, username) -> dict:
        return self._call("GET", f"/bundle/{username}")

    def send(self, to, init, n, ciphertext):
        return self._call("POST", "/messages", json={"to": to, "init": init, "n": n, "ciphertext": ciphertext})

    def fetch(self) -> list:
        return self._call("GET", "/messages")
