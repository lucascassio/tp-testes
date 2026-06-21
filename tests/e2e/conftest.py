"""End-to-end test fixtures — real uvicorn server."""
import socket
import threading
import time

import pytest
import uvicorn
import httpx

from app.main import app


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server():
    port = _get_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(0.5)

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=3)
