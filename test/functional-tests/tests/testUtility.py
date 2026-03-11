##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

"""
Shared constants, fixtures, and helper functions for crashupload functional tests.

Import what you need:
    from testUtility import (
        cleanup_pytest_cache, binary_path,
        DEFAULT_LOG_PATH, CORE_LOG_FILE,
        MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE,
        SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH,
        NO_DUMPS_FOUND, REBOOT_FLAG_FILE,
        create_dummy_dump, hold_lock_and_release, wait_for_path,
    )

Pytest fixtures (cleanup_pytest_cache, binary_path) are discovered by pytest when
imported into a test module's global namespace.
"""

import os
import shutil
import time
import fcntl
import threading
import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants mirroring the C source
# ---------------------------------------------------------------------------

# Default log path used by config_manager.c when LOG_PATH property is absent
DEFAULT_LOG_PATH     = "/opt/logs"

# core_log_file = {log_path}/core_log.txt — must exist for system_initialize() to pass
CORE_LOG_FILE        = f"{DEFAULT_LOG_PATH}/core_log.txt"

# Lock files created/removed by main.c and lock_manager.c
MINIDUMP_LOCK_FILE   = "/tmp/.uploadMinidumps"
COREDUMP_LOCK_FILE   = "/tmp/.uploadCoredumps"

# Dump directory paths resolved by config_init_load() (config_manager.c)
# When argv[3] == "secure":  minidump → /opt/secure/minidumps
#                             coredump → /opt/secure/corefiles
# When argv[3] is absent:    minidump → /opt/minidumps
#                             coredump → /var/lib/systemd/coredump
SECURE_MINIDUMP_PATH = "/opt/secure/minidumps"
SECURE_COREDUMP_PATH = "/opt/secure/corefiles"

# NO_DUMPS_FOUND exit path: prerequisites_wait() returns 5 → goto cleanup → exit(0)
NO_DUMPS_FOUND       = 5

# Reboot flag checked by is_box_rebooting() in system_utils.c
REBOOT_FLAG_FILE     = "/tmp/set_crash_reboot_flag"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def cleanup_pytest_cache():
    """Remove __pycache__ directories created by pytest after the session."""
    yield
    for cache_dir in Path(__file__).parent.rglob("__pycache__"):
        shutil.rmtree(cache_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def binary_path():
    """Return path to the crashupload binary; skip if CRASHUPLOAD_BINARY is unset."""
    path = os.environ.get("CRASHUPLOAD_BINARY", "")
    if not path or not os.path.isfile(path):
        pytest.skip("CRASHUPLOAD_BINARY not set or binary not found")
    return path


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def create_dummy_dump(dump_dir: str, name: str, size_kb: int = 4) -> str:
    """
    Create a minimal dummy dump file and return its absolute path.

    The file consists of a recognisable header (b'MINIDUMP_HEADER') followed
    by zero-padded content.  The caller is responsible for cleanup.
    """
    os.makedirs(dump_dir, exist_ok=True)
    path = os.path.join(dump_dir, name)
    with open(path, "wb") as fh:
        fh.write(b"MINIDUMP_HEADER")
        fh.write(b"\x00" * (size_kb * 1024))
    assert os.path.exists(path), f"Failed to create dump file {path}"
    assert os.path.getsize(path) > 0, f"Dump file {path} has zero size"
    return path


def hold_lock_and_release(
    lock_file_path: str,
    duration_sec: float,
    lock_acquired_event: threading.Event,
) -> None:
    """
    Hold an exclusive flock on *lock_file_path* for *duration_sec* seconds,
    then release it.

    Intended to run in a daemon thread to simulate a concurrent crashupload
    instance.  Sets *lock_acquired_event* once the lock is held (or if it
    cannot be acquired) so the calling test can proceed without busy-waiting.

    File-descriptor lifecycle:
      open(O_CREAT|O_RDWR) → flock(LOCK_EX|LOCK_NB) → sleep → flock(LOCK_UN)
      → close in finally block.
    """
    lock_fd = None
    try:
        lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(f"[Thread] Lock acquired on {lock_file_path}")
        lock_acquired_event.set()
        print(f"[Thread] Holding lock for {duration_sec} seconds...")
        time.sleep(duration_sec)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        print(f"[Thread] Lock released on {lock_file_path}")
    except BlockingIOError:
        print(f"[Thread] Could not acquire lock on {lock_file_path} — already locked")
        lock_acquired_event.set()
    except Exception as exc:
        print(f"[Thread] Error in lock thread: {exc}")
        lock_acquired_event.set()
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


def wait_for_path(path: str, present: bool, timeout: float = 10.0) -> bool:
    """
    Poll until *path* exists (present=True) or is absent (present=False).

    Returns True when the condition is satisfied within *timeout* seconds,
    False otherwise.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path) == present:
            return True
        time.sleep(0.1)
    return os.path.exists(path) == present
