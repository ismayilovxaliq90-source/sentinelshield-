import time

from sentinelshield.watch_agent import (
    WatchAgent,
    WatchAgentStatus,
)


def test_agent_starts(tmp_path):
    calls = []

    agent = WatchAgent(
        tmp_path,
        lambda: calls.append(1),
        interval=0.01,
    )

    status = agent.start()

    assert isinstance(status, WatchAgentStatus)

    time.sleep(0.05)

    status = agent.status()

    assert status.running is True
    assert status.cycles >= 1

    agent.stop()


def test_agent_stops(tmp_path):
    calls = []

    agent = WatchAgent(
        tmp_path,
        lambda: calls.append(1),
        interval=0.01,
    )

    agent.start()
    time.sleep(0.03)

    status = agent.stop()

    assert status.running is False


def test_agent_performs_repeated_checks(tmp_path):
    calls = []

    agent = WatchAgent(
        tmp_path,
        lambda: calls.append(time.monotonic()),
        interval=0.01,
    )

    agent.start()

    time.sleep(0.08)

    agent.stop()

    assert len(calls) >= 2


def test_agent_start_is_idempotent(tmp_path):
    calls = []

    agent = WatchAgent(
        tmp_path,
        lambda: calls.append(1),
        interval=0.01,
    )

    agent.start()
    first = agent._thread

    agent.start()
    second = agent._thread

    agent.stop()

    assert first is second


def test_agent_status_initially_stopped(tmp_path):
    agent = WatchAgent(
        tmp_path,
        lambda: None,
    )

    status = agent.status()

    assert status.running is False
    assert status.cycles == 0


def test_agent_does_not_modify_project(tmp_path):
    marker = tmp_path / "main.py"

    marker.write_text(
        "print('test')\n",
        encoding="utf-8",
    )

    before = marker.read_text(
        encoding="utf-8",
    )

    agent = WatchAgent(
        tmp_path,
        lambda: None,
        interval=0.01,
    )

    agent.start()
    time.sleep(0.03)
    agent.stop()

    after = marker.read_text(
        encoding="utf-8",
    )

    assert before == after


def test_agent_uses_daemon_thread(tmp_path):
    agent = WatchAgent(
        tmp_path,
        lambda: None,
        interval=0.01,
    )

    agent.start()

    assert agent._thread is not None
    assert agent._thread.daemon is True

    agent.stop()


def test_agent_accepts_path_objects(tmp_path):
    agent = WatchAgent(
        tmp_path,
        lambda: None,
        interval=0.01,
    )

    status = agent.start()

    assert status.running is True

    agent.stop()
