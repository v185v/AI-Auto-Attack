from agents.target_profiler import TargetProfiler


def test_target_profiler_detects_windows_from_ports_and_services() -> None:
    profiler = TargetProfiler()
    profile = profiler.profile(
        target="10.20.1.9",
        scan={
            "tool_results": [
                {
                    "parsed": {
                        "open_ports": [
                            {"port": 445, "service": "microsoft-ds"},
                            {"port": 3389, "service": "ms-wbt-server"},
                        ]
                    }
                }
            ],
            "findings": [],
        },
    )
    assert profile["os_guess"] == "windows"
    assert profile["os_confidence"] >= 0.6
    assert profile["strategy_hint"] == "strategy_windows"


def test_target_profiler_detects_linux_from_ssh_signal() -> None:
    profiler = TargetProfiler()
    profile = profiler.profile(
        target="192.168.56.10",
        scan={
            "tool_results": [
                {
                    "parsed": {
                        "open_ports": [
                            {"port": 22, "service": "ssh"},
                            {"port": 80, "service": "http"},
                        ]
                    }
                }
            ],
            "findings": [],
        },
    )
    assert profile["os_guess"] == "linux"
    assert profile["os_confidence"] >= 0.6
    assert profile["strategy_hint"] == "strategy_linux"


def test_target_profiler_returns_unknown_without_signals() -> None:
    profiler = TargetProfiler()
    profile = profiler.profile(target="https://example.com", scan={"tool_results": [], "findings": []})
    assert profile["target_type"] == "url"
    assert profile["os_guess"] == "unknown"
    assert profile["strategy_hint"] == "strategy_generic"
