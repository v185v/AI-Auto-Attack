from connectors.models import CommandExecution
from connectors.nmap_connector import NmapConnector
from connectors.nuclei_connector import NucleiConnector
from connectors.scan_orchestrator import ScanOrchestrator
from connectors.zap_connector import ZapConnector
from backend.security.action_gate import ActionGate
from backend.security.approval_store import ApprovalStore


def test_nmap_nuclei_zap_connectors_parse_and_execute() -> None:
    def nmap_runner(command, timeout):
        return CommandExecution(
            command=command,
            return_code=0,
            stdout=(
                "Host is up (0.012s latency).\n"
                "80/tcp open http Apache httpd\n"
                "443/tcp open https nginx\n"
            ),
            stderr="",
            duration_ms=120,
        )

    def nuclei_runner(command, timeout):
        return CommandExecution(
            command=command,
            return_code=0,
            stdout=(
                '{"template-id":"cve-2021-0001","matched-at":"http://10.20.1.8","info":{"severity":"high"}}\n'
            ),
            stderr="",
            duration_ms=90,
        )

    def zap_runner(command, timeout):
        return CommandExecution(
            command=command,
            return_code=0,
            stdout="WARN: Missing security header\nFAIL: SQL Injection indicator",
            stderr="",
            duration_ms=200,
        )

    nmap = NmapConnector(binary="nmap", runner=nmap_runner)
    nuclei = NucleiConnector(binary="nuclei", runner=nuclei_runner)
    zap = ZapConnector(binary="zap.sh", runner=zap_runner)

    nmap_res = nmap.execute("10.20.1.8")
    nuclei_res = nuclei.execute("10.20.1.8")
    zap_res = zap.execute("10.20.1.8")

    assert nmap_res.status == "success"
    assert len(nmap_res.findings) == 2
    assert nuclei_res.status == "success"
    assert len(nuclei_res.findings) == 1
    assert zap_res.status == "success"
    assert len(zap_res.findings) >= 1


def test_scan_orchestrator_enforces_action_gate_allowlist() -> None:
    def ok_runner(command, timeout):
        return CommandExecution(
            command=command,
            return_code=0,
            stdout="",
            stderr="",
            duration_ms=50,
        )

    policy = {
        "command_allowlist": {
            "low_risk": ["nmap", "nuclei", "zap.sh"],
            "medium_risk": [],
            "high_risk": [],
        },
        "gates": {"require_approval_for_high_risk": True},
    }
    action_gate = ActionGate(policy=policy, approval_store=ApprovalStore())

    connectors = [
        NmapConnector(binary="nmap", runner=ok_runner),
        NucleiConnector(binary="nuclei", runner=ok_runner),
        ZapConnector(binary="zap.bat", runner=ok_runner),
    ]
    orchestrator = ScanOrchestrator(connectors=connectors, action_gate=action_gate)
    result = orchestrator.execute(target="10.20.1.8", requested_by="tester")

    assert result["executed_tools"] == 2
    assert result["blocked_tools"] == 1
    assert result["status"] == "completed"


def test_scan_orchestrator_selects_platform_strategy_branch() -> None:
    def ok_runner(command, timeout):
        return CommandExecution(
            command=command,
            return_code=0,
            stdout="80/tcp open http\n",
            stderr="",
            duration_ms=60,
        )

    policy = {
        "command_allowlist": {
            "low_risk": ["nmap", "nuclei", "zap.sh"],
            "medium_risk": [],
            "high_risk": [],
        },
        "gates": {"require_approval_for_high_risk": True},
    }
    action_gate = ActionGate(policy=policy, approval_store=ApprovalStore())
    connectors = [
        NmapConnector(binary="nmap", runner=ok_runner),
        NucleiConnector(binary="nuclei", runner=ok_runner),
        ZapConnector(binary="zap.sh", runner=ok_runner),
    ]
    orchestrator = ScanOrchestrator(connectors=connectors, action_gate=action_gate)

    windows_no_web = orchestrator.execute(
        target="10.20.1.9",
        requested_by="tester",
        strategy_hint="strategy_windows",
        target_profile={"os_guess": "windows", "open_ports": [445], "target_type": "ip"},
    )
    assert windows_no_web["strategy"]["key"] == "strategy_windows"
    assert windows_no_web["executed_tools"] == 1
    assert windows_no_web["skipped_tools"] == 2

    linux_with_web = orchestrator.execute(
        target="10.20.1.8",
        requested_by="tester",
        strategy_hint="strategy_linux",
        target_profile={"os_guess": "linux", "open_ports": [22, 80], "target_type": "ip"},
    )
    assert linux_with_web["strategy"]["key"] == "strategy_linux"
    assert linux_with_web["executed_tools"] == 3
    assert linux_with_web["skipped_tools"] == 0
