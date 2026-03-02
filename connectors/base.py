from __future__ import annotations

from abc import ABC, abstractmethod
import subprocess
import time
from typing import Callable

from connectors.models import CommandExecution, ConnectorResult, PreparedCommand


CommandRunner = Callable[[list[str], int], CommandExecution]


def run_command(command: list[str], timeout_seconds: int) -> CommandExecution:
    start = time.time()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((time.time() - start) * 1000)
        return CommandExecution(
            command=command,
            return_code=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration_ms=duration_ms,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.time() - start) * 1000)
        return CommandExecution(
            command=command,
            return_code=124,
            stdout=(exc.stdout or ""),
            stderr=(exc.stderr or ""),
            duration_ms=duration_ms,
            timed_out=True,
            error=f"timeout_after_{timeout_seconds}s",
        )
    except FileNotFoundError:
        duration_ms = int((time.time() - start) * 1000)
        return CommandExecution(
            command=command,
            return_code=127,
            stdout="",
            stderr="",
            duration_ms=duration_ms,
            error="binary_not_found",
        )
    except Exception as exc:  # pragma: no cover - safety net
        duration_ms = int((time.time() - start) * 1000)
        return CommandExecution(
            command=command,
            return_code=1,
            stdout="",
            stderr="",
            duration_ms=duration_ms,
            error=str(exc),
        )


class ToolConnector(ABC):
    def __init__(
        self,
        *,
        tool_name: str,
        binary: str,
        timeout_seconds: int = 120,
        runner: CommandRunner | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.runner = runner or run_command

    @abstractmethod
    def prepare(self, target: str) -> PreparedCommand:
        raise NotImplementedError

    @abstractmethod
    def parse(self, execution: CommandExecution, prepared: PreparedCommand) -> dict:
        raise NotImplementedError

    def validate(self, parsed: dict) -> dict:
        return {"valid": True, "reason": "ok"}

    def extract_findings(self, parsed: dict) -> list[dict]:
        return list(parsed.get("findings", []))

    def execute(self, target: str) -> ConnectorResult:
        prepared = self.prepare(target)
        return self.execute_prepared(prepared)

    def execute_prepared(self, prepared: PreparedCommand) -> ConnectorResult:
        execution = self.runner(prepared.command, prepared.timeout_seconds)
        parsed = self.parse(execution, prepared)
        validation = self.validate(parsed)
        findings = self.extract_findings(parsed)

        status = "success"
        error = execution.error
        if execution.timed_out:
            status = "error"
            error = error or "timeout"
        elif execution.return_code != 0:
            status = "error"
            error = error or f"non_zero_exit:{execution.return_code}"
        elif not validation.get("valid", False):
            status = "error"
            error = str(validation.get("reason", "invalid_result"))

        return ConnectorResult(
            tool=prepared.tool,
            target=prepared.target,
            status=status,
            command=prepared.command,
            return_code=execution.return_code,
            duration_ms=execution.duration_ms,
            timed_out=execution.timed_out,
            parsed=parsed,
            findings=findings,
            validation=validation,
            error=error,
            stdout=execution.stdout,
            stderr=execution.stderr,
        )

