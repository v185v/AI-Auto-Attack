from backend.scheduler.resource_quota import ResourceQuotaManager, ResourceQuotaSettings


def test_resource_quota_allows_and_clamps_parallelism() -> None:
    manager = ResourceQuotaManager(
        ResourceQuotaSettings(
            enabled=True,
            max_parallel_tasks=2,
            max_targets_per_run=10,
        )
    )
    decision = manager.check_run(target_count=3, requested_parallelism=5)
    assert decision.allowed is True
    assert decision.applied_parallelism == 2
    assert decision.clamped is True
    assert decision.reason == "parallelism_clamped"


def test_resource_quota_rejects_over_target_limit() -> None:
    manager = ResourceQuotaManager(
        ResourceQuotaSettings(
            enabled=True,
            max_parallel_tasks=2,
            max_targets_per_run=1,
        )
    )
    decision = manager.check_run(target_count=2, requested_parallelism=1)
    assert decision.allowed is False
    assert decision.reason == "targets_over_quota"


def test_resource_quota_can_be_disabled() -> None:
    manager = ResourceQuotaManager(
        ResourceQuotaSettings(
            enabled=False,
            max_parallel_tasks=2,
            max_targets_per_run=1,
        )
    )
    decision = manager.check_run(target_count=5, requested_parallelism=4)
    assert decision.allowed is True
    assert decision.reason == "quota_disabled"
    assert decision.applied_parallelism == 4
