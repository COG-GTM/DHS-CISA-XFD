"""Test scheduler."""
# Standard Python Libraries
from datetime import timedelta
from unittest.mock import MagicMock, patch

# Third-Party Libraries
from django.utils import timezone
import pytest
from xfd_api.models import Organization, Scan, ScanTask
from xfd_api.schema_models.scan import SCAN_SCHEMA
from xfd_api.tasks.scheduler import Scheduler, handler


@pytest.fixture
def org():
    """Org fixture."""
    return Organization.objects.create(
        name="org1",
        rootDomains=["example.com"],
        ipBlocks=["192.168.0.0/24"],
    )


@pytest.fixture(autouse=True)
def patch_boto3_client():
    """Mock SQS."""
    with patch("xfd_api.tasks.scheduler.boto3.client") as mock_boto3_client:
        mock_sqs = MagicMock()
        mock_boto3_client.return_value = mock_sqs
        mock_sqs.create_queue.return_value = {"QueueUrl": "https://mock-sqs-url"}
        mock_sqs.send_message_batch.return_value = {}
        yield


@pytest.mark.django_db
def test_scheduler_skips_when_no_organizations():
    """Test scheduler skips when no organizations."""
    scan = Scan.objects.create(name="censys", concurrent_tasks=2, frequency=1)
    scheduler = Scheduler()
    scheduler.initialize([scan], [])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        scheduler.run()
        mock_exec.assert_not_called()


@pytest.mark.django_db
def test_manual_run_pending_forces_execution(org):
    """Test manual run pending forces execution."""
    scan = Scan.objects.create(
        name="censys", concurrent_tasks=1, frequency=1, manualRunPending=True
    )
    scheduler = Scheduler()
    scheduler.initialize([scan], [org])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        mock_exec.return_value = {"statusCode": 200}
        scheduler.run()
        mock_exec.assert_called_once()


@pytest.mark.django_db
def test_scheduler_respects_frequency_window(org):
    """Test scheduler respects frequency."""
    scan = Scan.objects.create(
        name="censys",
        concurrent_tasks=1,
        frequency=1,
        lastRun=timezone.now() - timedelta(hours=12),
    )
    scheduler = Scheduler()
    scheduler.initialize([scan], [org])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        scheduler.run()
        mock_exec.assert_not_called()


@pytest.mark.django_db
def test_global_scan_triggers_single_execution(org):
    """Test global scan triggers single execution."""
    SCAN_SCHEMA["censys"].global_scan = True
    scan = Scan.objects.create(name="censys", concurrent_tasks=5, frequency=1)
    scheduler = Scheduler()
    scheduler.initialize([scan], [org])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        mock_exec.return_value = {"statusCode": 200}
        scheduler.run()
        mock_exec.assert_called_once()
        args, _ = mock_exec.call_args
        assert args[0]["desiredCount"] == 1  # forced single for global


@pytest.mark.django_db
def test_scan_skips_if_recent_task_running(org):
    """Test scan skips if recent task running."""
    scan = Scan.objects.create(name="censys", concurrent_tasks=1, frequency=1)
    ScanTask.objects.create(
        scan=scan,
        status="started",
    ).organizations.set([org])

    scheduler = Scheduler()
    scheduler.initialize([scan], [org])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        scheduler.run()
        mock_exec.assert_not_called()


@pytest.mark.django_db
def test_scan_skips_if_single_scan_and_already_finished(org):
    """Test scan skips if single scan and already finished."""
    scan = Scan.objects.create(
        name="censys", concurrent_tasks=1, frequency=1, isSingleScan=True
    )
    ScanTask.objects.create(
        scan=scan,
        status="finished",
        finishedAt=timezone.now() - timedelta(days=1),
    ).organizations.set([org])

    scheduler = Scheduler()
    scheduler.initialize([scan], [org])

    with patch("xfd_api.tasks.scheduler.scan_execution_handler") as mock_exec:
        scheduler.run()
        mock_exec.assert_not_called()


@pytest.mark.django_db
def test_handler_filters_scan_and_org_ids(org):
    """Test handler filters scan and org ids."""
    scan = Scan.objects.create(name="censys", concurrent_tasks=1, frequency=1)

    with patch("xfd_api.tasks.scheduler.Scheduler.run") as mock_run:
        handler(
            {
                "scanIds": [str(scan.id)],
                "organizationIds": [str(org.id)],
            },
            None,
        )
        mock_run.assert_called_once()
