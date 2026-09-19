"""Dispatch tests for analysis.runner.start_analysis execution selection.

These cover the queue-vs-thread branching only: every branch that would do
real work (huey enqueue or a pipeline thread) is mocked, so the tests never
touch providers or the huey queue and stay deterministic and fast.
"""

import os
from unittest import mock

from django.test import TestCase, override_settings

from segments.scraping.discovery.models import ScanJob

from .runner import execute_analysis, start_analysis

_SQLITE_HUEY = {
    "name": "t",
    "huey_class": "huey.SqliteHuey",
    "connection": {},
    "consumer": {},
}
_NO_ASYNC_ENV = {"ECDAT_QUEUE_ASYNC": ""}


def _make_job(target="dispatch/app"):
    """Minimal completed job the dispatch path needs to create a run."""
    return ScanJob.objects.create(
        source_type="source_code",
        target=target,
        mode="actual",
        status="completed",
        config={"scan_type": "specified"},
    )


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
@override_settings(HUEY={**_SQLITE_HUEY, "immediate": False})
class StartAnalysisThreadDispatchTests(TestCase):
    """Plain conditions (no env var, non-immediate) run in-process on a thread."""

    def test_default_dispatches_to_daemon_execute_analysis_thread(self):
        with mock.patch.dict(os.environ, _NO_ASYNC_ENV, clear=False):
            with mock.patch("segments.ml.analysis.runner.run_analysis_task") as enqueue:
                with mock.patch("segments.ml.analysis.runner.threading.Thread") as thread:
                    job = _make_job()
                    run = start_analysis(job)

        enqueue.assert_not_called()
        thread.assert_called_once()
        call = thread.call_args
        self.assertIs(call.kwargs["target"], execute_analysis)
        self.assertIs(call.kwargs["daemon"], True)
        self.assertEqual(call.kwargs["args"], (run.pk, run.mode))
        thread.return_value.start.assert_called_once()
        self.assertEqual(run.status, "queued")
        self.assertEqual(run.session_id, job.session_id)

    def test_async_env_var_favours_huey_queue_over_thread(self):
        with mock.patch.dict(os.environ, {"ECDAT_QUEUE_ASYNC": "1"}, clear=False):
            with mock.patch("segments.ml.analysis.runner.run_analysis_task") as enqueue:
                with mock.patch("segments.ml.analysis.runner.threading.Thread") as thread:
                    job = _make_job()
                    run = start_analysis(job)

        enqueue.assert_called_once_with(run.pk, run.mode)
        thread.assert_not_called()


@override_settings(ECDAT={"DEMO_MODE": True, "ACTIVE_MODE": "actual"})
@override_settings(HUEY={**_SQLITE_HUEY, "immediate": True})
class StartAnalysisImmediateDispatchTests(TestCase):
    """Immediate huey mode runs the task inline via the wrapper, never a thread."""

    def test_immediate_mode_favours_huey_task_over_thread(self):
        with mock.patch.dict(os.environ, _NO_ASYNC_ENV, clear=False):
            with mock.patch("segments.ml.analysis.runner.run_analysis_task") as enqueue:
                with mock.patch("segments.ml.analysis.runner.threading.Thread") as thread:
                    job = _make_job()
                    run = start_analysis(job)

        enqueue.assert_called_once_with(run.pk, run.mode)
        thread.assert_not_called()
        self.assertEqual(run.status, "queued")
        self.assertEqual(run.session_id, job.session_id)