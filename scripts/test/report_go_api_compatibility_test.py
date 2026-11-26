# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = os.path.join(os.path.dirname(__file__), "..", "report-go-api-compatibility.py")
SPEC = importlib.util.spec_from_file_location("report", SCRIPT)
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class FakeGitHub:
    def __init__(self, annotation, comments=None, current_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", conclusion="success"):
        self.annotation = annotation
        self.comments = comments or []
        self.current_sha = current_sha
        self.conclusion = conclusion
        self.writes = []

    def request(self, method, path, body=None):
        if path.endswith("/actions/workflows/7"):
            return {"path": report.SOURCE_WORKFLOW, "name": report.SOURCE_NAME}
        if path.endswith("/actions/runs/41/attempts/2/jobs?per_page=100&page=1"):
            return []
        if path.endswith("/actions/workflows/7"):
            return {"path": report.SOURCE_WORKFLOW, "name": report.SOURCE_NAME}
        if path.endswith("/pulls?state=open&head=contrib%3Atopic"):
            return [self.pull()]
        if path.endswith("/pulls/9"):
            pr = self.pull()
            pr["head"]["sha"] = self.current_sha
            return pr
        if method in ("POST", "PATCH"):
            self.writes.append((method, path, body))
            return {}
        raise AssertionError((method, path))

    def pages(self, path):
        if "/attempts/2/jobs" in path:
            return [{"name": report.JOB_NAME, "run_id": 41, "run_attempt": 2,
                     "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "conclusion": self.conclusion, "id": 88,
                     "check_run_url": "https://api.github.com/repos/x/check-runs/77"}]
        if "/check-runs/77/annotations" in path:
            return [] if self.annotation is None else [self.annotation]
        if "/issues/9/comments" in path:
            return self.comments
        raise AssertionError(path)

    @staticmethod
    def pull():
        return {"number": 9, "state": "open",
                "base": {"repo": {"full_name": report.REPOSITORY}},
                "head": {"repo": {"full_name": "contrib/repo"}, "ref": "topic", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}


class ReportTest(unittest.TestCase):
    def test_jobs_endpoint_object_is_paginated(self):
        github = report.GitHub("token")
        with patch.object(github, "request", return_value={"total_count": 1, "jobs": [{"id": 2}]}) as request:
            self.assertEqual(github.pages("/jobs"), [{"id": 2}])
            request.assert_called_once_with("GET", "/jobs?per_page=100&page=1")

    def run_helper(self, annotation, fake):
        event = {"workflow_run": {"id": 41, "workflow_id": 7, "run_attempt": 2,
                 "event": "pull_request", "repository": {"full_name": report.REPOSITORY},
                 "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "head_branch": "topic",
                 "head_repository": {"full_name": "contrib/repo", "owner": {"login": "contrib", "id": 2}}}}
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as file:
            json.dump(event, file)
            file.flush()
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": report.REPOSITORY, "GITHUB_TOKEN": "test"}), \
                    patch.object(report, "GitHub", return_value=fake), \
                    patch.object(report.sys, "argv", [SCRIPT, file.name]):
                self.assertEqual(report.main(), 0)

    def test_warning_escapes_untrusted_annotation_and_posts_marked_comment(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning",
                           "message": "removed `Thing`\n</pre>\n@everyone"})
        self.run_helper(fake.annotation, fake)
        self.assertEqual(len(fake.writes), 1)
        method, path, body = fake.writes[0]
        self.assertEqual((method, path), ("POST", f"/repos/{report.REPOSITORY}/issues/9/comments"))
        self.assertIn("&lt;/pre&gt;", body["body"])
        self.assertIn("&#64;everyone", body["body"])
        self.assertIn("/actions/runs/41/job/88", body["body"])

    def test_stale_head_does_not_post(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"}, current_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_clean_report_only_clears_existing_bot_comment(self):
        prior = {"id": 101, "body": report.MARKER + "\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "notice",
                           "message": "No incompatible API changes detected."}, comments=[prior])
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes[0][0:2], ("PATCH", f"/repos/{report.REPOSITORY}/issues/comments/101"))

    def test_clean_report_does_not_create_a_fresh_comment(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "notice",
                           "message": "No incompatible API changes detected."})
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_human_marker_is_not_updated(self):
        human = {"id": 101, "body": report.MARKER + "\nnot a bot",
                 "user": {"login": "someone", "type": "User"}}
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"}, comments=[human])
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes[0][0:2], ("POST", f"/repos/{report.REPOSITORY}/issues/9/comments"))

    def test_failed_or_missing_report_leaves_existing_comment_unchanged(self):
        prior = {"id": 101, "body": report.MARKER + "\nold", "user": {"login": "github-actions[bot]", "type": "Bot"}}
        for annotation, conclusion in ((None, "success"), ({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"}, "failure")):
            fake = FakeGitHub(annotation, comments=[prior], conclusion=conclusion)
            self.run_helper(annotation, fake)
            self.assertEqual(fake.writes, [])


if __name__ == "__main__":
    unittest.main()
