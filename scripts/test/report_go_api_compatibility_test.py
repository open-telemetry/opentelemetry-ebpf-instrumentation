# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = os.path.join(os.path.dirname(__file__), "..", "report-go-api-compatibility.py")
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
MERGE_SHA = "e" * 40
SPEC = importlib.util.spec_from_file_location("report", SCRIPT)
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class FakeGitHub:
    def __init__(self, annotation, comments=None, current_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", conclusion="success", additional_annotations=None):
        self.annotation = annotation
        self.additional_annotations = additional_annotations or []
        self.comments = comments or []
        self.current_sha = current_sha
        self.conclusion = conclusion
        self.writes = []
        self.base_sha = BASE_SHA
        self.base_ref = "main"
        self.base_lookups = 0
        self.advance_base_after_first_lookup = False
        self.open_fork_prs = [self.pull(), self.pull(number=10, base_ref="release-1.0")]
        self.pr_reads = []

    def request(self, method, path, body=None):
        if path.endswith("/actions/workflows/7"):
            return {"path": report.SOURCE_WORKFLOW, "name": report.SOURCE_NAME}
        if path.endswith("/actions/runs/41/attempts/2/jobs?per_page=100&page=1"):
            return []
        if path.endswith("/actions/workflows/7"):
            return {"path": report.SOURCE_WORKFLOW, "name": report.SOURCE_NAME}
        if "/pulls/" in path:
            number = int(path.rsplit("/", 1)[1])
            self.pr_reads.append(number)
            pr = next((item for item in self.open_fork_prs if item["number"] == number), None)
            if pr is None:
                raise AssertionError(path)
            pr = dict(pr)
            pr["base"] = dict(pr["base"])
            pr["head"] = dict(pr["head"])
            pr["head"]["sha"] = self.current_sha
            return pr
        if "/git/ref/heads/" in path:
            self.base_lookups += 1
            if self.advance_base_after_first_lookup and self.base_lookups > 1:
                return {"object": {"sha": "c" * 40}}
            return {"object": {"sha": self.base_sha}}
        if path.endswith("/git/commits/" + MERGE_SHA):
            return {"parents": [{"sha": BASE_SHA}, {"sha": HEAD_SHA}]}
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
            return ([] if self.annotation is None else [self.annotation]) + self.additional_annotations + [
                {"title": report.IDENTITY_TITLE, "annotation_level": "notice",
                 "message": json.dumps({"pr": "9", "base_ref": "main", "base_sha": BASE_SHA,
                                        "head_sha": HEAD_SHA, "merge_sha": MERGE_SHA})}
            ]
        if "/issues/9/comments" in path:
            return self.comments
        raise AssertionError(path)

    def pull(self, number=9, base_ref=None):
        return {"number": number, "state": "open",
                "base": {"repo": {"full_name": report.REPOSITORY}, "ref": base_ref or self.base_ref, "sha": BASE_SHA},
                "merge_commit_sha": MERGE_SHA,
                "head": {"repo": {"full_name": "contrib/repo"}, "ref": "topic", "sha": HEAD_SHA}}


class ReportTest(unittest.TestCase):
    def test_pinned_apidiff_separates_additions_from_interface_breaks(self):
        repository = pathlib.Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            base, head = root / "base", root / "head"
            for checkout in (base, head):
                (checkout / "api").mkdir(parents=True)
                (checkout / "go.mod").write_text("module go.opentelemetry.io/obi\n\ngo 1.24\n", encoding="utf-8")
            (base / "api/api.go").write_text(
                "package api\ntype Handler interface { Handle() }\nfunc Existing() {}\n", encoding="utf-8"
            )
            (head / "api/api.go").write_text(
                "package api\ntype Handler interface { Handle(); Added() }\n"
                "func Existing() {}\nfunc Added() {}\n", encoding="utf-8"
            )
            (head / "newpkg").mkdir()
            (head / "newpkg/new.go").write_text("package newpkg\nfunc New() {}\n", encoding="utf-8")
            for checkout, subject in ((base, "base"), (head, "head")):
                subprocess.run(["git", "init", "-q", str(checkout)], check=True)
                subprocess.run(["git", "-C", str(checkout), "config", "user.email", "test@example.com"], check=True)
                subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Test"], check=True)
                subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
                subprocess.run(["git", "-C", str(checkout), "commit", "-qm", subject], check=True)
            summary = root / "summary.md"
            result = subprocess.run(
                ["bash", str(repository / "scripts/check-go-api-compatibility.sh"), str(base), str(head)],
                env=dict(os.environ, GITHUB_STEP_SUMMARY=str(summary), COMPARISON_PR_NUMBER="9",
                         COMPARISON_BASE_REF="main", COMPARISON_HEAD_SHA="a" * 40),
                capture_output=True, text=True, check=True,
            )
            identity_line = next(line for line in result.stdout.splitlines()
                                 if line.startswith("::notice title=obi-go-api-comparison-identity::"))
            identity = json.loads(identity_line.split("::", 2)[2])
            self.assertEqual(identity["pr"], "9")
            self.assertEqual(identity["base_ref"], "main")
            self.assertEqual(identity["base_sha"], subprocess.check_output(
                ["git", "-C", str(base), "rev-parse", "HEAD"], text=True).strip())
            self.assertEqual(identity["merge_sha"], subprocess.check_output(
                ["git", "-C", str(head), "rev-parse", "HEAD"], text=True).strip())
            self.assertIn("::notice title=obi-go-api-additions-report::", result.stdout)
            self.assertIn("::warning title=obi-go-api-compatibility-report::", result.stdout)
            self.assertIn("### Public API additions", summary.read_text(encoding="utf-8"))
            self.assertIn("### Potential incompatibilities", summary.read_text(encoding="utf-8"))
            self.assertIn("- Added: added", result.stdout)
            self.assertIn("- Handler.Added: added", result.stdout)

    def test_jobs_endpoint_object_is_paginated(self):
        github = report.GitHub("token")
        with patch.object(github, "request", return_value={"total_count": 1, "jobs": [{"id": 2}]}) as request:
            self.assertEqual(github.pages("/jobs"), [{"id": 2}])
            request.assert_called_once_with("GET", "/jobs?per_page=100&page=1")

    def run_helper(self, annotation, fake, pull_requests=None):
        event = {"workflow_run": {"id": 41, "workflow_id": 7, "run_attempt": 2,
                 "event": "pull_request", "repository": {"full_name": report.REPOSITORY},
                 "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "head_branch": "topic",
                 "head_repository": {"full_name": "contrib/repo", "owner": {"login": "contrib", "id": 2}},
                 "pull_requests": []}}
        if pull_requests is not None:
            event["workflow_run"]["pull_requests"] = pull_requests
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
        self.assertEqual(fake.pr_reads, [9, 9])
        self.assertEqual([pr["base"]["ref"] for pr in fake.open_fork_prs], ["main", "release-1.0"])
        self.assertEqual([(pr["head"]["ref"], pr["head"]["sha"]) for pr in fake.open_fork_prs],
                         [("topic", HEAD_SHA), ("topic", HEAD_SHA)])

    def test_additions_only_posts_informational_comment(self):
        fake = FakeGitHub(
            {"title": report.REPORT_TITLE, "annotation_level": "notice",
             "message": "No incompatible API changes detected."},
            additional_annotations=[{"title": report.ADDITIONS_TITLE, "annotation_level": "notice",
                                    "message": "pkg: func New added"}],
        )
        self.run_helper(fake.annotation, fake)
        self.assertEqual(len(fake.writes), 1)
        body = fake.writes[0][2]["body"]
        self.assertIn("### Public API additions", body)
        self.assertNotIn("### Potential breaking", body)

    def test_mixed_report_keeps_break_warning_and_additions_separate(self):
        fake = FakeGitHub(
            {"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "method added to interface"},
            additional_annotations=[{"title": report.ADDITIONS_TITLE, "annotation_level": "notice",
                                    "message": "pkg: func New added"}],
        )
        self.run_helper(fake.annotation, fake)
        body = fake.writes[0][2]["body"]
        self.assertLess(body.index("### Public API additions"), body.index("### Potential breaking"))
        self.assertIn("method added to interface", body)

    def test_addition_title_requires_notice_level(self):
        base = {"title": report.REPORT_TITLE, "annotation_level": "notice",
                "message": "No incompatible API changes detected."}
        fake = FakeGitHub(
            base,
            additional_annotations=[{"title": report.ADDITIONS_TITLE, "annotation_level": "warning",
                                    "message": "pkg: func New added"}],
        )
        self.run_helper(base, fake)
        self.assertEqual(fake.writes, [])

    def test_stale_head_does_not_post(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"}, current_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_stale_base_with_same_head_does_not_post(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"})
        fake.base_sha = "d" * 40
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_base_retarget_does_not_post(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"})
        fake.base_ref = "release-1.0"
        fake.open_fork_prs[0]["base"]["ref"] = fake.base_ref
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_base_advance_between_lookup_and_write_does_not_post(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"})
        fake.advance_base_after_first_lookup = True
        self.run_helper(fake.annotation, fake)
        self.assertEqual(fake.writes, [])

    def test_workflow_run_pull_request_metadata_must_match_identity(self):
        fake = FakeGitHub({"title": report.REPORT_TITLE, "annotation_level": "warning", "message": "API break"})
        metadata = [{"number": 10, "base": {"ref": "release-1.0"},
                     "head": {"ref": "topic", "sha": HEAD_SHA}}]
        self.run_helper(fake.annotation, fake, metadata)
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
