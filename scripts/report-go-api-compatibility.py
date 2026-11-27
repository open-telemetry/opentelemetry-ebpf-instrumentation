#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Post a sticky pull request comment from a trusted workflow_run context."""

import json
import html
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "open-telemetry/opentelemetry-ebpf-instrumentation"
SOURCE_WORKFLOW = ".github/workflows/pull_request.yml"
SOURCE_NAME = "PR checks"
JOB_NAME = "Public Go API compatibility (report only)"
REPORT_TITLE = "obi-go-api-compatibility-report"
ADDITIONS_TITLE = "obi-go-api-additions-report"
IDENTITY_TITLE = "obi-go-api-comparison-identity"
MARKER = "<!-- obi-go-api-compatibility -->"
MAX_REPORT = 3000


class GitHub:
    def __init__(self, token):
        self.token = token

    def request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request) as response:
            payload = response.read()
            return json.loads(payload) if payload else None

    def pages(self, path):
        result = []
        page = 1
        while True:
            separator = "&" if "?" in path else "?"
            batch = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            items = batch.get("jobs", []) if isinstance(batch, dict) else batch
            result.extend(items)
            if len(items) < 100:
                return result
            page += 1


def fail(message):
    print(message, file=sys.stderr)
    return 1


def read_report(gh, run):
    jobs = gh.pages(f"/repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs")
    matching = [
        job for job in jobs
        if job.get("name") == JOB_NAME
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("head_sha") == run["head_sha"]
    ]
    if len(matching) != 1 or matching[0].get("conclusion") != "success":
        return None
    job = matching[0]
    check_run_id = job.get("check_run_url", "").rsplit("/", 1)[-1]
    if not check_run_id.isdecimal() or not str(job.get("id", "")).isdecimal():
        return None
    annotations = gh.pages(f"/repos/{REPOSITORY}/check-runs/{check_run_id}/annotations")
    reports = [annotation for annotation in annotations if annotation.get("title") in (REPORT_TITLE, ADDITIONS_TITLE, IDENTITY_TITLE)]
    compatibility = [annotation for annotation in reports if annotation.get("title") == REPORT_TITLE]
    additions = [annotation for annotation in reports if annotation.get("title") == ADDITIONS_TITLE]
    identities = [annotation for annotation in reports if annotation.get("title") == IDENTITY_TITLE]
    if len(compatibility) != 1 or len(additions) > 1 or len(identities) != 1:
        return None
    annotation = compatibility[0]
    if annotation.get("annotation_level") not in ("warning", "notice"):
        return None
    message = annotation.get("message", "")
    if not isinstance(message, str) or len(message.encode("utf-8")) > MAX_REPORT:
        return None
    incompatible = annotation["annotation_level"] == "warning"
    if (incompatible and not message.strip()) or (not incompatible and message != "No incompatible API changes detected."):
        return None
    addition_message = None
    if additions:
        addition = additions[0]
        addition_message = addition.get("message", "")
        if (addition.get("annotation_level") != "notice" or not isinstance(addition_message, str)
                or not addition_message.strip() or len(addition_message.encode("utf-8")) > MAX_REPORT):
            return None
    identity = identities[0]
    identity_message = identity.get("message", "")
    if identity.get("annotation_level") != "notice" or not isinstance(identity_message, str) or len(identity_message) > 512:
        return None
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate comparison identity field")
            result[key] = value
        return result

    fields = json.loads(identity_message, object_pairs_hook=unique_object)
    if (not isinstance(fields, dict) or set(fields) != {"pr", "base_ref", "base_sha", "head_sha", "merge_sha"}
            or not isinstance(fields["pr"], str) or not fields["pr"].isdecimal() or int(fields["pr"]) <= 0
            or not isinstance(fields["base_ref"], str) or not fields["base_ref"]
            or any(not isinstance(fields[key], str) or len(fields[key]) != 40
                   or any(c not in "0123456789abcdef" for c in fields[key])
                   for key in ("base_sha", "head_sha", "merge_sha"))):
        return None
    return (message if incompatible else None), addition_message, job, fields


def find_current_pr(run, identity):
    head_repo = run.get("head_repository") or {}
    head_owner = (head_repo.get("owner") or {}).get("login")
    head_ref = run.get("head_branch")
    if (not head_owner or not head_ref or not head_repo.get("full_name")
            or head_repo["full_name"].split("/", 1)[0].casefold() != head_owner.casefold()):
        return None
    pr_number = int(identity["pr"])
    if run.get("head_sha") != identity["head_sha"]:
        return None
    if "pull_requests" in run:
        metadata = run["pull_requests"]
        if not isinstance(metadata, list):
            return None
        if metadata and not any(
            isinstance(item, dict)
            and item.get("number") == pr_number
            and isinstance(item.get("base"), dict)
            and item["base"].get("ref") == identity["base_ref"]
            and isinstance(item.get("head"), dict)
            and item["head"].get("ref") == head_ref
            and item["head"].get("sha") == identity["head_sha"]
            for item in metadata
        ):
            return None
    return (pr_number, head_repo, head_ref, identity)


def current_pull_request(gh, selected):
    number, head_repo, head_ref, identity = selected
    latest = gh.request("GET", f"/repos/{REPOSITORY}/pulls/{number}")
    ref = urllib.parse.quote(identity["base_ref"], safe="")
    base_tip = gh.request("GET", f"/repos/{REPOSITORY}/git/ref/heads/{ref}")
    merge = gh.request("GET", f"/repos/{REPOSITORY}/git/commits/{identity['merge_sha']}")
    parents = [parent.get("sha") for parent in merge.get("parents", []) if isinstance(parent, dict)]
    return (
        latest.get("number") == number and latest.get("state") == "open"
        and latest.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY
        and latest.get("base", {}).get("ref") == identity["base_ref"]
        and latest.get("head", {}).get("repo", {}).get("full_name") == head_repo.get("full_name")
        and latest.get("head", {}).get("ref") == head_ref
        and latest.get("head", {}).get("sha") == identity["head_sha"]
        and base_tip.get("object", {}).get("sha") == identity["base_sha"]
        and latest.get("merge_commit_sha") == identity["merge_sha"]
        and parents == [identity["base_sha"], identity["head_sha"]]
    )


def main():
    if len(sys.argv) != 2:
        return fail("usage: report-go-api-compatibility.py <workflow_run event.json>")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if repository != REPOSITORY or not token:
        return fail("unexpected repository or missing GitHub token")

    with open(sys.argv[1], encoding="utf-8") as event_file:
        event = json.load(event_file)
    run = event.get("workflow_run", {})
    if run.get("event") != "pull_request" or run.get("repository", {}).get("full_name") != REPOSITORY:
        return 0
    if (
        not str(run.get("id", "")).isdecimal()
        or not str(run.get("workflow_id", "")).isdecimal()
        or not str(run.get("run_attempt", "")).isdecimal()
        or len(run.get("head_sha", "")) != 40
        or any(character not in "0123456789abcdef" for character in run.get("head_sha", ""))
    ):
        return fail("workflow_run event is missing run identity")

    gh = GitHub(token)
    workflow = gh.request("GET", f"/repos/{REPOSITORY}/actions/workflows/{run.get('workflow_id')}")
    if workflow.get("path") != SOURCE_WORKFLOW or workflow.get("name") != SOURCE_NAME:
        return 0
    report = read_report(gh, run)
    selected_pr = find_current_pr(run, report[3]) if report else None
    if not selected_pr:
        return 0
    incompatible_message, additions_message, job, _ = report
    pr_number, head_repo, head_ref, identity = selected_pr
    if not current_pull_request(gh, selected_pr):
        return 0
    issue_path = f"/repos/{REPOSITORY}/issues/{pr_number}/comments"
    existing = [
        comment for comment in gh.pages(issue_path)
        if comment.get("body", "").startswith(MARKER)
        and comment.get("user", {}).get("login") == "github-actions[bot]"
        and comment.get("user", {}).get("type") == "Bot"
    ]
    if len(existing) > 1:
        return fail("multiple bot marker comments found; refusing to update")
    if incompatible_message or additions_message:
        sections = [MARKER + "\n"]
        if additions_message:
            sections.extend([
                "### Public API additions\n\n",
                "These additions are informational. Check whether each one is intended to be public.\n\n",
                "<details><summary>Added API</summary>\n\n<pre>" + html.escape(additions_message, quote=True).replace("@", "&#64;") + "</pre>\n\n</details>\n",
            ])
        if incompatible_message:
            sections.extend([
                "### Potential breaking Go API changes\n\n",
                "The report-only check found potential incompatible changes in publicly importable "
                "root-module packages. This is a warning for review, not a definitive compatibility "
                "guarantee. OBI's stable Go API follows source-level compatibility rules; breaking "
                "changes require a major release.\n\n",
                "<details><summary>Comparison details</summary>\n\n"
                "<pre>" + html.escape(incompatible_message, quote=True).replace("@", "&#64;") + "</pre>\n\n</details>\n",
            ])
        sections.extend([
            f"[View the completed check run](https://github.com/{REPOSITORY}/actions/runs/{run['id']}/job/{job['id']})\n",
            "<!-- /obi-go-api-compatibility -->",
        ])
        body = "".join(sections)
        if existing and existing[0].get("body") == body:
            return 0
        if not current_pull_request(gh, selected_pr):
            return 0
        if existing:
            gh.request("PATCH", f"/repos/{REPOSITORY}/issues/comments/{existing[0]['id']}", {"body": body})
        else:
            gh.request("POST", issue_path, {"body": body})
        return 0

    if existing:
        cleared = f"{MARKER}\n> The Go API compatibility check completed with neither public API additions nor potential incompatibilities for the current head.\n<!-- /obi-go-api-compatibility -->"
        if existing[0].get("body") != cleared:
            if not current_pull_request(gh, selected_pr):
                return 0
            gh.request("PATCH", f"/repos/{REPOSITORY}/issues/comments/{existing[0]['id']}", {"body": cleared})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, urllib.error.URLError) as error:
        sys.exit(fail(f"Go API comment helper failed safely: {error}"))
