#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import urllib.request

repository = "open-telemetry/opentelemetry-ebpf-instrumentation"
responses = {}

def fetch(path):
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        data = json.load(response)
    responses[path] = data
    return data

page = 1
while True:
    releases = fetch(f"/repos/{repository}/releases?per_page=100&page={page}")
    # Preserve page lengths without publishing private draft metadata.
    responses[f"/repos/{repository}/releases?per_page=100&page={page}"] = [
        {"draft": True} if release["draft"] else {
            **{key: release[key] for key in ("tag_name", "draft", "prerelease", "immutable")},
            "assets": [{"name": asset["name"]} for asset in release["assets"]],
        }
        for release in releases
    ]
    for release in releases:
        tag = release["tag_name"]
        if release["draft"] or release["prerelease"]:
            continue
        if not re.fullmatch(r"v[1-9][0-9]*\.[0-9]+\.[0-9]+", tag):
            continue
        path = f"/repos/{repository}/git/ref/tags/{tag}"
        for _ in range(8):
            obj = fetch(path)["object"]
            if not re.fullmatch(r"[0-9a-f]{40}", obj["sha"]):
                raise ValueError(f"Invalid object ID for {tag}")
            if obj["type"] == "commit":
                break
            if obj["type"] != "tag":
                raise ValueError(f"Unexpected object type for {tag}")
            path = f"/repos/{repository}/git/tags/{obj['sha']}"
        else:
            raise ValueError(f"Cannot resolve {tag} to a commit")
    if len(releases) < 100:
        break
    page += 1

with open("release-metadata.json", "w") as output:
    json.dump(responses, output)
