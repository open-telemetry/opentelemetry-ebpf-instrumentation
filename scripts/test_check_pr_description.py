#!/usr/bin/env python3
# Tests for check-pr-description.py, with example bodies for every rule and
# for the failure modes reported in review: bullet lists concatenated into one
# sentence, headings counted inside code blocks and comments, domain terms
# treated as filler, and empty or untouched-template bodies passing.
#
#   python3 scripts/test_check_pr_description.py

import importlib.util
import pathlib
import unittest

_SCRIPT = pathlib.Path(__file__).with_name("check-pr-description.py")
_spec = importlib.util.spec_from_file_location("check_pr_description", _SCRIPT)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

TEMPLATE = """<!--
Keep the whole description short (aim for under ~20 lines) and in plain
language: a reviewer must understand what changed and why in a single read.
Long or AI-generated walls of text will be sent back for a rewrite before
review (see AI-POLICY.md).
-->

## Summary

<!-- What changed and why, in 2-4 sentences. Link the issue if there is one. -->

## Testing

<!-- How you verified it: tests run, environment, before/after behavior. -->

## Validation

- [ ] I have read and followed the [contributing guidelines](https://example.com/CONTRIBUTING.md)
- [ ] If this enhances / fixes / changes a core feature, I have updated the [features documentation](https://example.com/features.md) and [support matrix](https://example.com/SUPPORT_MATRIX.md) as needed.
"""


def findings(body: str) -> list[str]:
    text = check.prose(body)
    return check.empty_problems(body) + check.structure_problems(body) + check.problems(text)


class TestGoodDescriptions(unittest.TestCase):
    def test_short_filled_template_passes(self):
        body = TEMPLATE.replace(
            "## Summary\n",
            "## Summary\n\nFix a nil map access in the Kafka parser when the "
            "header block is truncated. Fixes #1234.\n",
        ).replace(
            "## Testing\n",
            "## Testing\n\nAdded a unit test with the truncated capture from "
            "the issue; ran the Kafka integration suite.\n",
        )
        self.assertEqual(findings(body), [])

    def test_bullet_list_without_punctuation_passes(self):
        # regression: bullets used to be concatenated into one long sentence
        body = """## Summary

Rework the exporter startup:

- move the queue setup out of the constructor
- retry the endpoint resolution with backoff instead of failing once
- drop the unused mutex around the batch counter
- log the resolved endpoint at debug level so support can see it
"""
        self.assertEqual(findings(body), [])

    def test_numbered_list_passes(self):
        body = """Steps taken to validate the release artifacts before tagging:

1) built the image from a clean checkout on both amd64 and arm64 hosts
2) ran the verifier suite against every supported kernel in the matrix
3) compared the emitted schema files against the previous release
"""
        self.assertEqual(findings(body), [])

    def test_domain_term_underscore_passes(self):
        # regression: "underscore" was on the filler list and a real
        # metric-naming migration description used it five times
        body = """## Summary

Rename the Prometheus-style metric names to the OTel dot format. Every
underscore in a metric name becomes a dot, except the unit suffix where the
underscore is kept. Names with a leading underscore are rejected, names with
a double underscore keep one underscore, and the target_info underscores are
unchanged. Fixes #2634.
"""
        self.assertEqual(findings(body), [])

    def test_headings_in_code_blocks_do_not_count(self):
        # regression: shell comments in a fenced example counted as headings
        body = """## Summary

Teach the collector config loader to expand environment variables.

## Testing

Manual run with the config below plus the loader unit tests.

```bash
# start the collector
# with the test config
# and debug logging
# on both ports
OTEL_LOG=debug ./collector --config test.yaml
```
"""
        self.assertEqual(findings(body), [])

    def test_headings_in_html_comments_do_not_count(self):
        body = "One-line fix for the flaky DNS test.\n<!--\n# a\n# b\n# c\n# d\n# e\n# f\n-->\n"
        self.assertEqual(findings(body), [])

    def test_crlf_body_passes(self):
        body = "## Summary\r\n\r\nBump the base image to fix CVE-2026-1234.\r\n"
        self.assertEqual(findings(body), [])

    def test_one_long_sentence_in_a_short_description_passes(self):
        # a single 35-word sentence is not a wall of text
        body = (
            "Fix a stuck collector shutdown caused by closing the ring "
            "buffer reader too late in the pipeline teardown, and add a "
            "deadline so a blocked reader cannot hold the shutdown forever."
        )
        self.assertEqual(findings(body), [])

    def test_fixes_link_only_passes(self):
        # "fixes <issue link>" leaves the explanation to the linked issue
        body = TEMPLATE.replace(
            "## Summary\n",
            "## Summary\n\nfixes https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3056\n",
        )
        self.assertEqual(findings(body), [])

    def test_fixes_issue_number_only_passes(self):
        self.assertEqual(findings("Fixes #123"), [])

    def test_any_author_text_passes(self):
        # only a completely empty or template-only body fails
        self.assertEqual(findings("Fixes"), [])
        self.assertEqual(findings(TEMPLATE + "\nrelease prep"), [])

    def test_single_filler_word_passes(self):
        body = (
            "Make the retry loop robust against clock skew by comparing "
            "monotonic timestamps instead of wall-clock times."
        )
        self.assertEqual(findings(body), [])


class TestBadDescriptions(unittest.TestCase):
    def assert_fails(self, body: str, needle: str):
        found = findings(body)
        self.assertTrue(
            any(needle in f for f in found),
            f"expected a finding containing {needle!r}, got {found!r}",
        )

    def test_empty_body_fails(self):
        # regression: an empty body used to pass with 0 characters of prose
        self.assert_fails("", "empty")

    def test_untouched_template_fails(self):
        # regression: the untouched template strips to nothing and passed
        self.assert_fails(TEMPLATE, "empty")

    def test_whitespace_only_body_fails(self):
        self.assert_fails("   \n\n  \n", "empty")

    def test_too_long_fails(self):
        body = "The parser change touches every branch. " * 60
        self.assert_fails(body, "limit 2000")

    def test_too_many_headings_fails(self):
        body = (
            "# One\n## Two\n## Three\n## Four\n## Five\n## Six\n\n"
            "Rewrite of the pipeline configuration docs.\n"
        )
        self.assert_fails(body, "section headings")

    def test_long_sentences_fail(self):
        sentence = (
            "this change updates the exporter and the receiver and the "
            "processor and the config loader and the docs and the tests and "
            "the benchmarks and the examples and the readme and the changelog "
            "and the release notes and the helm chart. "
        )
        self.assert_fails(sentence * 3, "sentences average")

    def test_single_run_on_wall_fails(self):
        body = "word " * 70
        self.assert_fails(body, "sentences average")

    def test_boilerplate_phrase_fails(self):
        body = (
            "It's important to note that this refactor keeps the wire format "
            "unchanged while moving the encoder into its own package."
        )
        self.assert_fails(body, "boilerplate")

    def test_filler_word_density_fails(self):
        body = (
            "This comprehensive change leverages the new API to seamlessly "
            "streamline the pipeline."
        )
        self.assert_fails(body, "filler")

    def test_long_word_ratio_fails(self):
        word = "internationalization "
        body = ("fix the parser.\n" + word * 3) * 5
        self.assert_fails(body, "simpler words")


class TestProse(unittest.TestCase):
    def test_list_items_become_separate_lines(self):
        text = check.prose("- first item\n- second item\n")
        self.assertEqual(text, "first item\nsecond item")

    def test_paragraph_lines_are_joined(self):
        text = check.prose("a sentence wrapped\nover two lines\n")
        self.assertEqual(text, "a sentence wrapped over two lines")

    def test_unclosed_code_fence_is_stripped(self):
        text = check.prose("Fix the flaky test.\n```\n# not a heading\nx = 1\n")
        self.assertEqual(text, "Fix the flaky test.")
        self.assertEqual(check.structure_problems("```\n# a\n# b\n"), [])

    def test_template_strips_to_nothing(self):
        self.assertEqual(check.prose(TEMPLATE), "")


if __name__ == "__main__":
    unittest.main()
