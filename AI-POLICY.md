# OpenTelemetry eBPF Instrumentation Generative AI Policy

Based on the [Cilium Generative AI Policy](https://github.com/cilium/community/blob/main/AI-POLICY.md#unacceptable-use).

To maintain the high quality and trustworthiness of contributions to the
OpenTelemetry eBPF Instrumentation (OBI)
community, we provide the following guidance on the use of "Generative
Artificial Intelligence", including large language models (LLMs), GitHub
Copilot, ChatGPT, Codex, Claude code, or similar tools ("Generative AI"). The
guidance in this document is intended for contributors and describes their
responsibilities regardless of which tools they use. Instructions for coding
agents are maintained separately in [AGENTS.md]. As a Linux Foundation project,
OBI is also subject to the Linux Foundation
[Guidance Regarding Use of Generative AI Tools]. The guidance in this document
is intended to support you as a contributor in addition to the Linux Foundation
guidance.

## 1. Guiding Principle

OBI is a community-driven organization that values expertise, clear
communication, and personal responsibility. The community prides itself on a
commitment to high quality and trust amongst its members. To maintain this in
the AI era, we follow a key principle:

**What you do with Generative AI reflects on you**.

Successful ongoing contribution to this community is contingent on building
trust with the members of the organization through ongoing collaboration.
Whether or not Generative AI tools were involved, you are fully accountable for
the correctness, security, and clarity of your contributions. Human review is
required for all code, including code generated or assisted by Generative AI
tools. If you contribute regularly, other contributors will become familiar
with your work, so we request that you mindfully consider the impact that your
use of Generative AI may have on other community members.

## 2. Acceptable Use

We recognize that Generative AI can be a helpful _tool_, for example you may
use it to:

- Explain parts of the codebase you don’t understand;
- Auto-complete routines or boilerplate code (such as error handling, test
  scaffolding, function signatures);
- Reformat or refactor existing content;
- Brainstorm and evaluate implementation options;
- Draft or implement code, documentation, and tests that you subsequently
  review, revise, and validate; or
- Analyze your own content submissions.

These uses are acceptable provided you:

1. Are involved in the entire process for creating the contributions;
2. Personally review, edit, and understand generated content before you submit
  it to the organization;
3. Validate generated content where applicable;
4. Take personal responsibility for the content, just as if you had authored
  it without using Generative AI;
5. Ensure the output adheres to project guidelines and licensing requirements; and
6. Disclose non-trivial use of Generative AI as described in
  [Transparency and Disclosure](#5-transparency-and-disclosure).

### GitHub Communication

Generative AI may help draft issue and pull request descriptions, reviews, and
comments. Before posting, verify its factual claims and revise the text so it
accurately represents your judgment and intent. Keep communication concise,
specific, and easy to scan. Do not post generated wall-of-text reports,
exhaustive restatements of the code, or a play-by-play of the work. Include only
the context needed for another contributor to understand or act on the message.

## 3. Unacceptable Use

It is not acceptable to use Generative AI tools to:

1. Post Generative AI output in an OBI community space without verifying that
  it accurately represents your judgment and intent.
2. Submit code, documentation, or discussion content that you have not reviewed
  in careful detail, including testing the content where applicable.
3. Use Generative AI output as a substitute for your own judgment in technical
  problem solving or architectural decision making.
4. Submit work produced via Generative AI tooling that copies from external
  sources without correct attribution or licensing.
5. Submit contributions where you cannot explain, contextualize, or justify the
  submission as part of review.

## 4. Generative AI for Translation

Contributors may use generative or non-generative translation tools to
participate in OBI community spaces. Review translated text when possible to
ensure it conveys your intended meaning. Translation assistance does not
require disclosure unless the tool also generates substantive content.

## 5. Transparency and Disclosure

Disclose non-trivial Generative AI use. This includes using Generative AI to
produce implementation code, tests, documentation, or substantive
communication. Briefly describe how it was used and how you reviewed and
validated its output. You do not need to disclose spelling assistance, simple
autocomplete, or translation that does not generate substantive content.

Disclosure provides context for reviewers; it does not change the standards
applied to the contribution. If required disclosure is missing, maintainers may
ask for it during review.

## DCO and Licensing

The [EasyCLA signature](https://easycla.lfx.linuxfoundation.org/#/?version=2) is required for contributions to
the OBI organization. AI tools often lack transparency into their training
data and may produce output with pre-existing copyright. If you submit
AI-assisted contributions, you are personally certifying that you have the
right to contribute the content under the project's license. The Linux
Foundation [Guidance Regarding Use of Generative AI Tools] provides a more
detailed description of your obligations as a contributor. If you’re unsure
about the licensing of code you created using Generative AI tools,
**don’t submit it**.

[Guidance Regarding Use of Generative AI Tools]: https://www.linuxfoundation.org/legal/generative-ai
[AGENTS.md]: AGENTS.md
