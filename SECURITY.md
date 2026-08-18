# Security Policy

CyberBuddy is a security assessment tool, so responsible handling of flaws in
the project itself matters.

## Supported version

The latest code on `main` and the current GitHub Pages deployment are supported.
Older clones, forks, and third-party deployments may not include current fixes.

## Report a vulnerability privately

Email **amitpal.secure@gmail.com** with the subject
`[CyberBuddy security] <short summary>`.

Please do **not** open a public issue for a suspected vulnerability. Include:

- the affected page, endpoint, file, or commit;
- impact and realistic attack conditions;
- reproducible steps or a minimal proof of concept;
- browser, Python version, and deployment mode when relevant; and
- suggested remediation, if you have one.

Do not send real credentials, production tokens, customer data, or destructive
payloads. Use synthetic values and redact target details that are not needed to
reproduce the issue.

The maintainer will acknowledge and triage reports as soon as practical,
coordinate remediation and disclosure based on severity, and credit reporters
who want attribution. Please allow time for a fix before publishing details.

## Scope

This policy covers vulnerabilities in CyberBuddy's source, hosted site, local
server, serverless API adapters, generated artifacts, and publication workflow.
It does not cover security findings that CyberBuddy reports about a third-party
target. Report those through that target owner's disclosure process and only
after authorized testing.

Good-faith research that respects authorization boundaries, avoids privacy
violations and service disruption, and follows this process is welcome.

The hosted discovery copy of this contact is available at
[`.well-known/security.txt`](.well-known/security.txt). On a GitHub Pages
project subpath it cannot serve as the RFC 9116 domain-root file; this repository
policy is the canonical GitHub disclosure route.
