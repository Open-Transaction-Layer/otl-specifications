# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability
reporting on this repository, under **Security → Report a vulnerability**. That
is the only reporting channel because it needs no shared mailbox and it keeps
the report and the fix in one place.

Please do not open a public issue for a security problem, and please do not
disclose it publicly until a fix is available, because implementations may
need time to change before a flaw in the protocol is widely known.

We aim to acknowledge a report within 3 working days and to agree a disclosure
timeline with the reporter.

## Scope

This repository holds protocol specifications rather than code, so the reports
that matter most describe a flaw in the protocol itself. That means a design in
which a conforming implementation, following the specification correctly, can
still be made to accept a forged or replayed proof, a tampered or forked
version log, a revoked or expired credential, or a party it should not trust.
An ambiguity that lets 2 conforming implementations disagree on whether
something is valid is also worth reporting here when one of them fails open.

A bug in a particular implementation belongs with that implementation. For the
reference implementation that is the
[OTL SDK](https://github.com/Open-Transaction-Layer/otl-sdk/security).

Editorial problems and ambiguities that cause implementations to fail closed
are not security issues, so please raise them as ordinary issues.
