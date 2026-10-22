# Security Policy and Operational Boundaries

## Supported purpose

This toolkit is intended for authorized administrators to inventory PHP runtimes and respond to CVE-2026-109618 and CVE-2026-109619 on systems they own or operate.

The HTTP scanner is passive: it reads normal HTTP response metadata and does not send exploit payloads. Do not repurpose the project to attack systems without written authorization.

## Credential handling

- The PC and Web scanners do not ask for or store SSH passwords.
- SSH mode uses OpenSSH keys or `ssh-agent`.
- The Web backend must bind to loopback by default. Binding to another interface requires `--token`.
- SSH key paths are resolved on the machine running the Web backend, not on the browser machine.
- Never commit `.env`, private keys, production inventories, scan reports, or access tokens.
- The sample server inventory uses documentation-only addresses from RFC 5737.

## Remediation safety

The Linux and Windows full-flow scripts are separate from the passive scanner.

- Check mode is the default and must remain safe on production systems.
- Apply mode requires a full-machine/cloud snapshot acknowledgement and three exact interactive confirmations.
- Before changing a managed component, the script records its version, SAPI, extension list, configuration, process/service state, and a rollback artifact.
- Automatic changes are intentionally limited to recognized patterns. Unknown source builds, distribution packages, control-panel variants, containers, and embedded runtimes are reported with a manual path rather than modified blindly.
- A PHP package update is not complete until old PHP-FPM, Apache/mod_php, CGI, LiteSpeed, FrankenPHP, IIS/FastCGI, and long-running PHP workers have been restarted.
- Restore from a whole-machine snapshot first if the host becomes unstable. Use the generated component rollback script only when the snapshot cannot be used or the change is known to be isolated.

## Scanner limitations

- An HTTP banner can be hidden, stale, proxied, or unrelated to the runtime that executes a request.
- Distribution packages may show an upstream-looking version while containing a vendor backport. Verify the vendor advisory and package changelog.
- Docker image tags may not match the runtime inside a container.
- Embedded PHP in appliances and third-party products requires the product vendor's advisory.
- A fixed version does not establish that earlier compromise must not be investigated.

## Reporting a vulnerability

Please report security issues in this toolkit privately to the repository owner rather than opening a public issue with secrets, production hostnames, evidence archives, or exploit data.

Include the affected version, operating system, reproduction steps using synthetic data, and the expected/actual behavior.
