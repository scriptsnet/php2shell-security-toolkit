# PHP2Shell Incident Report and Server Remediation Guide

Updated: October 22, 2026

## Executive summary

At 14:00 UTC on October 21, 2026, PHP published emergency security releases for two runtime vulnerabilities that can enable unauthenticated remote code execution.

| CVE | Failure mode | Official CVSS v4.0 | Advisory |
| --- | --- | --- | --- |
| CVE-2026-109618 | Out-of-memory handling can leave request state invalid; shutdown may interpret corrupted state as valid | 9.2 | GHSA-w8hw-w9fx-j79w |
| CVE-2026-109619 | Request-owned global state can survive after its memory is freed and be consumed by a later request | 9.2 | GHSA-6wmf-4rv5-p3rp |

These are PHP core issues, not WordPress, Laravel, Drupal, or plugin vulnerabilities. Every PHP SAPI serving web requests must be inventoried, including PHP-FPM, Apache `mod_php`, `php-cgi`, FrankenPHP, and LiteSpeed. PHP considers `mod_php` the highest risk because a demonstrated unauthenticated request can trigger exploitation before application code runs.

## Affected and fixed versions

| PHP branch | Affected | Fixed release |
| --- | --- | --- |
| 8.5 | Below 8.5.12 | 8.5.12 |
| 8.4 | Below 8.4.27 | 8.4.27 |
| 8.3 | Below 8.3.36 | 8.3.36 |
| 8.2 | Below 8.2.35 | 8.2.35 |
| 8.1 and older | End-of-life upstream | PHP provided minimal source backports for 7.4, 8.0, and 8.1, but no new official binary releases |

Linux distributions may ship the fix while retaining the original upstream-looking version string. Check the Ubuntu, Debian, Red Hat, AlmaLinux, Rocky Linux, or LTS vendor advisory and package changelog when a package appears older than the fixed upstream release.

## Attack conditions and impact

### CVE-2026-109618

PHP uses `longjmp()` for some out-of-memory exits. If allocation fails while request memory is only partially initialized, the exit path may not unwind safely and request shutdown can process invalid state. Multipart parsing provides several OOM strategies: a request without a usable declared content length, an excessive number of headers inside one part, empty file controls, and deeply nested field names.

PHP confirms application-independent exploitation against Apache `mod_php` before application code runs. Source analysis indicates PHP-FPM is susceptible, although the public advisory did not state that a complete FPM exploit was demonstrated. FrankenPHP is considered likely susceptible; LSAPI exposure can depend on application behavior. FPM should not be treated as safe.

### CVE-2026-109619

A request interrupted by a fatal error, timeout, or OOM may leave a worker-global field pointing to request-owned memory. After the request heap is freed, a later request on the same worker can consume the stale value before normal initialization resets it.

Confirmed consumers include session upload progress and, with `fatal_error_backtraces` enabled on PHP 8.5, fatal-error backtrace handling. Configuration diagnostics can become another early consumer when Apache `.htaccess`/directory PHP settings or `PHP_VALUE`/`PHP_ADMIN_VALUE` from an FPM frontend are applied before ordinary request initialization.

Successful exploitation can execute code as the web-worker account, disclose process-visible data, or cause denial of service. Patching does not retroactively remove a web shell, persistence, or stolen credentials. Investigate hosts that were exposed before remediation.

## Official interim mitigations

Updating is the only complete fix. The following measures reduce specific attack paths only.

### CVE-2026-109618

- Set and enforce `memory_limit=-1` where applications cannot override it, such as an FPM pool or Apache configuration.
- Keep `post_max_size` low, with `upload_max_filesize` below it.
- Block `multipart/form-data` at the proxy for applications that do not accept uploads.
- Limit decoded request size, multipart part count, headers per part, field count, and nesting depth at the frontend.
- Do not use `RLIMIT_AS` or `RLIMIT_DATA` as a replacement for the PHP memory limit; they can trigger the same OOM exit path. Container or cgroup limits can provide an availability boundary but are not a complete fix.

### CVE-2026-109619

- Set `session.upload_progress.enabled=0` in PHP, FPM pool, or server configuration that applies before request parsing, then restart every worker.
- Also set `fatal_error_backtraces=0` on PHP 8.5.
- Remove or fix invalid, deprecated, or conflicting INI settings that emit diagnostics before request initialization.
- Do not rely on `.user.ini` or `ini_set()` for these runtime mitigations; they apply too late for some paths.

## Inventory priorities

1. Internet-facing web services first; prioritize `mod_php`, FrankenPHP, and appliances with embedded PHP.
2. On Linux, inspect `PATH`, `/www/server/php`, `/usr/local`, `/opt`, systemd/init units, FPM pools, Apache modules, and Docker.
3. On Windows Server, inspect `PATH`, IIS FastCGI, Apache, XAMPP/WAMP/Laragon, service command lines, the registry, and every `php.exe`/`php-cgi.exe`.
4. Check vendor advisories for appliances, NAS products, control panels, monitoring systems, mail systems, and container images. Updating host PHP does not update embedded runtimes.
5. Verify the actual web SAPI rather than relying only on `php -v`. One host can have CLI, FPM, CGI, mod_php, and multiple stale directories.
6. Compare package installation time with PHP worker start time. An installed update does not patch an old running worker.

## Production remediation sequence

1. **Take a full-machine snapshot first.** The component backup created by these scripts does not include databases, application data, or unrelated system changes.
2. Record `php -v`, `php -i`, SAPI, FPM pools, Apache modules, extension lists, package versions, image IDs, and service state.
3. Back up `php.ini`, FPM/Apache configuration, extension files, and binaries.
4. Install the same-branch official fixed release or a distribution package explicitly marked fixed by its vendor advisory.
5. During a maintenance window, drain the node or stop accepting new traffic.
6. Install the update and run configuration validation. For Docker, pull the new image and recreate the container; `docker restart` alone is not a patch.
7. Fully restart PHP-FPM, Apache/mod_php, IIS/W3SVC, LiteSpeed/FrankenPHP, and all long-running PHP workers.
8. Verify the actual web SAPI as well as login, uploads, payments, queues, scheduled jobs, caching, and critical APIs.
9. Keep the old version and rollback artifact through an observation period.
10. If the host was internet-exposed before the patch, preserve logs and hunt for web shells, unexpected child processes, new accounts, scheduled tasks, outbound connections, and credential access.

## Linux rollback

A whole-machine snapshot remains the preferred rollback. The script also generates a component-level rollback:

```bash
ls -l /root/php2shell-fullfix/latest
bash /root/php2shell-fullfix/<timestamp>/rollback.sh
```

Review `report.txt`, `plan.txt`, and `rollback.sh` before running it. BT panel source installations and Debian official-image containers are tracked in `bt-backups.tsv` and `docker-backups.tsv`.

## Windows Server rollback

Run the script on the actual Windows Server/NT host that executes PHP. Apply mode is rejected on ordinary Windows workstations.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File "C:\ProgramData\PHP2ShellFullFix\<timestamp>\rollback.ps1"
```

Confirm the backup manifest, original service state, and current `php.ini` before restoring. PHP 7.4, 8.0, and 8.1 have no corresponding official Windows security ZIP; the script does not invent one. Upgrade to a supported branch or use a vendor/source backport.

## Tool boundaries

- HTTP scanning is a passive fingerprint check. It does not send exploit payloads and cannot prove that a site with a hidden version is safe.
- Bulk remote inventory targets Linux with OpenSSH. Windows Server uses the local PowerShell full-flow script.
- The full-flow scripts default to check-only mode. Automatic changes cover recognized BT panel PHP installations, a narrow set of Debian official-image PHP containers, and Windows official PHP ZIP installations.
- Distribution packages, unknown source builds, third-party panels, and embedded runtimes receive an operator path rather than an unchecked modification.

## October 22 production verification

During the authorized review of the Hong Kong production node, `/www/server/php/84` CLI, PHP-FPM, and CGI all reported 8.4.27. The Nextcloud `ocps/nextcloud:34.0.4-php8.5.12` container's mod_php reported 8.5.12. PHP-FPM was fully restarted and the final scan no longer matched either CVE.

This conclusion covers only the inventoried runtimes. Hidden versions, later containers, embedded PHP in third-party products, and other hosts still require separate verification.

## Primary sources

- PHP official security advisory: <https://www.php.net/archive/2026.php#2026-10-21-5>
- CVE-2026-109618 / GHSA-w8hw-w9fx-j79w: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- PHP 8.2.35 release: <https://github.com/php/php-src/releases/tag/php-8.2.35>
- NCSC-NL operational information: <https://github.com/NCSC-NL/php2shell>
- CISA CSAF/VEX: <https://vulnerability.circl.lu/vuln/VA-26-295-01>
- Canadian Centre for Cyber Security AL26-026: <https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619>
- CERT-EU 2026-018: <https://cert.europa.eu/publications/security-advisories/2026-018/>
- Cloudflare WAF note: <https://blog.cloudflare.com/php-vulnerabilities-waf-protection>
