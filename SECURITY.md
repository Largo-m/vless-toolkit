# Security policy

## Share links are secrets

A VLESS, VMess, Trojan or Shadowsocks share link contains credentials that can
grant access to a proxy server. Treat links, subscription URLs and decoded
subscription payloads as secrets:

- Do not paste real links into bug reports, issues or pull requests.
- Do not commit exported links or subscription files to a repository.
- Use the library's redaction helpers before writing links to logs.
- Prefer environment variables or a local, git-ignored file for automation.

## Supported versions

Security fixes are applied to the latest released version.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability) rather than a public issue. Include a
minimal reproduction and the impact you believe the issue has. Do not include
live credentials; rotate any credential that may have been exposed.
