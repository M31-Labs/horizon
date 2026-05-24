# Security Policy

Horizon generates eBPF C, object files, Go bindings, and capability manifests.
Security issues can affect generated kernel programs, verifier assumptions,
diagnostic remapping, or host capability reporting.

## Reporting

Do not open public issues for suspected vulnerabilities.

Use GitHub private vulnerability reporting for this repository. If that is not
available, open a minimal public issue asking for a private security contact and
do not include exploit details, logs, object files, or generated artifacts.

Include the smallest safe reproducer you can share:

- Horizon version or commit SHA
- `.hzn` source if it is safe to disclose
- generated C or verifier log only if it does not expose sensitive host data
- kernel version, architecture, clang version, and libbpf version when relevant

## Scope

Security-relevant reports include:

- generated C that violates Horizon's safety model
- verifier diagnostics mapped to the wrong authored source
- resource lifetime checks that allow use-after-submit, missing nil checks, or
  leaked reservations
- incorrect capability manifests or host requirement reporting
- unsafe generated Go bindings

General language design requests, unsupported helpers, and normal verifier
rejections should use regular issues.
