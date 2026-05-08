# Security Policy

We take security vulnerabilities seriously. If you discover a security vulnerability within « Bouclier Bleu », please follow the guidelines below to report it securely.

## Reporting a Vulnerability

We strictly follow a Coordinated Vulnerability Disclosure (CVD) model. If you believe you have found a security vulnerability, a bypass mechanism, or a kernel-level flaw in Bouclier Bleu, please report it to us privately. **Do not open a public GitHub Issue.**

### 1. Contact Information

Please send an email to: [alexandreboutrik@protonmail.ch](mailto:alexandreboutrik@protonmail.ch).

### 2. Secure Communication (PGP)

We highly encourage you to encrypt sensitive Proof of Concept (PoC) code or exploit details. 

> [!IMPORTANT]
> To ensure a high level of security against future threats, our project utilizes Post-Quantum Cryptography (PQC). Our public key is a LibrePGP v5 key utilizing the Kyber algorithm. Because of this, you will need a modern PGP client (such as GnuPG 2.5.19 or later) to properly encrypt your messages to us.

> [!NOTE]
> If you are using NixOS, you can run `nix-shell --arg useCustomGnuPG true` to drop into a dev shell equipped with GnuPG 2.5.19. Please be aware that this will compile GnuPG and its dependencies from source, which will take a while (potentially hours).

* **PGP Key Fingerprint:** `BB516 4C311 D9286 04099 9E699 55DEC 8C928 9A8FA D5478 39B38`.
* **Public Key:** You can download our public key directly from this repository: [`bouclier-bleu-pubkey.asc`](./assets/bouclier-bleu-pubkey.asc).

### 3. What to Include

To help us triage the issue quickly, please include:

* A detailed description of the vulnerability and its potential impact.
* The specific environment (e.g., Linux kernel version, distribution, architecture).
* Step-by-step instructions or a PoC script to reproduce the issue.

## Our Commitment (SLAs)

When you submit a vulnerability report, you can expect the following:

* **Acknowledgment:** We will acknowledge receipt of your report within 72 hours.
* **Triage & Confirmation:** We will investigate and confirm the vulnerability within 14 days.
* **Remediation:** We will work diligently to develop a patch and coordinate a release date with you.
* **Embargo:** We ask for a standard **90-day embargo** before you publish your research, allowing us time to protect our users.

## Acknowledgments

We deeply appreciate the security research community. If your vulnerability report leads to a patch, we will gladly credit you in our Release Notes, the official CVE filing (if applicable), and our upcoming Security Hall of Fame, unless you prefer to remain anonymous.
