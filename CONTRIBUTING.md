# Contributing to Bouclier Bleu

Thank you for your interest in contributing to Bouclier Bleu.

This document outlines the process for proposing changes, submitting code, and ensuring your contributions meet our legal and technical standards.

---

## 1. Dual-License Architecture

Due to its hybrid design, Bouclier Bleu operates under a dual-licensing model:
* **User-Space Components** (Rust daemon, CLI, modules): Licensed under the **Apache License, Version 2.0**.
* **Kernel-Space Components** (eBPF C code): Licensed under the **GNU General Public License v2.0 (GPL-2.0)** to maintain compatibility with the Linux kernel verifier.

By submitting a Pull Request, you agree that your code will be licensed under the respective license of the component you are modifying.

---

## 2. Developer Certificate of Origin (DCO)

To protect the project, its users, and yourself, all contributions must be legally verified. By adding your name, you certify that your contributions are made under the project's Developer Certificate of Origin (DCO).

We do not require a formal Contributor License Agreement (CLA). Instead, we use the frictionless DCO model standard in the Linux ecosystem.

### How to Sign Your Commits

You must add a `Signed-off-by` line to every commit. You can do this automatically by passing the `-s` flag to Git:

```bash
git commit -s -m "feat: add canary file monitoring"
```

This will append the following line to your commit message based on your Git config: `Signed-off-by: Your Name <your.email@example.com>`.

### What if I forget?

Our CI/CD pipeline includes a DCO bot that will block your Pull Request if any commit is missing a signature. If you forget, you do not need to start over. Simply amend your last commit:

```bash
# Add the signature to the previous commit without changing the message
git commit --amend --no-edit -s

# Update your remote branch
git push --force-with-lease
```

## 3. Updating the CONTRIBUTORS File

The `CONTRIBUTORS` file acknowledges all individuals and organizations who have contributed to the project.

When submitting your first Pull Request, you must add yourself to this file. To add your name, please submit a pull request updating this file alongside your first contribution.

Please use the exact format requested: `Name/Organization <email address>`.

> [!NOTE]
> The `AUTHORS` file lists the original creators, architects, and primary copyright holders of the Bouclier Bleu software. For a comprehensive list of all individuals and entities who have contributed to the project, please see the `CONTRIBUTORS` file.

## 4. Pull Request Process

- **Fork and Branch**: Fork the repository and create a descriptive branch for your feature or bug fix (git switch -c feat/your-feature-name).
- **Write Code**: Make your changes, ensuring memory safety in user-space and strict verifier compliance in kernel-space.
- **Test**: Ensure the core daemon compiles (cargo build --release) and that the eBPF hooks load successfully into the kernel.
- **Commit and Sign**: Use git commit -s for all changes.
- **Submit PR**: Open a Pull Request against the main branch. Provide a clear summary of the changes and link any relevant GitHub Issues.
