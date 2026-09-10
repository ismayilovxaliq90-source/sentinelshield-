# TASK 176 — Execution Environment Validation

This task is SERVER-only.

The implementation is written in the repository, but the actual
environment validation is executed by GitHub Actions on an isolated
runner.

Local WSL must not execute the Task 176 validation command.

Expected execution flow:

WSL
-> git push
-> GitHub Actions
-> ubuntu-latest runner
-> Task 176 validation
-> evidence artifact
