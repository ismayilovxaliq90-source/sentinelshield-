# TASK 177 — Python Virtual Environment Validation

SERVER-ONLY.

The repository implementation is prepared in WSL, but Task 177
validation is executed only by the GitHub Actions runner.

Execution path:

WSL
-> git push
-> GitHub Actions
-> isolated runner
-> Python virtual environment
-> Task 177 validation
-> evidence artifact
