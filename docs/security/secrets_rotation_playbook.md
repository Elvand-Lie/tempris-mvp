# Secrets Rotation Playbook

This playbook defines the incident response procedures for compromised credentials or secrets.

## SLA Response Timeframes
- **Critical (Superadmin/DB passwords, private signing keys):** 2 hours.
- **High (API keys, service accounts):** 6 hours.
- **Medium (Development environment credentials):** 24 hours.

## Standard Rotation Workflow

1. **Detection & Quarantine**
   - Identify the source of the leak (e.g., git commit history, exposed logs).
   - Log the incident in the SIEM / Security incident log system with a unique ticket ID.

2. **Revocation & Provisioning**
   - Generate a new cryptographically secure secret (minimum 32 bytes/characters).
   - Update the configuration management or secret store (e.g., AWS Secrets Manager, HashiCorp Vault).
   - Revoke the compromised token/key on the provider side (e.g., OAuth provider, Database server).

3. **Code Cleanup & Commit Purging**
   - If committed to Git, use `git-filter-repo` or BFG Repo-Cleaner to permanently scrub the secret from all historical commits.
   - Force push the sanitized branches to remote repositories.

4. **Notifications**
   - Notify the affected partners/clients via the secure customer notification channel.
   - Alert the Security Operations Team (SecOps) via Slack `#security-alerts` or email `security@tempris.com`.
