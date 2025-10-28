# Environment Synchronization Script

## Overview

`sync_environments.py` replicates ALL configuration from one Heimdall environment to another, ensuring they are EXACTLY identical.

## Features

- ✅ **Comprehensive Sync**: Actions, Roles, Mappings, Groups, and all their relationships
- ✅ **Healthcheck**: Verifies permissions before making any changes
- ✅ **Idempotent**: Safe to run multiple times
- ✅ **Resilient**: Checkpoint system allows resuming from failures
- ✅ **Dry-run**: Preview changes before applying
- ✅ **Detailed Reporting**: Shows all creates, updates, and deletes

## Prerequisites

1. JWT tokens for both source and target environments
2. User must have **superadmin** role in both environments
3. Python environment with dependencies:
   ```bash
   pip install requests
   ```

## Usage

### 1. Dry Run (Preview Changes)

Always run dry-run first to see what will change:

```bash
python scripts/sync_environments.py \
  --source-url https://services.staging.app.dados.rio \
  --source-token $STAGING_TOKEN \
  --target-url https://services.pref.rio \
  --target-token $PROD_TOKEN \
  --dry-run
```

### 2. Run Actual Sync

After reviewing dry-run output:

```bash
python scripts/sync_environments.py \
  --source-url https://services.staging.app.dados.rio \
  --source-token $STAGING_TOKEN \
  --target-url https://services.pref.rio \
  --target-token $PROD_TOKEN
```

The script will:
1. Run healthcheck on both environments
2. Show a 5-second warning before making changes
3. Sync all entities in dependency order
4. Display detailed progress and summary

### 3. Resume from Checkpoint

If the sync is interrupted (Ctrl+C or error), resume with:

```bash
python scripts/sync_environments.py \
  --source-url https://services.staging.app.dados.rio \
  --source-token $STAGING_TOKEN \
  --target-url https://services.pref.rio \
  --target-token $PROD_TOKEN \
  --resume
```

## What Gets Synced

The script syncs in this order (respecting dependencies):

1. **Actions** - All available actions in the system
2. **Roles** - All roles and their action assignments
3. **Mappings** - All endpoint-to-action mappings
4. **Groups** - All groups and their role assignments

The target environment will be updated to EXACTLY match the source:
- Missing entities are **created**
- Different entities are **updated**
- Extra entities are **deleted**

## Example Output

```
==============================================================
HEIMDALL ENVIRONMENT SYNCHRONIZATION
==============================================================
Source: https://services.staging.app.dados.rio
Target: https://services.pref.rio
Mode: LIVE

==============================================================
RUNNING HEALTHCHECK
==============================================================

Checking SOURCE environment...
  URL: https://services.staging.app.dados.rio
  ✓ API is healthy
  ✓ Authentication valid (user: 47562396507)
  ✓ User has superadmin role
  ✓ Write permissions verified

Checking TARGET environment...
  URL: https://services.pref.rio
  ✓ API is healthy
  ✓ Authentication valid (user: 47562396507)
  ✓ User has superadmin role
  ✓ Write permissions verified

==============================================================

✓ Healthcheck PASSED - ready to sync

⚠️  WARNING: This will modify the target environment!
Press Ctrl+C within 5 seconds to cancel...

==============================================================
SYNCING ACTIONS
==============================================================
Fetching actions from source...
  Found 25 actions in source
Fetching actions from target...
  Found 23 actions in target
  [CREATE] Action 'users:export'
  [CREATE] Action 'data:analyze'
  [UPDATE] Action 'users:read' description
  [DELETE] Action 'legacy:action'

==============================================================
SYNCING ROLES
==============================================================
Fetching roles from source...
  Found 10 roles in source
Fetching roles from target...
  Found 8 roles in target
  [CREATE] Role 'data-scientist'
  [CREATE] Role 'auditor'

Syncing role-action assignments...
  [ASSIGN] Action 'users:export' to role 'admin'
  [UNASSIGN] Action 'legacy:action' from role 'viewer'

==============================================================
SYNCING MAPPINGS
==============================================================
Fetching mappings from source...
  Found 50 mappings in source
Fetching mappings from target...
  Found 48 mappings in target
  [CREATE] Mapping GET /api/v1/users/export -> users:export
  [CREATE] Mapping POST /api/v1/data/analyze -> data:analyze
  [DELETE] Mapping GET /api/v1/legacy -> legacy:action

==============================================================
SYNCING GROUPS
==============================================================
Fetching groups from source...
  Found 5 groups in source
Fetching groups from target...
  Found 4 groups in target
  [CREATE] Group 'data-team'

Syncing group-role assignments...
  [ASSIGN] Role 'data-scientist' to group 'data-team'

==============================================================
SYNC SUMMARY
==============================================================
Actions:  +2 ~1 -1
Roles:    +2 ~0 -0
Mappings: +2 ~0 -1
Groups:   +1 ~0 -0
Errors:   0
Total Changes: 9
==============================================================

Completed in 12.34 seconds
```

## Getting API Tokens

### For Staging

```bash
# Get token from Keycloak or use existing JWT
export STAGING_TOKEN="eyJhbGc..."
```

### For Production

```bash
# Get token from Keycloak or use existing JWT
export PROD_TOKEN="eyJhbGc..."
```

## Safety Features

1. **Healthcheck First**: Verifies connectivity, authentication, and permissions before any changes
2. **5-Second Warning**: Gives you time to cancel before making changes (not in dry-run)
3. **Checkpoint System**: Saves progress after each stage
4. **Error Isolation**: One failed entity doesn't stop the entire sync
5. **Dry-Run Mode**: Preview all changes before applying

## Troubleshooting

### "User does not have superadmin role"

Ensure the user whose JWT token you're using has the `heimdall-admin` role in Keycloak, which grants superadmin privileges.

### "Write permission test failed"

The user may not have permission to create actions. Check that:
1. User has superadmin role
2. Token is valid and not expired
3. API is accessible

### Sync Interrupted

If the sync is interrupted (Ctrl+C or network error), use `--resume` to continue from the last checkpoint:

```bash
python scripts/sync_environments.py \
  --source-url ... \
  --target-url ... \
  --resume
```

The checkpoint file (`sync_checkpoint.json`) tracks progress and is automatically deleted on successful completion.

## Best Practices

1. **Always dry-run first**: Review what will change
2. **Test in staging**: Sync from dev → staging before staging → prod
3. **Off-peak hours**: Run production syncs during low-traffic periods
4. **Backup before sync**: Consider backing up target environment
5. **Monitor after sync**: Verify everything works as expected

## Notes

- The script does NOT sync users or user memberships (these are auto-created from JWT)
- Source environment is never modified (read-only)
- Target environment is modified to match source exactly
- Deleted entities in source are also deleted in target
