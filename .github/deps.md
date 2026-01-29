# Dependency Upgrade Tracking

This file tracks dependencies that have been verified to work after upgrade.
The CD pipeline uses this file to force-upgrade these dependencies.

## Last Updated

Initial creation - will be auto-updated by CI

## Verified Upgrades

| Package | From Version | To Version | Verified Date | Commit |
|---------|--------------|------------|---------------|--------|
<!-- Upgrades will be automatically added here by CI -->

## Force Upgrade Commands

The following commands can be used to force-upgrade verified dependencies:

```bash
# Commands will be automatically added here by CI
cargo update  # Update all dependencies
```

## Upgrade History

### Initial Setup

This file was created as part of the CI/CD pipeline setup.
The CI pipeline will automatically:
1. Check for outdated dependencies
2. Attempt to bump them
3. Run the full build and test suite
4. If successful, record the upgrade here

The CD pipeline will:
1. Read this file on merge/PR
2. Force-upgrade listed dependencies
3. Run security scans
4. Generate SBOM
5. Create attestations

## Manual Dependency Management

To manually add a verified upgrade:

1. Test the upgrade locally:
   ```bash
   cargo update -p <package-name>
   cargo build --workspace
   cargo test --workspace
   ```

2. If successful, add to the table above with:
   - Package name
   - Previous version
   - New version
   - Date verified
   - Commit hash where verified

## Security Notes

- All upgrades are scanned with `cargo-audit` and OSV Scanner
- SBOM is generated for each release
- Build artifacts are attested via GitHub's artifact attestation
