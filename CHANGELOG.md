# Changelog

## 1.1.0

- Add the optional Team tier: seat-based licence activation, entitlement checks, and
  centralised reporting for organisations. Entirely opt-in.
- Free scanning is unchanged and still runs completely on your own machine. Nothing is
  uploaded unless you activate a Team licence.
- Team reports carry only extension IDs and names, risk scores, and counts of findings by
  category and severity. Source code, secret values, file paths, and your raw machine
  identifier are never transmitted.
- Licence keys and access tokens are stored only in VS Code SecretStorage.
- The Team service URL can be pointed at your own deployment if you would rather host it.

## 1.0.2

- Prevent activation failures when the legacy `babstudios.extguard` build is still installed.
- Use distinct command and view IDs for the current Marketplace identity.
- Show legacy users a one-time migration notice with a direct route to the old extension.
- Correct the Marketplace links on the landing page.

## 1.0.1

- Publish under the permanent `babstudios.extguard-security` Marketplace identity.
- Improve the Marketplace-facing README and extension categorisation.

## 1.0.0

- Initial local extension audit, threat feed, secret scanner, capability analysis, risk sidebar,
  VSIX pre-install scan, publisher allowlist, and duplicate-version cleanup.
