# auth-go project notes

## Releasing — CHANGELOG discipline

Every user-visible change must land with a `CHANGELOG.md` entry in the
same PR, under the top `## Unreleased` heading. When you're about to
push code that changes behaviour, types, defaults, or wire format,
update CHANGELOG.md in the same commit set.

Bullets under `## Unreleased` must describe deltas **since the last
tag**, not since some earlier point. Stale survivors are the failure
mode — v0.3.4's draft inherited v0.3.2's `:access_token` bullet from
an Unreleased section that wasn't promoted at v0.3.2's tag time, and
the claim then read as "new in v0.3.4" until caught at tagging.

To tag a release:

1. Rename `## Unreleased` to `## vX.Y.Z — YYYY-MM-DD` in a regular PR,
   adding any missing entries for the release. Verify each bullet is
   actually new since the previous tag (`git log v<prev>..main`).
2. After merge, tag the merge commit with `git tag -a vX.Y.Z -m "..."`
   and `git push --tags`.

Pre-1.0 SemVer with one local convention: breaking changes may ship as
patch bumps when the surface is narrow and well-documented
(`v0.3.2` changed the default `subject_token_type` as a patch).
