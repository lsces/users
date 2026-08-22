# Users Package — Developer Notes

Session log — decisions, bugs found, and why things are the way they are. No `MANUAL.md`
counterpart yet.

Backfilled 2026-08-22 from real work already done and documented elsewhere (Claude's own memory
system, the top-level `bitweaver/CLAUDE.md`) — users never had its own doc file before this, so
mechanics and fixes that genuinely belong here were scattered across the top-level file and
memory instead. Entries below keep their original dates; this file is new, the history isn't.

## Role/permission model — RolePermUser only, group model deleted (completed 2026-05-16)

Two parallel class pairs existed historically:

- **`BitUser`/`BitPermUser`** — original TikiWiki-era group model. **Deleted entirely.** Users
  belonged to groups, groups carried permission flags (`p_xxx`) — coarse-grained "can this user
  *type* do this action," content owned by its creating user.
- **`RoleUser`/`RolePermUser`** — the lsces role model, **canonical, only model now**. Users map
  to roles via `users_roles_map`; answers both "can this user do this action" and "can this user
  access this *specific* content." Content belongs to a **role**, not to its author — a manager's
  content stays visible to all managers, no orphaning when staff leave.

**Why the group model couldn't work here** — three interlocking dependencies all require the role
model: Protector maps content to roles via `liberty_content_role_map`, joined against
`users_roles_map` (doesn't exist in the group schema); the nginx `auth_request` chain
(`config/kernel/auth_check.php`) checks `$_SESSION['user_role']`, only ever written by
`RolePermUser` on login; and the per-role content-ownership model itself is a deliberate design
choice for the client-management use case (staff/supervisor/manager/admin ring-fencing), not
something the group model's per-user ownership can express.

**Rationalisation, done**: `BitUser.php`/`BitPermUser.php` deleted; every `ROLE_MODEL`
conditional flattened (runtime, installer, schema, templates); `gatekeeper` package (postgres-
specific, group-model-only) deleted outright; `mGroups`/`loadGroups()`/`getAllGroups()`/
`isInGroup()`/etc. removed from `RolePermUser`; dead group-admin templates deleted. Protector is
effectively required now — every `isPackageActive('protector')` UI guard is gone, it's always on.

**Still outstanding**: `messages/` package still has deep group-model SQL
(`users_groups_map`/`users_groups`) throughout `Messages.php`/`broadcast.tpl` — no role-model
equivalent of "group send" has been designed yet, not touched. `blogs/recent_posts.php` has
`verifyViewPermission()` commented out as a temporary fix for an old 404 issue, never revisited.

**Why this rationalisation happened at all**: a github fork this codebase originated from kept
defaulting back to the group model; deleting it outright (not just deprecating) makes it
unambiguous that this stack runs role-model only. Full detail in `project_users_rationalisation`
memory.

## Permission / Role system reference

Default `role_id` values (`ANONYMOUS_TEAM_ID = -1`):
- `1` Administrators — `perm_level` `admin`
- `2` Editors — `perm_level` `editors`
- `3` Registered — `perm_level` `registered`
- `-1` Anonymous — `perm_level` `basic`

Permissions are assigned in each package's own `admin/schema_inc.php`. Role assignments are
stored in `users_role_permissions`. When writing xref role-filter queries elsewhere, guard
`mRoles` with `array_keys($gBitUser->mRoles ?? []) ?: [-1]` — Firebird rejects an empty `IN()`.

## Session / Auth cookie mechanics

Cookie name = `bit-user-{site_title_stripped}` (lowercase, alphanumeric only) — computed from
`kernel_config.site_title` (strip non-alnum, lowercase), via `RoleUser::getSiteCookieName()`.
Login stores PHP's own `session_id()` in `users_cnxn.cookie`, mapped to `user_id`. Every
subsequent request looks up that cookie value in `users_cnxn` to identify the user
(`RoleUser::getUserIdFromCookie()`) — this is deliberately separate from PHP's own session
mechanism, even though the two share the same cookie name (`session_name()` is set to the site
cookie name, but the actual auth check is the `users_cnxn` row lookup, not PHP session state).
Nuking a row in `users_cnxn` logs that session out immediately — no separate session-expiry
mechanism needed.

**Testing authenticated flows without a password**: `INSERT INTO users_cnxn (user_id, cookie, ip,
last_get, connect_time, get_count) VALUES (<user_id>, '<random hex>', '127.0.0.1', <epoch>,
<epoch>, 1)`, then send that same value as the `bit-user-{site}` cookie in curl. Confirmed working
2026-07-31 (smoke-testing a wiki save fix end-to-end), used routinely since. Clean up the row
afterward (`DELETE FROM users_cnxn WHERE cookie = '...'`) — it doesn't expire on its own. Use
`user_id = 3` on the target site's DB for this, not `1` — `1` is `root`, a placeholder account
without normal role assignments.

## 2026-08-20 — `RolePermUser::loadRoles()` passed `0` instead of `null`, broke role checks sitewide

Found chasing a report that `assign_role_user.php` "wasn't working" for a specific user — turned
out to be two unrelated issues stacked together. **Not a real bug**: that user already had the
expected roles from an earlier manual DB hack, and `addUserToRole()` is correctly idempotent —
re-assigning an already-held role silently no-ops with zero UI feedback, which read as "broken"
even though nothing was wrong. **Real bug**: `loadRoles()` called `$this->getRoles( 0,
$pForceRefresh )` — `getRoles(?int $pUserId = null, ...)` resolves as `$pUserId ?? $this->mUserId
?? -1`, and passing the literal `0` bypasses that fallback entirely (`??` only triggers on real
`null`), so every `loadRoles()` call queried `users_roles_map WHERE user_id=0 OR
role_id=ANONYMOUS_TEAM_ID` — user_id 0 never exists, so only the universal Anonymous row (via the
`OR`) ever came back. `mRoles` was effectively `['Anonymous']` for every logged-in user,
everywhere.

**Blast radius wider than the one admin page**: `mRoles` also feeds `isInRole()`, a
general-purpose permission-check helper used well beyond `assign_role_user.php` — any non-admin
role check going through it was silently broken the same way sitewide. `isAdmin()` itself uses a
separate code path, unaffected, which is why admin-gated pages never surfaced this.

**Fix**: one-line, `getRoles( 0, ...)` → `getRoles( null, ...)` (`f928a48`), deployed to srv9+srv10
same day. Verified live (all 4 roles show correctly, delete icons on already-assigned roles) on
desktop and re-confirmed on srv9 post-deploy. Full detail in `project_role_assignment_bug` memory,
including the note that `isInRole()`'s wider blast radius was never separately re-tested beyond
this one page — worth a spot-check if any other role-gated, non-admin feature behaves oddly.

## 2026-08-20 — post-login redirect always landed on the dashboard, never the originating page

Found live while clicking Sign In from a specific wiki page and landing on the site default
instead. **Two compounding bugs, both in `validate.php`'s referer-exclusion check** (the "don't
recapture `loginfrom` if we just came from an auth-flow page" logic):

1. It compared `$_SERVER['HTTP_REFERER']` against `USERS_PKG_PATH.'/login'` —
   `USERS_PKG_PATH` is a filesystem path constant, not a URL (there's no `USERS_PKG_URL`
   equivalent), so that substring could never match a real referer. Also the wrong page name —
   `/login` predates the page being renamed `signin.php`.
2. **The real remaining bug once #1 was fixed**: the `else` branch unconditionally nulled
   `$_SESSION['loginfrom']` — but that branch fires on *every normal login*, since the referer at
   POST time is naturally `signin.php` itself (the page the form was on). So it wiped the correct
   value `signin.php`'s own GET request had just captured moments earlier, in the same session.
   Confirmed via temporary diagnostic logging (added and removed same session): identical
   `session_id()` across the GET and POST, `loginfrom` present right after being set, gone by the
   time `login()` read it.

**Fix** (`71c6910`): match `signin.php`'s own already-correct pattern (plain `strpos(...,
'signin.php')`, no constant involved) for all three exclusions, and only null
`loginfrom`/`returnto` when there's no referer at all — not whenever the referer happens to be an
auth-flow page (`login()` already `unset()`s `loginfrom` once read, so leaving it alone in the
excluded-referer case carries no stale-data risk). Deployed to srv9+srv10 same day, live
everywhere. Full detail — including why the inline "permission denied, sign in here" flow never
exposed this bug (same-URL render, no separate GET/POST round trip for `loginfrom` to survive
across) — in `project_login_redirect_bug` memory.
