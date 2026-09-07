# Contributing

This repo drives two live environments, each tracked by its own branch:

- `v4.14.5-custom` — the dev/test/staging server. Source of truth for new work.
- `v4.14.5-production` — the production server. Only receives changes that have
  already been proven out on staging, via cherry-pick (see below).

To keep production stable and predictable, **nobody pushes directly to
`v4.14.5-custom` or `v4.14.5-production`.** All changes go through a branch and
a pull request, reviewed before they land anywhere.

## One-time setup

1. Use your own GitHub account with write access to this repo — don't share
   someone else's deploy key.
2. Generate your own SSH key and register it with your GitHub account.
3. Set your own git identity (don't rely on whatever the OS user defaults to):
   ```
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```
4. Work as your own regular OS user account on the servers — **never `sudo`**
   for git commands or file edits in this repo. Files created via `sudo` end
   up owned by `root` instead of the shared group, which breaks things like
   `git stash` for everyone else.

## Making a change (on the staging server)

```
git checkout v4.14.5-custom
git pull
git checkout -b <yourname>/<short-feature-name>
# make your changes, commit as yourself
git push -u origin <yourname>/<short-feature-name>
```

Test your change on the staging server from that branch. Iterate until you're
happy with it. Don't edit `v4.14.5-custom` in place — always work on your
feature branch.

## Opening a pull request

Open a PR from your branch into `v4.14.5-custom` on GitHub. Describe what
changed and why, and how you tested it. A maintainer reviews the diff and
merges it (a regular merge, not squash, so history stays readable) once it's
approved.

After merge:

```
git checkout v4.14.5-custom
git pull
```

Recreate any affected containers and confirm the merged code behaves as
expected on staging — not just your branch in isolation.

## Promoting to production

Once a change has been merged to `v4.14.5-custom` and verified on staging, a
maintainer promotes it to production with a cherry-pick (not a merge), so
production only ever receives changes that were explicitly chosen — never
unrelated or unreviewed work that happens to also be on `v4.14.5-custom`:

```
git checkout v4.14.5-production
git pull
git log v4.14.5-custom --oneline   # find the commit(s) to take
git cherry-pick <commit(s)>
git push
```

Then on the production server:

```
git checkout v4.14.5-production
git pull
```

Recreate the affected containers and verify.

## General notes

- Don't commit generated or environment-specific artifacts: Python virtualenvs,
  `__pycache__/`, real credentials/config files, report output. Check
  `.gitignore` before adding new tooling — extend it rather than committing
  something that shouldn't be tracked.
- If you're not sure whether a change belongs on staging first, it does.
  Production only ever gets things that were already proven out there.
