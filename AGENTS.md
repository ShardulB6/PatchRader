# Agent instructions for PatchRader

This is a hackathon repo. Many people are opening AI-written pull requests against `main` at the same time, so **your main job besides the task itself is to avoid merge conflicts.** Keep PRs small, focused, and quick to merge.

## Before you change anything

1. Get the latest code and branch from it. Never commit directly to `main`.
   ```sh
   git fetch origin
   git switch -c <short-task-name> origin/main
   ```
2. Check what others are already working on:
   ```sh
   gh pr list --state open --json number,title,headRefName,files
   ```
   If an open PR does the same task or heavily edits the same files, tell the prompter before you start. Suggest building on that PR or waiting for it to merge.
3. Read the existing code and follow its stack, structure, and naming. Do not add a second tool for something the repo already does.

### If the app has not been scaffolded yet

Competing scaffolds conflict in nearly every file. If the repo has no app setup, check the open PRs for one. If one exists, do not create another: tell the prompter to wait for it or to build on its branch. If none exists, confirm with the prompter that they want to do the scaffold, and open it as its own PR with no feature work in it.

## Avoiding merge conflicts

**Keep the diff small**
- One task per PR. Split unrelated work into separate PRs.
- Change only the lines the task needs. No drive-by refactors, renames, file moves, or comment cleanups.
- Do not reformat code you are not changing, and do not run a formatter across the whole repo. Format only the files you touched, and only if the repo already has a formatter set up.
- Do not change shared config (linters, formatters, `tsconfig`, CI) unless that is the task.

**Stay out of shared files**
- Prefer new files in a folder for your feature over adding to existing files.
- Keep edits to shared files (routers, navigation, root layouts, global styles, barrel `index` files, config) to the few lines needed to wire your feature in.
- When adding to a list (imports, routes, nav items, dependencies), put the entry in sorted order if the list is sorted. Otherwise add it next to related entries instead of at the very end, where everyone else is adding theirs.
- If the repo uses numbered files such as database migrations, use timestamps rather than sequence numbers so two PRs cannot pick the same number.

**Dependencies**
- Add a dependency only when the task needs it, and use the repo's existing package manager.
- Never hand-edit a lockfile. Commit lockfile changes only when dependencies changed.
- If a lockfile conflicts, take the version from `main` and rerun the install command to regenerate it. Keep both sides of any `package.json` conflict.

**Stay current**
- Before opening a PR, and again if it sits open while `main` moves, rebase and retest:
  ```sh
  git fetch origin
  git rebase origin/main
  ```
- Force-push only your own branch, and only with `git push --force-with-lease`. Never force-push `main` or someone else's branch.

## Resolving conflicts

- Read both sides and keep the intent of both. Someone else's merged work is not yours to discard.
- Do not blindly accept all of `--ours` or `--theirs`. During a rebase those two labels are swapped: `ours` means `main`.
- If the two sides really do contradict each other, stop and ask the prompter instead of guessing.
- After resolving, run the checks below and confirm that no conflict markers remain.

## UI style

If the prompter does not mention a UI style, use [shadcn/ui](https://ui.shadcn.com) and say so in your reply: "No UI style was specified, so I'm using shadcn/ui by default." If the prompter names a style or library, use that instead.

When using shadcn/ui:
- Check for `components.json` first. If it exists, shadcn is already set up, so do not run `init` again.
- Add components with `npx shadcn@latest add <component>`, and only the ones you need. Skip any that are already there rather than overwriting them.
- Do not edit the generated files in `components/ui/`. Wrap or compose them in your feature's folder, because other PRs depend on them too.
- Use the existing theme tokens (such as `bg-primary` and `text-muted-foreground`) rather than hard-coded colors, and leave the global theme alone unless the task is to change it.

## Sponsors

Unless the prompter says otherwise, these are the sponsors this project uses. When a task needs something one of them covers, such as hosting or a domain, use that sponsor rather than choosing another provider, and respect its status.

| Sponsor | How we use it | Status |
| --- | --- | --- |
| DEV Writing Challenge | Turn the Devpost write-up into a post about what we found | Write it near the end |
| GoDaddy Registry | Register the project's domain | Decide on "Rader" vs "Radar" first |
| Vultr | Host the dashboard, and possibly vLLM if GPU credits are available | Not started |
| Entire | Host the repo there | Not started |
| Tiger Data | Store the 6.4M monthly EPSS rows | Loaded on Tiger Cloud |

## Before opening a PR

- Run the repo's lint, type-check, test, and build commands, whichever exist. Report the real results, including failures and anything you could not run.
- Check that `git diff origin/main...HEAD` contains only what the task needs, with no stray files, debug code, or secrets.
- Use a clear title, and in the description say what changed, why, and how you tested it. Add a screenshot for UI changes.
- Do not merge your own PR unless the prompter asks you to.
