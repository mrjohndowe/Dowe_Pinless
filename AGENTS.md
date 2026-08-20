# Project Agent Instructions

## Git handoff

- After making project changes, always include the relevant Git commands the user can run to stage, commit, and push those changes.
- Tailor the staging command to the files changed in the task; do not blindly stage unrelated working-tree changes.
- Do not run, recommend, or include `git diff` commands.
- Do not commit or push unless the user explicitly asks the agent to do so.
- Treat every push as a synchronized push: first pull the current remote branch with rebase, then push that same branch.
- When handing off push commands, include both the synchronization pull and the subsequent push; do not provide a standalone `git push` command.
