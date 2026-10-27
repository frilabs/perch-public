# Working agreements

- Read `docs/HANDOFF.md` first.
- Work within a maintainer-approved brief. Keep changes scoped to the requested task.
- Never commit secrets, deployment configuration, account identities or personal operational notes. Use synthetic examples and document environment variable names in `.env.example`.
- Work on branches and submit pull requests. Merge, deployment and publication require explicit maintainer approval.
- Use the included Perch brand assets; retain copyright and third-party notices.
- Finish and run `npm run check` before pushing. Avoid intermediate pushes that consume CI resources. If CI cannot run, report the reason and retain local verification evidence.
