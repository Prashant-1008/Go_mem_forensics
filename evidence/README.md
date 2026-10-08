# evidence/

Local, controlled-testing directory for memory images and other evidence
files used while developing and validating GoMemForensics.

**Do not commit real evidence into this directory's tracked contents.**
`.gitignore` excludes everything under `evidence/` except this README, so
files placed here stay local by default - but always double-check `git
status` before staging, especially if `.gitignore` is ever changed.

Never place here:

- real victim data
- real credentials
- private memory dumps
- confidential case material

Memory images used for Phase-by-phase validation should come only from
controlled, clean Go builds (or, where legally and safely available,
controlled malware-analysis samples) - never automatically downloaded
malware. See `docs/validation/validation-plan.md`.
