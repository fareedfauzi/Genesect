# Migrating from PseudoNote

PseudoNote Extended installs beside classic PseudoNote. It uses different action IDs, configuration filenames and IDB netnodes, so installation does not replace or modify the classic plugin.

## Optional data migration

1. Back up the IDB normally.
2. Open the IDB with PseudoNote Extended installed.
3. Select **Edit → Plugins → PseudoNote Extended → Migrate Classic PseudoNote Data…**.
4. Review the confirmation and choose **Yes**.
5. Restart IDA and inspect several notes and generated artifacts.

Migration copies only missing values. Existing Extended values win. Classic netnodes and configuration files are never deleted, renamed or overwritten. Re-running migration is safe and reports copied and preserved counts.

Configuration migration checks `~/.pseudonote.ini` and a sibling `PseudoNote.ini`. Missing options are copied into `~/.pseudonote-extended.ini`; existing Extended options are preserved. This can include provider keys present in the classic configuration, so protect both files with appropriate filesystem permissions.

## Rollback

Disable or remove `PseudoNoteExtended.py` and the `pseudonote_extended` folder. Classic PseudoNote data remains intact. Extended netnodes remain in the IDB but are ignored by classic PseudoNote.
