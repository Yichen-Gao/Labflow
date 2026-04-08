`write-systemd` generates host-specific units into `contrib/systemd/generated/`.

Those generated files are intentionally ignored by Git because they contain
absolute paths and machine-local settings.
