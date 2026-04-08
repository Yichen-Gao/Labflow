from __future__ import annotations

import pwd

from .config import LabflowConfig
from .models import DiscoveryResult, UserRecord


def _record_score(record: UserRecord) -> int:
    score = 0
    if record.display_name == record.login_name:
        score += 100
    if record.display_name.startswith(record.login_name):
        score += 20
    if record.display_name.startswith("."):
        score -= 100
    return score


def discover_users(config: LabflowConfig) -> DiscoveryResult:
    users_by_uid: dict[int, UserRecord] = {}
    conflicts: list[str] = []
    root = config.data_root

    if root.exists():
        for child in sorted(root.iterdir()):
            if child.is_symlink():
                continue
            if not child.is_dir():
                continue
            if config.skip_hidden_dirs and child.name.startswith("."):
                continue
            if child.name in config.exclude_dirs:
                continue
            stat_result = child.stat(follow_symlinks=False)
            uid = stat_result.st_uid
            try:
                login_name = pwd.getpwuid(uid).pw_name
            except KeyError:
                login_name = f"uid_{uid}"
            record = UserRecord(
                uid=uid,
                login_name=login_name,
                display_name=child.name,
                data_dir=str(child),
                source="datas",
            )
            existing = users_by_uid.get(uid)
            if existing and existing.data_dir != record.data_dir:
                chosen = existing
                if _record_score(record) > _record_score(existing):
                    chosen = record
                    users_by_uid[uid] = record
                conflicts.append(
                    f"UID {uid} owns multiple directories: {existing.data_dir} and {record.data_dir}. "
                    f"Keeping {chosen.display_name}."
                )
                continue
            users_by_uid[uid] = record

    for extra in config.extra_users:
        existing = users_by_uid.get(extra.uid)
        if existing is None:
            users_by_uid[extra.uid] = UserRecord(
                uid=extra.uid,
                login_name=extra.login_name,
                display_name=extra.display_name,
                data_dir=extra.data_dir,
                source="extra",
            )
            continue
        users_by_uid[extra.uid] = UserRecord(
            uid=extra.uid,
            login_name=extra.login_name or existing.login_name,
            display_name=extra.display_name or existing.display_name,
            data_dir=extra.data_dir or existing.data_dir,
            source="datas+extra",
        )

    for override in config.user_overrides:
        existing = users_by_uid.get(override.uid)
        login_name = override.login_name
        if login_name is None:
            login_name = existing.login_name if existing else f"uid_{override.uid}"
        display_name = override.display_name
        if display_name is None:
            display_name = existing.display_name if existing else login_name
        users_by_uid[override.uid] = UserRecord(
            uid=override.uid,
            login_name=login_name,
            display_name=display_name,
            data_dir=override.data_dir if override.data_dir is not None else (existing.data_dir if existing else None),
            source=override.source or (existing.source if existing else "override"),
        )

    users = sorted(users_by_uid.values(), key=lambda item: (item.uid, item.display_name))
    return DiscoveryResult(users=users, conflicts=conflicts)
