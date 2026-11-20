from __future__ import annotations

import logging
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .config import Settings


class ProfileDatabaseError(RuntimeError):
    pass


class ProfileRepository:
    def __init__(self, settings: Settings) -> None:
        settings.require_database()
        self._connection_string = settings.database_url

    def username_exists(self, username: str) -> bool:
        row = self._fetch_one(
            "username_exists",
            "select 1 from public.profiles where username = %s limit 1",
            (username,),
        )
        return row is not None

    def profile_for_user(self, user_id: str) -> dict[str, Any] | None:
        row = self._fetch_one(
            "profile_for_user",
            "select id::text as id, username from public.profiles where id = %s::uuid limit 1",
            (user_id,),
        )
        return dict(row) if row is not None else None

    def _fetch_one(
        self,
        operation: str,
        query: str,
        parameters: tuple[str, ...],
    ) -> dict[str, Any] | None:
        try:
            with psycopg.connect(
                self._connection_string,
                connect_timeout=5,
                sslmode="require",
                row_factory=dict_row,
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query, parameters)
                    return cursor.fetchone()
        except psycopg.Error as exc:
            logging.error(
                "PostgreSQL profile query failed operation=%s sqlstate=%s",
                operation,
                exc.sqlstate or "unknown",
            )
            raise ProfileDatabaseError(
                "NovaNX profile storage is temporarily unavailable."
            ) from exc
