"""
OpenConfess — Anonymous confessions bot for Discord
Slash commands + modals + buttons, SQLite persistence.

Env:
  DISCORD_TOKEN=...
  DB_PATH=confessions.sqlite3   (optional; default)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Union

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_COOLDOWN_SECONDS = 120
DEFAULT_MAX_CHARS = 2000
DEFAULT_MAX_ATTACHMENTS = 4
THREAD_METADATA_TTL_DAYS = 7
THREAD_METADATA_TTL_SECONDS = THREAD_METADATA_TTL_DAYS * 24 * 60 * 60
MIN_REPLY_COOLDOWN_SECONDS = 30
CONFESSION_HEADER_LENGTH = 2        # len("# ")
MAX_DISCORD_MESSAGE_LENGTH = 2000

ERROR_NOT_CONFIGURED = "Bot is not configured. Ask an admin to set destination/log channels."
ERROR_CONFIG_INVALID = "Bot configuration is invalid. Contact an administrator."
ERROR_PANIC_MODE = "Confessions are temporarily disabled."
ERROR_USER_BLOCKED = "You can't submit confessions on this server."
ERROR_REPLIES_DISABLED = "Anonymous replies are disabled on this server."
ERROR_NOT_SETUP = "Guild not configured: run /confession set-dest and /confession set-log first."

load_dotenv()


# ── Utilities ─────────────────────────────────────────────────────────────────
def now_ts() -> int:
    return int(time.time())


def defang_everyone_here(text: str) -> str:
    return (
        text.replace("@everyone", "@\u200beveryone")
            .replace("@here", "@\u200bhere")
    )


def jump_link(guild_id: int, channel_id: int, message_id: int) -> str:
    return f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"


# ── Data layer ────────────────────────────────────────────────────────────────
@dataclass
class GuildConfig:
    guild_id: int
    dest_channel_id: int
    log_channel_id: int
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    max_chars: int = DEFAULT_MAX_CHARS
    max_attachments: int = DEFAULT_MAX_ATTACHMENTS
    panic: bool = False
    replies_enabled: bool = True
    notify_op_on_reply: bool = False
    per_day_limit: int = 0
    launcher_channel_id: int = 0
    launcher_message_id: int = 0
    blocked_user_ids: Optional[List[int]] = None

    def blocked_set(self) -> set[int]:
        return set(self.blocked_user_ids or [])


class ConfigStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._connection = sqlite3.connect(db_path)
        self._connection.row_factory = sqlite3.Row
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        return self._connection

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS guild_config (
                    guild_id INTEGER PRIMARY KEY,
                    dest_channel_id INTEGER NOT NULL,
                    log_channel_id INTEGER NOT NULL,
                    cooldown_seconds INTEGER NOT NULL DEFAULT 120,
                    max_chars INTEGER NOT NULL DEFAULT 2000,
                    max_attachments INTEGER NOT NULL DEFAULT 4,
                    panic INTEGER NOT NULL DEFAULT 0,
                    replies_enabled INTEGER NOT NULL DEFAULT 1,
                    notify_op_on_reply INTEGER NOT NULL DEFAULT 0,
                    per_day_limit INTEGER NOT NULL DEFAULT 0,
                    launcher_channel_id INTEGER NOT NULL DEFAULT 0,
                    launcher_message_id INTEGER NOT NULL DEFAULT 0,
                    blocked_user_ids TEXT NOT NULL DEFAULT '[]'
                )
            """)
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(guild_config)")}
            for col, defn in [
                ("launcher_channel_id", "INTEGER NOT NULL DEFAULT 0"),
                ("launcher_message_id", "INTEGER NOT NULL DEFAULT 0"),
                ("notify_op_on_reply", "INTEGER NOT NULL DEFAULT 0"),
            ]:
                if col not in cols:
                    conn.execute(f"ALTER TABLE guild_config ADD COLUMN {col} {defn}")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    guild_id INTEGER NOT NULL,
                    author_id INTEGER NOT NULL,
                    last_confess_at INTEGER NOT NULL DEFAULT 0,
                    last_reply_at INTEGER NOT NULL DEFAULT 0,
                    day_key TEXT NOT NULL,
                    day_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (guild_id, author_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS thread_posts (
                    guild_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    root_message_id INTEGER NOT NULL,
                    original_author_id INTEGER NOT NULL,
                    notify_original_author INTEGER NOT NULL DEFAULT -1,
                    created_at INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (guild_id, message_id)
                )
            """)
            thread_cols = {row["name"] for row in conn.execute("PRAGMA table_info(thread_posts)")}
            for col, defn in [
                ("notify_original_author", "INTEGER NOT NULL DEFAULT -1"),
                ("created_at", "INTEGER NOT NULL DEFAULT 0"),
                ("reply_button_message_id", "INTEGER NOT NULL DEFAULT 0"),
                ("discord_thread_id", "INTEGER NOT NULL DEFAULT 0"),
            ]:
                if col not in thread_cols:
                    conn.execute(f"ALTER TABLE thread_posts ADD COLUMN {col} {defn}")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_thread_posts_created_at ON thread_posts(created_at)"
            )
        self.purge_old_thread_posts()

    def get_config(self, guild_id: int) -> Optional[GuildConfig]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM guild_config WHERE guild_id=?", (guild_id,)
            ).fetchone()
            if not row:
                return None
            return GuildConfig(
                guild_id=row["guild_id"],
                dest_channel_id=row["dest_channel_id"],
                log_channel_id=row["log_channel_id"],
                cooldown_seconds=row["cooldown_seconds"],
                max_chars=row["max_chars"],
                max_attachments=row["max_attachments"],
                panic=bool(row["panic"]),
                replies_enabled=bool(row["replies_enabled"]),
                notify_op_on_reply=bool(row["notify_op_on_reply"]),
                per_day_limit=row["per_day_limit"],
                launcher_channel_id=row["launcher_channel_id"],
                launcher_message_id=row["launcher_message_id"],
                blocked_user_ids=json.loads(row["blocked_user_ids"] or "[]"),
            )

    def upsert_config(self, cfg: GuildConfig) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO guild_config (
                    guild_id, dest_channel_id, log_channel_id, cooldown_seconds,
                    max_chars, max_attachments, panic, replies_enabled, notify_op_on_reply,
                    per_day_limit, launcher_channel_id, launcher_message_id, blocked_user_ids
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    dest_channel_id=excluded.dest_channel_id,
                    log_channel_id=excluded.log_channel_id,
                    cooldown_seconds=excluded.cooldown_seconds,
                    max_chars=excluded.max_chars,
                    max_attachments=excluded.max_attachments,
                    panic=excluded.panic,
                    replies_enabled=excluded.replies_enabled,
                    notify_op_on_reply=excluded.notify_op_on_reply,
                    per_day_limit=excluded.per_day_limit,
                    launcher_channel_id=excluded.launcher_channel_id,
                    launcher_message_id=excluded.launcher_message_id,
                    blocked_user_ids=excluded.blocked_user_ids
            """, (
                cfg.guild_id, cfg.dest_channel_id, cfg.log_channel_id,
                cfg.cooldown_seconds, cfg.max_chars, cfg.max_attachments,
                int(cfg.panic), int(cfg.replies_enabled), int(cfg.notify_op_on_reply),
                cfg.per_day_limit, cfg.launcher_channel_id, cfg.launcher_message_id,
                json.dumps(cfg.blocked_user_ids or []),
            ))

    def upsert_thread_post(
        self,
        guild_id: int,
        message_id: int,
        channel_id: int,
        root_message_id: int,
        original_author_id: int,
        notify_original_author: int = -1,
    ) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO thread_posts (
                    guild_id, message_id, channel_id, root_message_id,
                    original_author_id, notify_original_author, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, message_id) DO UPDATE SET
                    channel_id=excluded.channel_id,
                    root_message_id=excluded.root_message_id,
                    original_author_id=excluded.original_author_id,
                    notify_original_author=excluded.notify_original_author,
                    created_at=excluded.created_at
            """, (
                guild_id, message_id, channel_id, root_message_id,
                original_author_id, notify_original_author, now_ts(),
            ))

    def get_thread_info(self, guild_id: int, message_id: int) -> Optional[Tuple[int, int, int]]:
        with self._conn() as conn:
            row = conn.execute("""
                SELECT root_message_id, original_author_id, notify_original_author
                FROM thread_posts WHERE guild_id=? AND message_id=?
            """, (guild_id, message_id)).fetchone()
            if not row:
                return None
            return (
                int(row["root_message_id"]),
                int(row["original_author_id"]),
                int(row["notify_original_author"]),
            )

    def get_discord_thread_id(self, guild_id: int, root_message_id: int) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT discord_thread_id FROM thread_posts WHERE guild_id=? AND message_id=?",
                (guild_id, root_message_id),
            ).fetchone()
            return int(row["discord_thread_id"]) if row else 0

    def update_discord_thread_id(self, guild_id: int, root_message_id: int, thread_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE thread_posts SET discord_thread_id=? WHERE guild_id=? AND message_id=?",
                (thread_id, guild_id, root_message_id),
            )

    def get_reply_button_message_id(self, guild_id: int, root_message_id: int) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT reply_button_message_id FROM thread_posts WHERE guild_id=? AND message_id=?",
                (guild_id, root_message_id),
            ).fetchone()
            return int(row["reply_button_message_id"]) if row else 0

    def update_reply_button_message_id(self, guild_id: int, root_message_id: int, button_message_id: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE thread_posts SET reply_button_message_id=? WHERE guild_id=? AND message_id=?",
                (button_message_id, guild_id, root_message_id),
            )

    def purge_old_thread_posts(self, max_age_seconds: int = THREAD_METADATA_TTL_SECONDS) -> int:
        cutoff = now_ts() - max_age_seconds
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM thread_posts WHERE created_at < ?", (cutoff,))
            return max(cur.rowcount, 0)

    def check_and_bump_limits(
        self,
        guild_id: int,
        author_id: int,
        *,
        is_reply: bool,
        cooldown_seconds: int,
        per_day_limit: int,
    ) -> Tuple[bool, str]:
        """Returns (ok, message). If ok is False, message is an ephemeral error string."""
        now = now_ts()
        day_key = time.strftime("%Y-%m-%d", time.gmtime())

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rate_limits WHERE guild_id=? AND author_id=?",
                (guild_id, author_id),
            ).fetchone()

            last_confess_at, last_reply_at, stored_day_key, day_count = 0, 0, day_key, 0
            if row:
                last_confess_at = row["last_confess_at"]
                last_reply_at = row["last_reply_at"]
                stored_day_key = row["day_key"]
                day_count = row["day_count"]

            if stored_day_key != day_key:
                day_count = 0
                stored_day_key = day_key

            last_at = last_reply_at if is_reply else last_confess_at
            if cooldown_seconds > 0 and (now - last_at) < cooldown_seconds:
                remaining = cooldown_seconds - (now - last_at)
                verb = "reply" if is_reply else "post"
                return False, f"Slow down — you can {verb} again in **{remaining}s**."

            if per_day_limit > 0 and day_count >= per_day_limit:
                return False, f"You've hit today's limit (**{per_day_limit}**). Try again tomorrow."

            if is_reply:
                last_reply_at = now
            else:
                last_confess_at = now
                day_count += 1

            conn.execute("""
                INSERT INTO rate_limits (guild_id, author_id, last_confess_at, last_reply_at, day_key, day_count)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id, author_id) DO UPDATE SET
                    last_confess_at=excluded.last_confess_at,
                    last_reply_at=excluded.last_reply_at,
                    day_key=excluded.day_key,
                    day_count=excluded.day_count
            """, (guild_id, author_id, last_confess_at, last_reply_at, stored_day_key, day_count))

        return True, "ok"


# ── Embed helpers ─────────────────────────────────────────────────────────────
async def log_confession(
    *,
    log_channel: discord.TextChannel,
    author: discord.Member | discord.User,
    guild_id: int,
    dest_channel_id: int,
    dest_message_id: int,
    content: str,
) -> Optional[discord.Message]:
    emb = discord.Embed(
        title="Logged Confession",
        description="(Private log entry)",
        timestamp=discord.utils.utcnow(),
    )
    emb.add_field(name="Author", value=f"{author.mention} (`{author.id}`)", inline=False)
    emb.add_field(
        name="Posted",
        value=f"<#{dest_channel_id}>\n{jump_link(guild_id, dest_channel_id, dest_message_id)}",
        inline=False,
    )
    emb.add_field(name="Content", value=content[:1024], inline=False)
    emb.add_field(
        name="Meta",
        value=f"guild_id={guild_id}\nchannel_id={dest_channel_id}\nmessage_id={dest_message_id}",
        inline=False,
    )
    try:
        return await log_channel.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        return None


async def log_reply(
    *,
    log_channel: discord.TextChannel,
    author: discord.Member | discord.User,
    guild_id: int,
    parent_channel_id: int,
    parent_message_id: int,
    reply_channel_id: int,
    reply_message_id: int,
    content: str,
) -> Optional[discord.Message]:
    emb = discord.Embed(
        title="Logged Reply",
        description="(Private log entry)",
        timestamp=discord.utils.utcnow(),
    )
    emb.add_field(name="Author", value=f"{author.mention} (`{author.id}`)", inline=False)
    emb.add_field(name="Parent", value=jump_link(guild_id, parent_channel_id, parent_message_id), inline=False)
    emb.add_field(name="Reply", value=jump_link(guild_id, reply_channel_id, reply_message_id), inline=False)
    emb.add_field(name="Content", value=content[:1024], inline=False)
    emb.add_field(name="Meta", value=f"guild_id={guild_id}", inline=False)
    try:
        return await log_channel.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        return None


# ── Modals ────────────────────────────────────────────────────────────────────
class DMRequestModal(discord.ui.Modal, title="New DM Request"):
    request = discord.ui.TextInput(
        label="What do you need help with?",
        style=discord.TextStyle.long,
        required=True,
        max_length=2000,
        placeholder="Describe what you'd like to discuss in DMs.",
    )

    def __init__(self, bot: "ConfessionsBot"):
        super().__init__()
        self.bot = bot

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await self.bot._safe_ephemeral(interaction, ERROR_NOT_CONFIGURED)
            return

        log_channel = interaction.guild.get_channel(cfg.log_channel_id)
        if not isinstance(log_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, ERROR_CONFIG_INVALID)
            return

        request_text = str(self.request.value).strip()
        if not request_text:
            await self.bot._safe_ephemeral(interaction, "DM request can't be empty.")
            return

        emb = discord.Embed(
            title="New DM Request",
            description=defang_everyone_here(request_text),
            timestamp=discord.utils.utcnow(),
        )
        emb.add_field(name="Requester", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=False)
        emb.add_field(name="Guild", value=f"{interaction.guild.name} (`{interaction.guild.id}`)", inline=False)

        try:
            await log_channel.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Failed to submit DM request (missing perms?).")
            return

        await self.bot._safe_ephemeral(interaction, "Your DM request was sent to moderators.")


class ConfessModal(discord.ui.Modal, title="Anonymous Confession"):
    confession = discord.ui.TextInput(
        label="Confession",
        style=discord.TextStyle.long,
        required=True,
        max_length=4000,
        placeholder="Say it plainly. No names if you can help it.",
    )
    notify_pref = discord.ui.TextInput(
        label="Notify me on replies? (yes/no)",
        style=discord.TextStyle.short,
        required=False,
        default="yes",
        max_length=3,
        placeholder="yes",
    )

    def __init__(self, bot: "ConfessionsBot"):
        super().__init__()
        self.bot = bot

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await self.bot._safe_ephemeral(interaction, ERROR_NOT_CONFIGURED)
            return
        if cfg.panic:
            await self.bot._safe_ephemeral(interaction, ERROR_PANIC_MODE)
            return
        if interaction.user.id in cfg.blocked_set():
            await self.bot._safe_ephemeral(interaction, ERROR_USER_BLOCKED)
            return

        content = str(self.confession.value).strip()
        pref = str(self.notify_pref.value or "").strip().lower()
        if pref in ("", "y", "yes", "true", "1", "on"):
            ping_pref = True
        elif pref in ("n", "no", "false", "0", "off"):
            ping_pref = False
        else:
            await self.bot._safe_ephemeral(interaction, "Invalid notify setting. Use `yes` or `no`.")
            return

        if not content:
            await self.bot._safe_ephemeral(interaction, "Confession can't be empty.")
            return

        confession_max_chars = min(cfg.max_chars, max(1, MAX_DISCORD_MESSAGE_LENGTH - CONFESSION_HEADER_LENGTH))
        if len(content) > confession_max_chars:
            await self.bot._safe_ephemeral(
                interaction,
                f"That's too long (max **{confession_max_chars}** characters for this confession format).",
            )
            return

        ok, msg = self.bot.store.check_and_bump_limits(
            interaction.guild.id, interaction.user.id,
            is_reply=False, cooldown_seconds=cfg.cooldown_seconds, per_day_limit=cfg.per_day_limit,
        )
        if not ok:
            await self.bot._safe_ephemeral(interaction, msg)
            return

        dest_channel = interaction.guild.get_channel(cfg.dest_channel_id)
        log_channel = interaction.guild.get_channel(cfg.log_channel_id)
        if not isinstance(dest_channel, (discord.TextChannel, discord.ForumChannel)) or not isinstance(log_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, "Bot config is invalid (missing destination or log channel).")
            return

        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.HTTPException:
            return

        if isinstance(dest_channel, discord.ForumChannel):
            # Forum path: create_thread posts the confession as the forum post opener
            try:
                forum_result = await dest_channel.create_thread(
                    name="Anonymous Confession",
                    content=defang_everyone_here(content),
                    allowed_mentions=discord.AllowedMentions.none(),
                    auto_archive_duration=10080,
                )
            except discord.HTTPException:
                await self.bot._safe_ephemeral(interaction, "Failed to post confession (missing perms?).")
                return
            forum_thread = forum_result.thread
            # In Discord forum posts, the thread ID equals the starter message ID
            root_message_id = forum_thread.id
            await log_confession(
                log_channel=log_channel,
                author=interaction.user,
                guild_id=interaction.guild.id,
                dest_channel_id=forum_thread.id,
                dest_message_id=forum_thread.id,
                content=content,
            )
            self.bot.store.upsert_thread_post(
                guild_id=interaction.guild.id,
                message_id=root_message_id,
                channel_id=dest_channel.id,
                root_message_id=root_message_id,
                original_author_id=interaction.user.id,
                notify_original_author=1 if ping_pref else 0,
            )
            self.bot.store.update_discord_thread_id(interaction.guild.id, root_message_id, forum_thread.id)
            try:
                button_msg = await forum_thread.send(
                    view=self.bot.build_reply_button_view(root_message_id),
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                self.bot.store.update_reply_button_message_id(interaction.guild.id, root_message_id, button_msg.id)
            except discord.HTTPException:
                pass
            await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)
            await self.bot._safe_complete(interaction)
            return

        # Text channel path: post confession, then create a thread from it
        try:
            sent = await dest_channel.send(
                content=defang_everyone_here(content),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Failed to post confession (missing perms?).")
            return

        await log_confession(
            log_channel=log_channel,
            author=interaction.user,
            guild_id=interaction.guild.id,
            dest_channel_id=dest_channel.id,
            dest_message_id=sent.id,
            content=content,
        )
        self.bot.store.upsert_thread_post(
            guild_id=interaction.guild.id,
            message_id=sent.id,
            channel_id=dest_channel.id,
            root_message_id=sent.id,
            original_author_id=interaction.user.id,
            notify_original_author=1 if ping_pref else 0,
        )
        try:
            thread = await sent.create_thread(
                name="Anonymous Confession",
                auto_archive_duration=10080,
            )
            self.bot.store.update_discord_thread_id(interaction.guild.id, sent.id, thread.id)
            try:
                button_msg = await thread.send(
                    view=self.bot.build_reply_button_view(sent.id),
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                self.bot.store.update_reply_button_message_id(interaction.guild.id, sent.id, button_msg.id)
            except discord.HTTPException:
                pass
        except discord.HTTPException:
            pass
        await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)
        await self.bot._safe_complete(interaction)


class ReplyModal(discord.ui.Modal, title="Anonymous Reply"):
    reply = discord.ui.TextInput(
        label="Reply",
        style=discord.TextStyle.long,
        required=True,
        max_length=4000,
        placeholder="Reply kindly. Keep it about the content, not the person.",
    )
    notify_pref = discord.ui.TextInput(
        label="Notify me on replies? (yes/no)",
        style=discord.TextStyle.short,
        required=False,
        default="yes",
        max_length=3,
        placeholder="yes",
    )

    def __init__(
        self,
        bot: "ConfessionsBot",
        cfg: GuildConfig,
        parent_channel_id: int,
        parent_message_id: int,
        thread_id: int = 0,
    ):
        super().__init__()
        self.bot = bot
        self.cfg = cfg
        self.parent_channel_id = parent_channel_id
        self.parent_message_id = parent_message_id
        self.thread_id = thread_id

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await self.bot._safe_ephemeral(interaction, "Bot is not configured.")
            return
        if cfg.panic:
            await self.bot._safe_ephemeral(interaction, ERROR_PANIC_MODE)
            return
        if not cfg.replies_enabled:
            await self.bot._safe_ephemeral(interaction, ERROR_REPLIES_DISABLED)
            return
        if interaction.user.id in cfg.blocked_set():
            await self.bot._safe_ephemeral(interaction, "You can't submit anonymous replies on this server.")
            return

        content = str(self.reply.value).strip()
        pref = str(self.notify_pref.value or "").strip().lower()
        if pref in ("", "y", "yes", "true", "1", "on"):
            my_notify_pref = 1
        elif pref in ("n", "no", "false", "0", "off"):
            my_notify_pref = 0
        else:
            await self.bot._safe_ephemeral(interaction, "Invalid notify setting. Use `yes` or `no`.")
            return

        if not content:
            await self.bot._safe_ephemeral(interaction, "Reply can't be empty.")
            return
        reply_max_chars = min(cfg.max_chars, MAX_DISCORD_MESSAGE_LENGTH)
        if len(content) > reply_max_chars:
            await self.bot._safe_ephemeral(
                interaction, f"That's too long (max **{reply_max_chars}** characters for replies)."
            )
            return

        reply_cooldown = max(MIN_REPLY_COOLDOWN_SECONDS, cfg.cooldown_seconds // 2)
        ok, msg = self.bot.store.check_and_bump_limits(
            interaction.guild.id, interaction.user.id,
            is_reply=True, cooldown_seconds=reply_cooldown, per_day_limit=0,
        )
        if not ok:
            await self.bot._safe_ephemeral(interaction, msg)
            return

        log_channel = interaction.guild.get_channel(cfg.log_channel_id)
        if not isinstance(log_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, "Bot config is invalid.")
            return

        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.HTTPException:
            return

        root_message_id = self.parent_message_id
        parent_author_id = 0
        parent_notify_pref = 1 if cfg.notify_op_on_reply else 0
        thread_info = self.bot.store.get_thread_info(interaction.guild.id, self.parent_message_id)
        if thread_info:
            root_message_id, parent_author_id, parent_notify_pref = thread_info
            if parent_notify_pref not in (0, 1):
                parent_notify_pref = 1 if cfg.notify_op_on_reply else 0

        if self.thread_id:
            # Thread-based reply: post into the Discord Thread
            reply_channel: discord.Thread | discord.TextChannel | None = self.bot.get_channel(self.thread_id)  # type: ignore[assignment]
            if reply_channel is None:
                try:
                    reply_channel = await interaction.guild.fetch_channel(self.thread_id)  # type: ignore[assignment]
                except discord.HTTPException:
                    await self.bot._safe_ephemeral(interaction, "Couldn't access the confession thread.")
                    return
            if not isinstance(reply_channel, discord.Thread):
                await self.bot._safe_ephemeral(interaction, "Confession thread is unavailable.")
                return

            try:
                reply_msg = await reply_channel.send(
                    content=defang_everyone_here(content),
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                await self.bot._safe_ephemeral(interaction, "Failed to post reply (missing perms?).")
                return

            self.bot.store.upsert_thread_post(
                guild_id=interaction.guild.id,
                message_id=reply_msg.id,
                channel_id=reply_channel.id,
                root_message_id=root_message_id,
                original_author_id=interaction.user.id,
                notify_original_author=my_notify_pref,
            )

            old_btn_id = self.bot.store.get_reply_button_message_id(interaction.guild.id, root_message_id)
            if old_btn_id:
                try:
                    await reply_channel.get_partial_message(old_btn_id).delete()
                except discord.HTTPException:
                    pass
            try:
                button_msg = await reply_channel.send(
                    view=self.bot.build_reply_button_view(root_message_id),
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                self.bot.store.update_reply_button_message_id(interaction.guild.id, root_message_id, button_msg.id)
            except discord.HTTPException:
                pass

            if parent_author_id > 0 and parent_author_id != interaction.user.id:
                await self.bot.notify_original_poster(
                    guild=interaction.guild,
                    original_author_id=parent_author_id,
                    reply_channel_id=reply_channel.id,
                    reply_message_id=reply_msg.id,
                    root_message_id=root_message_id,
                    confession_channel_id=reply_channel.parent_id or cfg.dest_channel_id,
                )

            parent_channel_id = reply_channel.parent_id or cfg.dest_channel_id
            await log_reply(
                log_channel=log_channel,
                author=interaction.user,
                guild_id=interaction.guild.id,
                parent_channel_id=parent_channel_id,
                parent_message_id=self.parent_message_id,
                reply_channel_id=reply_channel.id,
                reply_message_id=reply_msg.id,
                content=content,
            )
            await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=parent_channel_id)
            await self.bot._safe_complete(interaction)
            return

        # Legacy path: post in the text channel with a message reference
        dest_channel = interaction.guild.get_channel(self.parent_channel_id)
        if not isinstance(dest_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, "Bot config is invalid.")
            return

        try:
            parent_msg = await dest_channel.fetch_message(self.parent_message_id)
        except discord.NotFound:
            await self.bot._safe_ephemeral(interaction, "That message no longer exists.")
            return
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Couldn't load that message.")
            return

        try:
            reply_msg = await dest_channel.send(
                content=defang_everyone_here(content),
                reference=parent_msg,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Failed to post reply (missing perms?).")
            return

        self.bot.store.upsert_thread_post(
            guild_id=interaction.guild.id,
            message_id=reply_msg.id,
            channel_id=dest_channel.id,
            root_message_id=root_message_id,
            original_author_id=interaction.user.id,
            notify_original_author=my_notify_pref,
        )

        old_btn_id = self.bot.store.get_reply_button_message_id(interaction.guild.id, root_message_id)
        if old_btn_id:
            try:
                await dest_channel.get_partial_message(old_btn_id).delete()
            except discord.HTTPException:
                pass
        try:
            button_msg = await dest_channel.send(
                view=self.bot.build_reply_button_view(root_message_id),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            self.bot.store.update_reply_button_message_id(interaction.guild.id, root_message_id, button_msg.id)
        except discord.HTTPException:
            pass

        if parent_author_id > 0 and parent_author_id != interaction.user.id:
            await self.bot.notify_original_poster(
                guild=interaction.guild,
                original_author_id=parent_author_id,
                reply_channel_id=dest_channel.id,
                reply_message_id=reply_msg.id,
                root_message_id=root_message_id,
            )

        await log_reply(
            log_channel=log_channel,
            author=interaction.user,
            guild_id=interaction.guild.id,
            parent_channel_id=dest_channel.id,
            parent_message_id=parent_msg.id,
            reply_channel_id=dest_channel.id,
            reply_message_id=reply_msg.id,
            content=content,
        )
        await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)
        await self.bot._safe_complete(interaction)


# ── Bot ───────────────────────────────────────────────────────────────────────
class ConfessionsBot(commands.Bot):
    def __init__(self, store: ConfigStore):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.messages = True
        super().__init__(command_prefix=[], intents=intents)
        self.store = store
        self._launcher_locks: dict[int, asyncio.Lock] = {}

    async def setup_hook(self) -> None:
        await self.add_cog(ConfessionsCog(self))
        await self.add_cog(AdminCog(self))
        await self.tree.sync()
        asyncio.create_task(self._periodic_purge())

    async def _periodic_purge(self) -> None:
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                self.store.purge_old_thread_posts()
            except Exception:
                log.exception("Error during periodic thread-post purge")
            await asyncio.sleep(3600)

    # ── Launcher management ───────────────────────────────────────────────────
    def _get_launcher_lock(self, guild_id: int) -> asyncio.Lock:
        if guild_id not in self._launcher_locks:
            self._launcher_locks[guild_id] = asyncio.Lock()
        return self._launcher_locks[guild_id]

    @staticmethod
    def _message_has_confess_launcher(message: discord.Message, guild_id: int) -> bool:
        target_id = f"nc|{guild_id}"
        return any(
            getattr(child, "custom_id", None) == target_id
            for row in message.components
            for child in row.children
        )

    async def _cleanup_duplicate_launchers(
        self,
        channel: discord.TextChannel,
        guild_id: int,
        *,
        keep_message_id: int,
    ) -> None:
        if not self.user:
            return
        try:
            async for msg in channel.history(limit=50):
                if msg.id == keep_message_id or msg.author.id != self.user.id:
                    continue
                if not self._message_has_confess_launcher(msg, guild_id):
                    continue
                try:
                    await msg.delete()
                except discord.HTTPException:
                    continue
        except discord.HTTPException:
            return

    async def _send_confess_launcher(self, channel: discord.TextChannel) -> Optional[discord.Message]:
        try:
            return await channel.send(
                view=self.build_confess_launcher_view(channel.guild.id),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            return None

    async def refresh_confess_launcher(
        self, guild_id: int, *, trigger_channel_id: Optional[int] = None
    ) -> None:
        async with self._get_launcher_lock(guild_id):
            cfg = self.store.get_config(guild_id)
            if not cfg or not cfg.launcher_channel_id:
                return
            if trigger_channel_id is not None and trigger_channel_id != cfg.launcher_channel_id:
                return

            guild = self.get_guild(guild_id)
            if guild is None:
                return
            channel = guild.get_channel(cfg.launcher_channel_id)
            if not isinstance(channel, discord.TextChannel):
                return

            if cfg.launcher_message_id:
                try:
                    old = await channel.fetch_message(cfg.launcher_message_id)
                    await old.delete()
                except discord.HTTPException:
                    pass

            sent = await self._send_confess_launcher(channel)
            if sent is None:
                return

            cfg.launcher_channel_id = channel.id
            cfg.launcher_message_id = sent.id
            self.store.upsert_config(cfg)
            await self._cleanup_duplicate_launchers(channel, guild_id, keep_message_id=sent.id)

    # ── View builders ─────────────────────────────────────────────────────────
    @staticmethod
    def build_reply_button_view(root_message_id: int) -> discord.ui.View:
        view = discord.ui.View(timeout=None)
        view.add_item(discord.ui.Button(
            label="Anonymously Reply",
            style=discord.ButtonStyle.secondary,
            custom_id=f"cr|{root_message_id}",
        ))
        return view

    @staticmethod
    def build_confess_launcher_view(guild_id: int) -> discord.ui.View:
        view = discord.ui.View(timeout=None)
        view.add_item(
            discord.ui.Button(label="Confess", style=discord.ButtonStyle.primary, custom_id=f"nc|{guild_id}")
        )
        return view

    # ── DM notification ───────────────────────────────────────────────────────
    async def notify_original_poster(
        self,
        *,
        guild: discord.Guild,
        original_author_id: int,
        reply_channel_id: int,
        reply_message_id: int,
        root_message_id: int,
        confession_channel_id: Optional[int] = None,
    ) -> None:
        user: Optional[discord.abc.User] = guild.get_member(original_author_id)
        if user is None:
            try:
                user = await self.fetch_user(original_author_id)
            except discord.HTTPException:
                return
        if user is None:
            return
        confession_ch = confession_channel_id or reply_channel_id
        text = (
            f"Someone replied to your anonymous confession in **{guild.name}**.\n"
            f"Reply: {jump_link(guild.id, reply_channel_id, reply_message_id)}\n"
            f"Confession: {jump_link(guild.id, confession_ch, root_message_id)}"
        )
        try:
            await user.send(text, allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            pass

    # ── Interaction router (persistent buttons) ───────────────────────────────
    def is_valid_reply_target_message(self, guild_id: int, msg: discord.Message) -> bool:
        if not self.user or msg.author.id != self.user.id:
            return False
        if self.store.get_thread_info(guild_id, msg.id):
            return True
        # Legacy fallback for buttons created before thread metadata was stored.
        return any(
            isinstance(getattr(child, "custom_id", None), str) and child.custom_id.startswith("cr|")
            for row in msg.components
            for child in row.children
        )

    async def on_message(self, message: discord.Message) -> None:
        if not message.guild or not self.user or message.author.bot:
            return
        cfg = self.store.get_config(message.guild.id)
        if (
            cfg
            and cfg.launcher_channel_id
            and cfg.launcher_message_id
            and message.channel.id == cfg.launcher_channel_id
            and message.id != cfg.launcher_message_id
        ):
            await self.refresh_confess_launcher(message.guild.id, trigger_channel_id=message.channel.id)
        await self.process_commands(message)

    async def on_thread_create(self, thread: discord.Thread) -> None:
        """Convert native forum posts into anonymous confessions."""
        if not thread.guild or not self.user or thread.owner_id == self.user.id:
            return
        if not isinstance(thread.parent, discord.ForumChannel):
            return

        cfg = self.store.get_config(thread.guild.id)
        if not cfg or thread.parent_id != cfg.dest_channel_id:
            return

        # Fetch the starter message (REST fetch is reliable even without message_content intent)
        await asyncio.sleep(0.5)  # brief pause to ensure the message is persisted
        try:
            starter_msg = await thread.fetch_message(thread.id)
        except discord.HTTPException:
            return

        author = starter_msg.author
        content = starter_msg.content.strip()

        # Validate: panic mode
        if cfg.panic:
            try:
                await thread.delete()
            except discord.HTTPException:
                pass
            return

        # Validate: blocked users
        if author.id in cfg.blocked_set():
            try:
                await thread.delete()
            except discord.HTTPException:
                pass
            return

        # Validate: content length
        max_chars = min(cfg.max_chars, MAX_DISCORD_MESSAGE_LENGTH)
        if not content or len(content) > max_chars:
            return  # leave the post; don't silently delete something we can't repost

        # Validate: rate limits — check before deleting so we don't lose the post
        ok, cooldown_msg = self.store.check_and_bump_limits(
            thread.guild.id, author.id,
            is_reply=False, cooldown_seconds=cfg.cooldown_seconds, per_day_limit=cfg.per_day_limit,
        )
        if not ok:
            try:
                await thread.delete()
                await author.send(
                    f"Your confession in **{thread.guild.name}** was removed because {cooldown_msg.lower()}\n"
                    "Please try again later.",
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                pass
            return

        log_channel = thread.guild.get_channel(cfg.log_channel_id)
        if not isinstance(log_channel, discord.TextChannel):
            return

        # Delete the native (non-anonymous) post
        try:
            await thread.delete()
        except discord.Forbidden:
            return  # no permission to delete; can't anonymize
        except discord.HTTPException:
            return

        # Repost as anonymous forum thread
        forum_channel = thread.parent
        try:
            forum_result = await forum_channel.create_thread(
                name="Anonymous Confession",
                content=defang_everyone_here(content),
                allowed_mentions=discord.AllowedMentions.none(),
                auto_archive_duration=10080,
            )
        except discord.HTTPException:
            log.exception("Failed to repost native forum post as anonymous (guild=%r)", thread.guild.id)
            return

        anon_thread = forum_result.thread
        root_message_id = anon_thread.id

        await log_confession(
            log_channel=log_channel,
            author=author,
            guild_id=thread.guild.id,
            dest_channel_id=anon_thread.id,
            dest_message_id=anon_thread.id,
            content=content,
        )
        self.store.upsert_thread_post(
            guild_id=thread.guild.id,
            message_id=root_message_id,
            channel_id=forum_channel.id,
            root_message_id=root_message_id,
            original_author_id=author.id,
            notify_original_author=1,
        )
        self.store.update_discord_thread_id(thread.guild.id, root_message_id, anon_thread.id)
        try:
            button_msg = await anon_thread.send(
                view=self.build_reply_button_view(root_message_id),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            self.store.update_reply_button_message_id(thread.guild.id, root_message_id, button_msg.id)
        except discord.HTTPException:
            pass

    async def on_interaction(self, interaction: discord.Interaction) -> None:
        custom_id: Optional[str] = None
        action = "interaction"
        try:
            if interaction.type != discord.InteractionType.component:
                return
            if not interaction.data or not isinstance(interaction.data, dict):
                return
            custom_id = interaction.data.get("custom_id")
            if not isinstance(custom_id, str):
                return

            if custom_id.startswith("nc|"):
                action = "new confession"
                parts = custom_id.split("|")
                if len(parts) != 2 or not parts[1].isdigit():
                    await self._safe_ephemeral(interaction, "Invalid confession button.")
                    return
                if not interaction.guild or interaction.guild.id != int(parts[1]):
                    await self._safe_ephemeral(interaction, "Invalid confession button.")
                    return
                if not interaction.response.is_done():
                    await interaction.response.send_modal(ConfessModal(self))
                return

            if custom_id != "cr" and not custom_id.startswith("cr|"):
                return
            action = "anonymous reply"

            if not interaction.guild:
                await self._safe_ephemeral(interaction, "Invalid reply target.")
                return

            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                await self._safe_ephemeral(interaction, "Bot is not configured.")
                return
            if cfg.panic:
                await self._safe_ephemeral(interaction, ERROR_PANIC_MODE)
                return
            if not cfg.replies_enabled:
                await self._safe_ephemeral(interaction, ERROR_REPLIES_DISABLED)
                return
            if interaction.user and interaction.user.id in cfg.blocked_set():
                await self._safe_ephemeral(interaction, "You can't submit anonymous replies on this server.")
                return

            if custom_id.startswith("cr|"):
                # New-style button: custom_id encodes the root confession message ID
                parts = custom_id.split("|")
                if len(parts) != 2 or not parts[1].isdigit():
                    await self._safe_ephemeral(interaction, "Invalid reply button.")
                    return
                root_message_id = int(parts[1])
                if not self.store.get_thread_info(interaction.guild.id, root_message_id):
                    await self._safe_ephemeral(interaction, "This confession can no longer be replied to.")
                    return
                discord_thread_id = self.store.get_discord_thread_id(interaction.guild.id, root_message_id)
                if not interaction.response.is_done():
                    await interaction.response.send_modal(
                        ReplyModal(
                            self, cfg,
                            parent_channel_id=cfg.dest_channel_id,
                            parent_message_id=root_message_id,
                            thread_id=discord_thread_id,
                        )
                    )
                return

            # Legacy plain "cr" button: the clicked message is the reply target
            target_msg = interaction.message
            if target_msg is None:
                await self._safe_ephemeral(interaction, "That message no longer exists.")
                return
            target_channel = target_msg.channel
            if not isinstance(target_channel, discord.TextChannel):
                await self._safe_ephemeral(interaction, "That message no longer exists.")
                return
            if not self.is_valid_reply_target_message(interaction.guild.id, target_msg):
                await self._safe_ephemeral(interaction, "This message can't be replied to anonymously.")
                return

            if not interaction.response.is_done():
                await interaction.response.send_modal(
                    ReplyModal(self, cfg, parent_channel_id=target_channel.id, parent_message_id=target_msg.id)
                )

        except discord.Forbidden:
            log.exception(
                "Missing access during %s (custom_id=%r guild=%r user=%r)",
                action, custom_id, interaction.guild_id,
                interaction.user.id if interaction.user else None,
            )
            await self._safe_ephemeral(interaction, "I don't have enough access to handle that action.")
        except discord.HTTPException as exc:
            if exc.code in (40060, 10062):
                log.debug("Stale interaction during %s (code=%r)", action, exc.code)
                return
            log.exception(
                "HTTP error during %s (custom_id=%r guild=%r user=%r)",
                action, custom_id, interaction.guild_id,
                interaction.user.id if interaction.user else None,
            )
            await self._safe_ephemeral(interaction, "Discord rejected that interaction. Please try again.")
        except Exception:
            log.exception(
                "Unexpected error during %s (custom_id=%r guild=%r user=%r)",
                action, custom_id, interaction.guild_id,
                interaction.user.id if interaction.user else None,
            )
            await self._safe_ephemeral(interaction, f"Something went wrong handling that {action}.")

    # ── Interaction helpers ───────────────────────────────────────────────────
    async def _safe_ephemeral(self, interaction: discord.Interaction, message: str) -> None:
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except Exception:
            pass

    async def _safe_complete(self, interaction: discord.Interaction) -> None:
        if interaction.response.is_done():
            try:
                await interaction.delete_original_response()
            except Exception:
                pass


# ── Cogs ──────────────────────────────────────────────────────────────────────
class ConfessionsCog(commands.Cog, name="Confessions"):
    """User-facing confession commands."""

    def __init__(self, bot: ConfessionsBot):
        self.bot = bot

    @app_commands.command(name="confess", description="Open the anonymous confession form.")
    @app_commands.guild_only()
    async def confess(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_modal(ConfessModal(self.bot))

    @app_commands.command(name="dmrequest", description="Send moderators a private DM request.")
    @app_commands.guild_only()
    async def dmrequest(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_modal(DMRequestModal(self.bot))


class AdminCog(commands.Cog, name="Admin"):
    """Admin confession management commands."""

    confession = app_commands.Group(
        name="confession",
        description="Admin tools for anonymous confessions",
        guild_only=True,
        default_permissions=discord.Permissions(manage_guild=True),
    )

    def __init__(self, bot: ConfessionsBot):
        self.bot = bot
        super().__init__()

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _require_cfg(self, guild_id: int) -> GuildConfig:
        cfg = self.bot.store.get_config(guild_id)
        if not cfg:
            raise RuntimeError(ERROR_NOT_SETUP)
        return cfg

    def _get_or_create_cfg(self, guild_id: int, fallback_channel_id: int) -> GuildConfig:
        """Return existing config, or a new minimal one using fallback_channel_id for unset channels."""
        cfg = self.bot.store.get_config(guild_id)
        if cfg is None:
            cfg = GuildConfig(
                guild_id=guild_id,
                dest_channel_id=fallback_channel_id,
                log_channel_id=fallback_channel_id,
            )
        return cfg

    async def cog_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        if isinstance(error, app_commands.CommandInvokeError) and isinstance(error.original, RuntimeError):
            await self.bot._safe_ephemeral(interaction, str(error.original))
            return
        log.exception(
            "Admin command error (command=%r guild=%r user=%r)",
            interaction.command.name if interaction.command else None,
            interaction.guild_id,
            interaction.user.id if interaction.user else None,
            exc_info=error,
        )
        await self.bot._safe_ephemeral(interaction, "An unexpected error occurred. Please try again.")

    # ── Commands ──────────────────────────────────────────────────────────────
    @confession.command(name="status", description="Show this server's confession settings.")
    async def status(self, interaction: discord.Interaction) -> None:
        assert interaction.guild
        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await interaction.response.send_message("No config set for this guild.", ephemeral=True)
            return
        msg = (
            f"**Destination:** <#{cfg.dest_channel_id}>\n"
            f"**Log:** <#{cfg.log_channel_id}>\n"
            f"**Cooldown:** {cfg.cooldown_seconds}s\n"
            f"**Max chars:** {cfg.max_chars}\n"
            f"**Replies enabled:** {cfg.replies_enabled}\n"
            f"**Ping OP on reply (DM):** {cfg.notify_op_on_reply}\n"
            f"**Panic:** {cfg.panic}\n"
            f"**Per-day limit:** {cfg.per_day_limit or 'off'}\n"
            f"**Blocked users:** {len(cfg.blocked_set())}\n"
        )
        await interaction.response.send_message(msg, ephemeral=True)

    @confession.command(name="set-dest", description="Set where anonymous confessions are posted (text or forum channel).")
    @app_commands.describe(channel="Destination channel (text or forum)")
    async def set_dest(self, interaction: discord.Interaction, channel: Union[discord.TextChannel, discord.ForumChannel]) -> None:
        assert interaction.guild
        cfg = self._get_or_create_cfg(interaction.guild.id, channel.id)
        cfg.dest_channel_id = channel.id
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Destination set to {channel.mention}", ephemeral=True)

    @confession.command(name="set-log", description="Set where private moderation logs are posted.")
    @app_commands.describe(channel="Log channel")
    async def set_log(self, interaction: discord.Interaction, channel: discord.TextChannel) -> None:
        assert interaction.guild
        cfg = self._get_or_create_cfg(interaction.guild.id, channel.id)
        cfg.log_channel_id = channel.id
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Log channel set to {channel.mention}", ephemeral=True)

    @confession.command(name="cooldown", description="Set per-user cooldown between posts (seconds).")
    async def set_cooldown(self, interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 86400]) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.cooldown_seconds = seconds
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Cooldown set to {seconds}s", ephemeral=True)

    @confession.command(name="maxchars", description="Set max characters for confessions and replies.")
    async def set_maxchars(self, interaction: discord.Interaction, n: app_commands.Range[int, 100, 4000]) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.max_chars = n
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Max chars set to {n}", ephemeral=True)

    @confession.command(name="panic", description="Enable or disable panic mode (pauses confessions/replies).")
    async def set_panic(self, interaction: discord.Interaction, on: bool) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.panic = on
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Panic mode set to **{on}**", ephemeral=True)

    @confession.command(name="replies", description="Enable or disable anonymous replies.")
    async def set_replies(self, interaction: discord.Interaction, on: bool) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.replies_enabled = on
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Anonymous replies enabled = **{on}**", ephemeral=True)

    @confession.command(name="ping-op", description="DM original posters when new anonymous replies are posted.")
    async def set_ping_op(self, interaction: discord.Interaction, on: bool) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.notify_op_on_reply = on
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(f"Ping OP on reply (DM) = **{on}**", ephemeral=True)

    @confession.command(name="perday", description="Set per-user daily confession limit (0 to disable).")
    async def set_perday(self, interaction: discord.Interaction, n: app_commands.Range[int, 0, 100]) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        cfg.per_day_limit = n
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(
            f"Per-day confession limit set to **{n or 'off'}**", ephemeral=True
        )

    @confession.command(name="block", description="Block or unblock a member from confessions/replies.")
    async def block_user(self, interaction: discord.Interaction, user: discord.Member, blocked: bool) -> None:
        assert interaction.guild
        cfg = self._require_cfg(interaction.guild.id)
        s = cfg.blocked_set()
        s.add(user.id) if blocked else s.discard(user.id)
        cfg.blocked_user_ids = sorted(s)
        self.bot.store.upsert_config(cfg)
        await interaction.response.send_message(
            f"{'Blocked' if blocked else 'Unblocked'} {user.mention}.", ephemeral=True
        )

    @confession.command(name="post-button", description="Post or move the persistent Confess button.")
    @app_commands.describe(channel="Channel to post the button in")
    async def post_button(
        self, interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None
    ) -> None:
        assert interaction.guild
        async with self.bot._get_launcher_lock(interaction.guild.id):
            target_channel = channel or interaction.channel
            if not isinstance(target_channel, discord.TextChannel):
                await interaction.response.send_message("Choose a text channel for the button.", ephemeral=True)
                return

            cfg = self._get_or_create_cfg(interaction.guild.id, target_channel.id)

            if cfg.launcher_channel_id and cfg.launcher_message_id:
                old_ch = interaction.guild.get_channel(cfg.launcher_channel_id)
                if isinstance(old_ch, discord.TextChannel):
                    try:
                        old_msg = await old_ch.fetch_message(cfg.launcher_message_id)
                        await old_msg.delete()
                    except discord.HTTPException:
                        pass

            sent = await self.bot._send_confess_launcher(target_channel)
            if sent is None:
                await interaction.response.send_message(
                    "Failed to post the confession button in that channel.", ephemeral=True
                )
                return

            cfg.launcher_channel_id = target_channel.id
            cfg.launcher_message_id = sent.id
            self.bot.store.upsert_config(cfg)
            await self.bot._cleanup_duplicate_launchers(
                target_channel, interaction.guild.id, keep_message_id=sent.id
            )
            await interaction.response.send_message(
                f"Confession button posted in {target_channel.mention}.", ephemeral=True
            )


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    db_path = os.getenv("DB_PATH", "confessions.sqlite3")
    if not token:
        raise RuntimeError("DISCORD_TOKEN env var is required.")
    store = ConfigStore(db_path=db_path)
    bot = ConfessionsBot(store=store)
    bot.run(token)


if __name__ == "__main__":
    main()
