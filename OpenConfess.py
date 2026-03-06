"""
Confessions Bot (stored thread metadata, restart-persistent anonymous replies)
- discord.py (latest) slash commands + modals + buttons
- Persists guild config, rate-limits, and minimal thread metadata in SQLite

Run:
  python bot.py

Env:
  DISCORD_TOKEN=...
  DB_PATH=confessions.sqlite3   (optional; default)
"""

from __future__ import annotations

import os
import json
import time
import sqlite3
from dataclasses import dataclass
from typing import Optional, Tuple, List, Any
from dotenv import load_dotenv

import discord
from discord import app_commands


# -----------------------------
# Utilities
# -----------------------------
def now_ts() -> int:
    return int(time.time())


def defang_everyone_here(text: str) -> str:
    # Extra safety beyond AllowedMentions.none()
    return (
        text.replace("@everyone", "@\u200beveryone")
            .replace("@here", "@\u200bhere")
    )


def jump_link(guild_id: int, channel_id: int, message_id: int) -> str:
    return f"https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"


load_dotenv()


# -----------------------------
# Persistence (config + rate-limits + thread metadata)
# -----------------------------
@dataclass
class GuildConfig:
    guild_id: int
    dest_channel_id: int
    log_channel_id: int
    cooldown_seconds: int = 120
    max_chars: int = 2000
    max_attachments: int = 4
    panic: bool = False
    replies_enabled: bool = True
    notify_op_on_reply: bool = False
    per_day_limit: int = 0
    launcher_channel_id: int = 0
    launcher_message_id: int = 0
    blocked_user_ids: List[int] = None

    def blocked_set(self) -> set[int]:
        return set(self.blocked_user_ids or [])


class ConfigStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

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
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(guild_config)").fetchall()}
            if "launcher_channel_id" not in cols:
                conn.execute("ALTER TABLE guild_config ADD COLUMN launcher_channel_id INTEGER NOT NULL DEFAULT 0")
            if "launcher_message_id" not in cols:
                conn.execute("ALTER TABLE guild_config ADD COLUMN launcher_message_id INTEGER NOT NULL DEFAULT 0")
            if "notify_op_on_reply" not in cols:
                conn.execute("ALTER TABLE guild_config ADD COLUMN notify_op_on_reply INTEGER NOT NULL DEFAULT 0")
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
            thread_cols = {row["name"] for row in conn.execute("PRAGMA table_info(thread_posts)").fetchall()}
            if "notify_original_author" not in thread_cols:
                conn.execute("ALTER TABLE thread_posts ADD COLUMN notify_original_author INTEGER NOT NULL DEFAULT -1")
            if "created_at" not in thread_cols:
                conn.execute("ALTER TABLE thread_posts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_thread_posts_created_at ON thread_posts(created_at)")
        self.purge_old_thread_posts()

    def get_config(self, guild_id: int) -> Optional[GuildConfig]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM guild_config WHERE guild_id=?",
                (guild_id,)
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
                notify_op_on_reply=bool(row["notify_op_on_reply"]) if "notify_op_on_reply" in row.keys() else False,
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
                cfg.guild_id, cfg.dest_channel_id, cfg.log_channel_id, cfg.cooldown_seconds,
                cfg.max_chars, cfg.max_attachments, int(cfg.panic), int(cfg.replies_enabled),
                int(cfg.notify_op_on_reply),
                cfg.per_day_limit, cfg.launcher_channel_id, cfg.launcher_message_id,
                json.dumps(cfg.blocked_user_ids or []),
            ))

    def set_field(self, guild_id: int, field: str, value: Any) -> None:
        if field not in {
            "dest_channel_id", "log_channel_id", "cooldown_seconds", "max_chars",
            "max_attachments", "panic", "replies_enabled", "per_day_limit",
            "notify_op_on_reply", "launcher_channel_id", "launcher_message_id", "blocked_user_ids"
        }:
            raise ValueError("Invalid field")
        with self._conn() as conn:
            conn.execute(f"UPDATE guild_config SET {field}=? WHERE guild_id=?", (value, guild_id))

    def upsert_thread_post(
        self,
        guild_id: int,
        message_id: int,
        channel_id: int,
        root_message_id: int,
        original_author_id: int,
        notify_original_author: int = -1,
    ) -> None:
        created_at = now_ts()
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
                original_author_id, int(notify_original_author), created_at
            ))
        self.purge_old_thread_posts()

    def get_thread_info(self, guild_id: int, message_id: int) -> Optional[Tuple[int, int, int]]:
        with self._conn() as conn:
            row = conn.execute("""
                SELECT root_message_id, original_author_id, notify_original_author
                FROM thread_posts
                WHERE guild_id=? AND message_id=?
            """, (guild_id, message_id)).fetchone()
            if not row:
                return None
            return int(row["root_message_id"]), int(row["original_author_id"]), int(row["notify_original_author"])

    def purge_old_thread_posts(self, max_age_seconds: int = 7 * 24 * 60 * 60) -> int:
        cutoff = now_ts() - max_age_seconds
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM thread_posts WHERE created_at < ?", (cutoff,))
            return max(cur.rowcount, 0)

    # --- rate limits ---
    def _day_key(self) -> str:
        # User timezone specified as America/Los_Angeles in instructions; in code, keep simple:
        # Use UTC date key to avoid adding tz dependency. Good enough for v1.
        return time.strftime("%Y-%m-%d", time.gmtime())

    def check_and_bump_limits(
        self,
        guild_id: int,
        author_id: int,
        *,
        is_reply: bool,
        cooldown_seconds: int,
        per_day_limit: int
    ) -> Tuple[bool, str]:
        """
        Returns (ok, message). If ok==False, message is an ephemeral error.
        Persists last_* times and daily counts.
        """
        now = now_ts()
        day_key = self._day_key()

        with self._conn() as conn:
            row = conn.execute("""
                SELECT * FROM rate_limits WHERE guild_id=? AND author_id=?
            """, (guild_id, author_id)).fetchone()

            last_confess_at = 0
            last_reply_at = 0
            stored_day_key = day_key
            day_count = 0

            if row:
                last_confess_at = row["last_confess_at"]
                last_reply_at = row["last_reply_at"]
                stored_day_key = row["day_key"]
                day_count = row["day_count"]

            # Reset daily counts if day changes
            if stored_day_key != day_key:
                day_count = 0
                stored_day_key = day_key

            last_at = last_reply_at if is_reply else last_confess_at
            if cooldown_seconds > 0 and (now - last_at) < cooldown_seconds:
                remaining = cooldown_seconds - (now - last_at)
                return False, f"Slow down — you can {'reply' if is_reply else 'post'} again in **{remaining}s**."

            if 0 < per_day_limit <= day_count:
                return False, f"You’ve hit today’s limit (**{per_day_limit}**). Try again tomorrow."

            # bump
            if is_reply:
                last_reply_at = now
            else:
                last_confess_at = now
                day_count += 1  # count only confessions toward per-day by default

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


# -----------------------------
# Embeds + Logging
# -----------------------------
def build_reply_content(content: str) -> str:
    return defang_everyone_here(content)


async def log_confession(
    *,
    log_channel: discord.TextChannel,
    author: discord.Member | discord.User,
    guild_id: int,
    dest_channel_id: int,
    dest_message_id: int,
    title: Optional[str],
    content: str,
) -> Optional[discord.Message]:
    emb = discord.Embed(
        title="Logged Confession",
        description="(Private log entry)",
        timestamp=discord.utils.utcnow()
    )
    emb.add_field(name="Author", value=f"{author.mention} (`{author.id}`)", inline=False)
    emb.add_field(name="Posted", value=f"<#{dest_channel_id}>\n{jump_link(guild_id, dest_channel_id, dest_message_id)}", inline=False)

    # Put content in description if short; otherwise a field.
    safe_content = content if len(content) <= 2000 else (content[:1990] + "…")
    emb.add_field(name="Content", value=safe_content[:1024], inline=False)
    emb.add_field(name="Meta", value=f"guild_id={guild_id}\nchannel_id={dest_channel_id}\nmessage_id={dest_message_id}", inline=False)

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
        timestamp=discord.utils.utcnow()
    )
    emb.add_field(name="Author", value=f"{author.mention} (`{author.id}`)", inline=False)
    emb.add_field(name="Parent", value=jump_link(guild_id, parent_channel_id, parent_message_id), inline=False)
    emb.add_field(name="Reply", value=jump_link(guild_id, reply_channel_id, reply_message_id), inline=False)

    safe_content = content if len(content) <= 2000 else (content[:1990] + "…")
    emb.add_field(name="Content", value=safe_content[:1024], inline=False)
    emb.add_field(name="Meta", value=f"guild_id={guild_id}", inline=False)

    try:
        return await log_channel.send(embed=emb, allowed_mentions=discord.AllowedMentions.none())
    except discord.HTTPException:
        return None


# -----------------------------
# Modals
# -----------------------------
class PingPreferenceSelect(discord.ui.Select):
    def __init__(self):
        super().__init__(
            placeholder="Ping setting",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(label="Ping me on replies", value="yes", default=True),
                discord.SelectOption(label="Do not ping me", value="no"),
            ],
        )


class ConfessModal(discord.ui.Modal, title="Anonymous Confession"):
    confession = discord.ui.TextInput(
        label="Confession",
        style=discord.TextStyle.long,
        required=True,
        max_length=4000,  # we'll enforce guild max_chars later
        placeholder="Say it plainly. No names if you can help it."
    )

    def __init__(
        self,
        bot: "ConfessionsBot",
        cfg: GuildConfig,
    ):
        super().__init__()
        self.bot = bot
        self.cfg = cfg
        self.ping_select = PingPreferenceSelect()
        self.add_item(self.ping_select)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        # Re-check config (it might change mid-flight)
        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await self.bot._safe_ephemeral(interaction, "Bot is not configured. Ask an admin to set destination/log channels.")
            return

        if cfg.panic:
            await self.bot._safe_ephemeral(interaction, "Confessions are temporarily disabled.")
            return

        if interaction.user.id in cfg.blocked_set():
            await self.bot._safe_ephemeral(interaction, "You can't submit confessions on this server.")
            return

        content = str(self.confession.value).strip()
        selected = self.ping_select.values[0] if self.ping_select.values else "yes"
        ping_pref = selected == "yes"

        if len(content) == 0:
            await self.bot._safe_ephemeral(interaction, "Confession can't be empty.")
            return

        heading_text = "# Anonymous Confession"
        # Discord content max is 2000 chars including heading and separators.
        confession_max_chars = min(cfg.max_chars, max(1, 2000 - len(heading_text) - 2))
        if len(content) > confession_max_chars:
            await self.bot._safe_ephemeral(
                interaction,
                f"That's too long (max **{confession_max_chars}** characters for this confession format).",
            )
            return

        ok, msg = self.bot.store.check_and_bump_limits(
            interaction.guild.id,
            interaction.user.id,
            is_reply=False,
            cooldown_seconds=cfg.cooldown_seconds,
            per_day_limit=cfg.per_day_limit
        )
        if not ok:
            await self.bot._safe_ephemeral(interaction, msg)
            return

        dest_channel = interaction.guild.get_channel(cfg.dest_channel_id)
        log_channel = interaction.guild.get_channel(cfg.log_channel_id)

        if not isinstance(dest_channel, discord.TextChannel) or not isinstance(log_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, "Bot config is invalid (missing destination or log channel).")
            return

        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.HTTPException:
            return

        confession_text = f"{heading_text}\n\n{defang_everyone_here(content)}"
        try:
            sent = await dest_channel.send(
                content=confession_text,
                view=self.bot.build_reply_view(),
                allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Failed to post confession (missing perms?).")
            return

        # Log (best effort)
        await log_confession(
            log_channel=log_channel,
            author=interaction.user,
            guild_id=interaction.guild.id,
            dest_channel_id=dest_channel.id,
            dest_message_id=sent.id,
            title=None,
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

        await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)
        await self.bot._safe_complete(interaction)


class ReplyModal(discord.ui.Modal, title="Anonymous Reply"):
    reply = discord.ui.TextInput(
        label="Reply",
        style=discord.TextStyle.long,
        required=True,
        max_length=4000,
        placeholder="Reply kindly. Keep it about the content, not the person."
    )

    def __init__(
        self,
        bot: "ConfessionsBot",
        cfg: GuildConfig,
        parent_channel_id: int,
        parent_message_id: int,
    ):
        super().__init__()
        self.bot = bot
        self.cfg = cfg
        self.parent_channel_id = parent_channel_id
        self.parent_message_id = parent_message_id

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await self.bot._safe_ephemeral(interaction, "Bot is not configured.")
            return

        if cfg.panic:
            await self.bot._safe_ephemeral(interaction, "Confessions are temporarily disabled.")
            return

        if not cfg.replies_enabled:
            await self.bot._safe_ephemeral(interaction, "Anonymous replies are disabled on this server.")
            return

        if interaction.user.id in cfg.blocked_set():
            await self.bot._safe_ephemeral(interaction, "You can't submit anonymous replies on this server.")
            return

        content = str(self.reply.value).strip()
        reply_max_chars = min(cfg.max_chars, 2000)
        if len(content) == 0:
            await self.bot._safe_ephemeral(interaction, "Reply can't be empty.")
            return
        if len(content) > reply_max_chars:
            await self.bot._safe_ephemeral(interaction, f"That's too long (max **{reply_max_chars}** characters for replies).")
            return

        # Replies cooldown: reuse cooldown_seconds but clamp lower bound to 30s for better UX
        reply_cooldown = max(30, int(cfg.cooldown_seconds / 2))

        ok, msg = self.bot.store.check_and_bump_limits(
            interaction.guild.id,
            interaction.user.id,
            is_reply=True,
            cooldown_seconds=reply_cooldown,
            per_day_limit=0  # default: don’t count replies against per-day cap
        )
        if not ok:
            await self.bot._safe_ephemeral(interaction, msg)
            return

        dest_channel = interaction.guild.get_channel(self.parent_channel_id)
        log_channel = interaction.guild.get_channel(cfg.log_channel_id)

        if not isinstance(dest_channel, discord.TextChannel) or not isinstance(log_channel, discord.TextChannel):
            await self.bot._safe_ephemeral(interaction, "Bot config is invalid.")
            return

        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
        except discord.HTTPException:
            return

        # Validate parent message still exists and is one of the bot's replyable posts.
        try:
            parent_msg = await dest_channel.fetch_message(self.parent_message_id)
        except discord.NotFound:
            await self.bot._safe_ephemeral(interaction, "That message no longer exists.")
            return
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Couldn't load that message.")
            return

        thread_info = self.bot.store.get_thread_info(interaction.guild.id, parent_msg.id)
        root_message_id = parent_msg.id
        original_author_id = 0
        notify_original_author = 1 if cfg.notify_op_on_reply else 0
        if thread_info:
            root_message_id, original_author_id, notify_original_author = thread_info
            if notify_original_author not in (0, 1):
                notify_original_author = 1 if cfg.notify_op_on_reply else 0

        reply_content = build_reply_content(content)

        try:
            reply_msg = await dest_channel.send(
                content=reply_content,
                reference=parent_msg,
                view=self.bot.build_reply_view(),
                allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException:
            await self.bot._safe_ephemeral(interaction, "Failed to post reply (missing perms?).")
            return

        self.bot.store.upsert_thread_post(
            guild_id=interaction.guild.id,
            message_id=reply_msg.id,
            channel_id=dest_channel.id,
            root_message_id=root_message_id,
            original_author_id=original_author_id,
            notify_original_author=notify_original_author,
        )

        if notify_original_author == 1 and original_author_id > 0 and original_author_id != interaction.user.id:
            await self.bot.notify_original_poster(
                guild=interaction.guild,
                original_author_id=original_author_id,
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
            content=content
        )

        await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)
        await self.bot._safe_complete(interaction)


# -----------------------------
# Bot
# -----------------------------
class ConfessionsBot(discord.Client):
    def __init__(self, store: ConfigStore):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.messages = True  # needed for fetch_message
        super().__init__(intents=intents)

        self.tree = app_commands.CommandTree(self)
        self.store = store

        self._register_commands()

    async def notify_original_poster(
        self,
        *,
        guild: discord.Guild,
        original_author_id: int,
        reply_channel_id: int,
        reply_message_id: int,
        root_message_id: int,
    ) -> None:
        member = guild.get_member(original_author_id)
        user: Optional[discord.abc.User] = member
        if user is None:
            try:
                user = await self.fetch_user(original_author_id)
            except discord.HTTPException:
                return

        if user is None:
            return

        reply_link = jump_link(guild.id, reply_channel_id, reply_message_id)
        root_link = jump_link(guild.id, reply_channel_id, root_message_id)
        text = (
            f"Someone replied to your anonymous confession in **{guild.name}**.\n"
            f"Reply: {reply_link}\n"
            f"Confession: {root_link}"
        )
        try:
            await user.send(text, allowed_mentions=discord.AllowedMentions.none())
        except (discord.Forbidden, discord.HTTPException):
            return

    def is_valid_reply_target_message(self, guild_id: int, msg: discord.Message) -> bool:
        if not self.user or msg.author.id != self.user.id:
            return False

        # Primary source of truth is our stored thread metadata.
        thread_info = self.store.get_thread_info(guild_id, msg.id)
        if thread_info:
            return True

        # Legacy fallback for older signed reply buttons created before thread metadata existed.
        for row in msg.components:
            for child in row.children:
                custom_id = getattr(child, "custom_id", None)
                if isinstance(custom_id, str) and custom_id.startswith("cr|"):
                    return True
        return False

    def build_reply_view(self) -> discord.ui.View:
        view = discord.ui.View(timeout=None)
        view.add_item(
            discord.ui.Button(
                label="Reply anonymously",
                style=discord.ButtonStyle.secondary,
                custom_id="cr",
            )
        )
        return view

    def build_confess_launcher_view(self, guild_id: int) -> discord.ui.View:
        view = discord.ui.View(timeout=None)
        view.add_item(
            discord.ui.Button(
                label="New confession",
                style=discord.ButtonStyle.primary,
                custom_id=f"nc|{guild_id}",
            )
        )
        return view

    async def _send_confess_launcher(self, channel: discord.TextChannel) -> Optional[discord.Message]:
        try:
            return await channel.send(
                view=self.build_confess_launcher_view(channel.guild.id),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            return None

    async def refresh_confess_launcher(self, guild_id: int, *, trigger_channel_id: Optional[int] = None) -> None:
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
                old_message = await channel.fetch_message(cfg.launcher_message_id)
            except discord.NotFound:
                old_message = None
            except discord.HTTPException:
                old_message = None
            if old_message is not None:
                try:
                    await old_message.delete()
                except discord.HTTPException:
                    return

        sent = await self._send_confess_launcher(channel)
        if sent is None:
            return

        cfg.launcher_channel_id = channel.id
        cfg.launcher_message_id = sent.id
        self.store.upsert_config(cfg)

    async def setup_hook(self) -> None:
        # Sync commands globally (or per-guild for faster iteration)
        await self.tree.sync()

    def _register_commands(self) -> None:
        # /confess command (with attachments)
        @self.tree.command(name="confess", description="Post an anonymous confession.")
        async def confess(
            interaction: discord.Interaction,
        ):
            if not interaction.guild or not interaction.user:
                await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
                return

            modal = ConfessModal(self, GuildConfig(guild_id=interaction.guild.id, dest_channel_id=0, log_channel_id=0))
            await interaction.response.send_modal(modal)

        # Admin config group
        config_group = app_commands.Group(name="confession", description="Confession bot admin tools")

        @config_group.command(name="status", description="Show current configuration.")
        async def status(interaction: discord.Interaction):
            if not interaction.guild:
                await interaction.response.send_message("Server-only.", ephemeral=True)
                return
            if not interaction.user or not isinstance(interaction.user, discord.Member):
                await interaction.response.send_message("Server-only.", ephemeral=True)
                return
            if not interaction.user.guild_permissions.manage_guild and not interaction.user.guild_permissions.administrator:
                await interaction.response.send_message("You need Manage Server to use this.", ephemeral=True)
                return

            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                await interaction.response.send_message("No config set for this guild.", ephemeral=True)
                return

            msg = (
                f"**Destination:** <#{cfg.dest_channel_id}>\n"
                f"**Log:** <#{cfg.log_channel_id}>\n"
                f"**Cooldown:** {cfg.cooldown_seconds}s\n"
                f"**Max chars:** {cfg.max_chars}\n"
                f"**Max attachments:** {cfg.max_attachments}\n"
                f"**Replies enabled:** {cfg.replies_enabled}\n"
                f"**Ping OP on reply (DM):** {cfg.notify_op_on_reply}\n"
                f"**Panic:** {cfg.panic}\n"
                f"**Per-day limit:** {cfg.per_day_limit or 'off'}\n"
                f"**Blocked users:** {len(cfg.blocked_set())}\n"
            )
            await interaction.response.send_message(msg, ephemeral=True)

        @config_group.command(name="set-dest", description="Set destination channel for confessions.")
        @app_commands.describe(channel="Destination channel")
        async def set_dest(interaction: discord.Interaction, channel: discord.TextChannel):
            await self._admin_gate(interaction)
            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                # create minimal config requires log too; set placeholder until set-log
                cfg = GuildConfig(guild_id=interaction.guild.id, dest_channel_id=channel.id, log_channel_id=channel.id)
            cfg.dest_channel_id = channel.id
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Destination set to {channel.mention}", ephemeral=True)

        @config_group.command(name="set-log", description="Set private log channel.")
        @app_commands.describe(channel="Log channel")
        async def set_log(interaction: discord.Interaction, channel: discord.TextChannel):
            await self._admin_gate(interaction)
            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                cfg = GuildConfig(guild_id=interaction.guild.id, dest_channel_id=channel.id, log_channel_id=channel.id)
            cfg.log_channel_id = channel.id
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Log channel set to {channel.mention}", ephemeral=True)

        @config_group.command(name="cooldown", description="Set cooldown between confessions (seconds).")
        async def set_cooldown(interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 86400]):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.cooldown_seconds = int(seconds)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Cooldown set to {seconds}s", ephemeral=True)

        @config_group.command(name="maxchars", description="Set max confession/reply length.")
        async def set_maxchars(interaction: discord.Interaction, n: app_commands.Range[int, 100, 4000]):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.max_chars = int(n)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Max chars set to {n}", ephemeral=True)

        @config_group.command(name="maxattachments", description="Set max attachments on confessions.")
        async def set_maxattachments(interaction: discord.Interaction, n: app_commands.Range[int, 0, 4]):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.max_attachments = int(n)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Max attachments set to {n}", ephemeral=True)

        @config_group.command(name="panic", description="Toggle panic mode (disables confessions and replies).")
        async def set_panic(interaction: discord.Interaction, on: bool):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.panic = bool(on)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Panic mode set to **{on}**", ephemeral=True)

        @config_group.command(name="replies", description="Enable/disable anonymous replies.")
        async def set_replies(interaction: discord.Interaction, on: bool):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.replies_enabled = bool(on)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Anonymous replies enabled = **{on}**", ephemeral=True)

        @config_group.command(name="ping-op", description="DM original poster when a new anonymous reply is posted.")
        async def set_ping_op(interaction: discord.Interaction, on: bool):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.notify_op_on_reply = bool(on)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Ping OP on reply (DM) = **{on}**", ephemeral=True)

        @config_group.command(name="perday", description="Set per-day confession limit (0 = off).")
        async def set_perday(interaction: discord.Interaction, n: app_commands.Range[int, 0, 100]):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            cfg.per_day_limit = int(n)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(f"Per-day confession limit set to **{n or 'off'}**", ephemeral=True)

        @config_group.command(name="block", description="Block or unblock a user from using /confess and replies.")
        async def block_user(interaction: discord.Interaction, user: discord.Member, blocked: bool):
            await self._admin_gate(interaction)
            cfg = self._require_cfg(interaction.guild.id)
            s = cfg.blocked_set()
            if blocked:
                s.add(user.id)
            else:
                s.discard(user.id)
            cfg.blocked_user_ids = sorted(s)
            self.store.upsert_config(cfg)
            await interaction.response.send_message(
                f"{'Blocked' if blocked else 'Unblocked'} {user.mention}.",
                ephemeral=True
            )

        @config_group.command(name="post-button", description="Post a persistent New confession button in a channel.")
        @app_commands.describe(channel="Channel to post the button in")
        async def post_button(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None):
            await self._admin_gate(interaction)

            target_channel = channel or interaction.channel
            if not isinstance(target_channel, discord.TextChannel):
                await interaction.response.send_message("Choose a text channel for the button.", ephemeral=True)
                return

            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                cfg = GuildConfig(
                    guild_id=interaction.guild.id,
                    dest_channel_id=target_channel.id,
                    log_channel_id=target_channel.id,
                )

            if cfg.launcher_channel_id and cfg.launcher_message_id:
                old_channel = interaction.guild.get_channel(cfg.launcher_channel_id)
                if isinstance(old_channel, discord.TextChannel):
                    try:
                        old_message = await old_channel.fetch_message(cfg.launcher_message_id)
                    except discord.NotFound:
                        old_message = None
                    except discord.HTTPException:
                        old_message = None
                    if old_message is not None:
                        try:
                            await old_message.delete()
                        except discord.HTTPException:
                            pass

            sent = await self._send_confess_launcher(target_channel)
            if sent is None:
                await interaction.response.send_message("Failed to post the confession button in that channel.", ephemeral=True)
                return

            cfg.launcher_channel_id = target_channel.id
            cfg.launcher_message_id = sent.id
            self.store.upsert_config(cfg)

        self.tree.add_command(config_group)

    async def _admin_gate(self, interaction: discord.Interaction) -> None:
        if not interaction.guild:
            await interaction.response.send_message("Server-only.", ephemeral=True)
            raise app_commands.AppCommandError("No guild")
        if not interaction.user or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Server-only.", ephemeral=True)
            raise app_commands.AppCommandError("No member")
        if not interaction.user.guild_permissions.manage_guild and not interaction.user.guild_permissions.administrator:
            await interaction.response.send_message("You need Manage Server to use this.", ephemeral=True)
            raise app_commands.AppCommandError("No perms")

    def _require_cfg(self, guild_id: int) -> GuildConfig:
        cfg = self.store.get_config(guild_id)
        if not cfg:
            raise RuntimeError("Guild not configured: set-dest and set-log first.")
        return cfg

    async def on_message(self, message: discord.Message) -> None:
        if not message.guild or not self.user:
            return
        if message.author.bot:
            return

        cfg = self.store.get_config(message.guild.id)
        if not cfg or not cfg.launcher_channel_id or not cfg.launcher_message_id:
            return
        if message.channel.id != cfg.launcher_channel_id:
            return
        if message.id == cfg.launcher_message_id:
            return

        await self.refresh_confess_launcher(message.guild.id, trigger_channel_id=message.channel.id)

    # --- Restart-persistent reply handling ---
    async def on_interaction(self, interaction: discord.Interaction) -> None:
        try:
            if interaction.type != discord.InteractionType.component:
                return
            if not interaction.data or not isinstance(interaction.data, dict):
                return
            custom_id = interaction.data.get("custom_id")
            if not isinstance(custom_id, str):
                return

            if custom_id.startswith("nc|"):
                parts = custom_id.split("|")
                if len(parts) != 2 or not parts[1].isdigit():
                    await self._safe_ephemeral(interaction, "Invalid confession button.")
                    return
                if not interaction.guild or interaction.guild.id != int(parts[1]):
                    await self._safe_ephemeral(interaction, "Invalid confession button.")
                    return

                modal = ConfessModal(
                    self,
                    GuildConfig(guild_id=interaction.guild.id, dest_channel_id=0, log_channel_id=0),
                )
                await interaction.response.send_modal(modal)
                return

            # Accept new static reply button id and legacy signed ids.
            if custom_id != "cr" and not custom_id.startswith("cr|"):
                return
            if not interaction.guild:
                await self._safe_ephemeral(interaction, "Invalid reply target.")
                return

            cfg = self.store.get_config(interaction.guild.id)
            if not cfg:
                await self._safe_ephemeral(interaction, "Bot is not configured.")
                return
            if cfg.panic:
                await self._safe_ephemeral(interaction, "Confessions are temporarily disabled.")
                return
            if not cfg.replies_enabled:
                await self._safe_ephemeral(interaction, "Anonymous replies are disabled on this server.")
                return
            if interaction.user and interaction.user.id in cfg.blocked_set():
                await self._safe_ephemeral(interaction, "You can't submit anonymous replies on this server.")
                return

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

            modal = ReplyModal(
                self,
                cfg,
                parent_channel_id=target_channel.id,
                parent_message_id=target_msg.id,
            )
            await interaction.response.send_modal(modal)

        except Exception:
            try:
                await self._safe_ephemeral(interaction, "Something went wrong handling that reply.")
            except Exception:
                pass

    async def _safe_ephemeral(self, interaction: discord.Interaction, message: str) -> None:
        if interaction.response.is_done():
            try:
                await interaction.followup.send(message, ephemeral=True)
            except Exception:
                pass
        else:
            try:
                await interaction.response.send_message(message, ephemeral=True)
            except Exception:
                pass

    async def _safe_complete(self, interaction: discord.Interaction) -> None:
        # If we deferred with "thinking", remove the placeholder without sending a success message.
        if interaction.response.is_done():
            try:
                await interaction.delete_original_response()
            except Exception:
                pass


# -----------------------------
# Entrypoint
# -----------------------------
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
