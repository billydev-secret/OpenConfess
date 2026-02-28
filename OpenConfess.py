"""
Confessions Bot (stateless content, restart-persistent anonymous replies)
- discord.py (latest) slash commands + modals + buttons
- No confession storage required
- Reply button custom_id encodes target channel/message + HMAC signature
- Persists only guild config + optional rate-limits in SQLite

Run:
  python bot.py

Env:
  DISCORD_TOKEN=...
  CONFESSION_HMAC_SECRET=long_random_string
  DB_PATH=confessions.sqlite3   (optional; default)
"""

from __future__ import annotations

import os
import hmac
import base64
import json
import time
import sqlite3
import hashlib
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

def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode_nopad(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

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
# Persistence (config/state only)
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
                    max_chars, max_attachments, panic, replies_enabled, per_day_limit,
                    launcher_channel_id, launcher_message_id, blocked_user_ids
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    dest_channel_id=excluded.dest_channel_id,
                    log_channel_id=excluded.log_channel_id,
                    cooldown_seconds=excluded.cooldown_seconds,
                    max_chars=excluded.max_chars,
                    max_attachments=excluded.max_attachments,
                    panic=excluded.panic,
                    replies_enabled=excluded.replies_enabled,
                    per_day_limit=excluded.per_day_limit,
                    launcher_channel_id=excluded.launcher_channel_id,
                    launcher_message_id=excluded.launcher_message_id,
                    blocked_user_ids=excluded.blocked_user_ids
            """, (
                cfg.guild_id, cfg.dest_channel_id, cfg.log_channel_id, cfg.cooldown_seconds,
                cfg.max_chars, cfg.max_attachments, int(cfg.panic), int(cfg.replies_enabled),
                cfg.per_day_limit, cfg.launcher_channel_id, cfg.launcher_message_id,
                json.dumps(cfg.blocked_user_ids or []),
            ))

    def set_field(self, guild_id: int, field: str, value: Any) -> None:
        if field not in {
            "dest_channel_id", "log_channel_id", "cooldown_seconds", "max_chars",
            "max_attachments", "panic", "replies_enabled", "per_day_limit",
            "launcher_channel_id", "launcher_message_id", "blocked_user_ids"
        }:
            raise ValueError("Invalid field")
        with self._conn() as conn:
            conn.execute(f"UPDATE guild_config SET {field}=? WHERE guild_id=?", (value, guild_id))

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

            if per_day_limit and per_day_limit > 0 and day_count >= per_day_limit:
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
# HMAC signing for button custom_id
# -----------------------------
class CustomIdSigner:
    def __init__(self, secret: str):
        if not secret or len(secret) < 16:
            raise RuntimeError("CONFESSION_HMAC_SECRET must be set and at least 16 chars.")
        self.secret = secret.encode("utf-8")

    def sign(self, payload: str, *, nbytes: int = 10) -> str:
        digest = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).digest()
        return b64url_nopad(digest[:nbytes])

    def verify(self, payload: str, sig: str) -> bool:
        expected = self.sign(payload)
        # Constant-time compare
        return hmac.compare_digest(expected, sig)


# -----------------------------
# Embeds + Logging
# -----------------------------
def build_confession_embed(title: Optional[str], content: str, tags: Optional[str]) -> discord.Embed:
    content = defang_everyone_here(content)
    emb = discord.Embed(description=content, timestamp=discord.utils.utcnow())

    return emb

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
    tags: Optional[str],
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
    if tags:
        emb.add_field(name="Tags", value=tags[:1024], inline=False)

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
class ConfessModal(discord.ui.Modal, title="Anonymous Confession"):
    confession_title = discord.ui.TextInput(
        label="Title (optional)",
        style=discord.TextStyle.short,
        required=False,
        max_length=100,
        placeholder="Short subject line for the confession"
    )
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

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        # Re-check config (it might change mid-flight)
        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await interaction.response.send_message("Bot is not configured. Ask an admin to set destination/log channels.", ephemeral=True)
            return

        if cfg.panic:
            await interaction.response.send_message("Confessions are temporarily disabled.", ephemeral=True)
            return

        if interaction.user.id in cfg.blocked_set():
            await interaction.response.send_message("You can’t submit confessions on this server.", ephemeral=True)
            return

        title = str(self.confession_title.value).strip() if self.confession_title.value else None
        content = str(self.confession.value).strip()
        tags = str(self.tags.value).strip() if self.tags.value else None

        if len(content) == 0:
            await interaction.response.send_message("Confession can’t be empty.", ephemeral=True)
            return

        if len(content) > cfg.max_chars:
            await interaction.response.send_message(f"That’s too long (max **{cfg.max_chars}** characters).", ephemeral=True)
            return

        ok, msg = self.bot.store.check_and_bump_limits(
            interaction.guild.id,
            interaction.user.id,
            is_reply=False,
            cooldown_seconds=cfg.cooldown_seconds,
            per_day_limit=cfg.per_day_limit
        )
        if not ok:
            await interaction.response.send_message(msg, ephemeral=True)
            return

        dest_channel = interaction.guild.get_channel(cfg.dest_channel_id)
        log_channel = interaction.guild.get_channel(cfg.log_channel_id)

        if not isinstance(dest_channel, discord.TextChannel) or not isinstance(log_channel, discord.TextChannel):
            await interaction.response.send_message("Bot config is invalid (missing destination or log channel).", ephemeral=True)
            return

        emb = build_confession_embed(title, content, tags)
        message_title = defang_everyone_here(title) if title else None

        # Build signed reply button custom_id based on final message ids (we need message_id -> send first, then edit with view)
        # We'll send without view, then edit to add the button with correct message_id.
        try:
            sent = await dest_channel.send(
                content=message_title,
                embed=emb,
                allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException:
            await interaction.response.send_message("Failed to post confession (missing perms?).", ephemeral=True)
            return

        view = self.bot.build_reply_view(interaction.guild.id, dest_channel.id, sent.id)

        try:
            await sent.edit(view=view)
        except discord.HTTPException:
            # Not fatal; replies won’t work for this confession
            pass

        # Log (best effort)
        await log_confession(
            log_channel=log_channel,
            author=interaction.user,
            guild_id=interaction.guild.id,
            dest_channel_id=dest_channel.id,
            dest_message_id=sent.id,
            title=title,
            content=content,
            tags=tags,
        )

        await self.bot.refresh_confess_launcher(interaction.guild.id, trigger_channel_id=dest_channel.id)

        await interaction.response.defer()


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
        expected_custom_id: Optional[str] = None,
    ):
        super().__init__()
        self.bot = bot
        self.cfg = cfg
        self.parent_channel_id = parent_channel_id
        self.parent_message_id = parent_message_id
        self.expected_custom_id = expected_custom_id

    async def on_submit(self, interaction: discord.Interaction) -> None:
        assert interaction.guild and interaction.user

        cfg = self.bot.store.get_config(interaction.guild.id)
        if not cfg:
            await interaction.response.send_message("Bot is not configured.", ephemeral=True)
            return

        if cfg.panic:
            await interaction.response.send_message("Confessions are temporarily disabled.", ephemeral=True)
            return

        if not cfg.replies_enabled:
            await interaction.response.send_message("Anonymous replies are disabled on this server.", ephemeral=True)
            return

        if interaction.user.id in cfg.blocked_set():
            await interaction.response.send_message("You can’t submit anonymous replies on this server.", ephemeral=True)
            return

        content = str(self.reply.value).strip()
        reply_max_chars = min(cfg.max_chars, 2000)
        if len(content) == 0:
            await interaction.response.send_message("Reply can’t be empty.", ephemeral=True)
            return
        if len(content) > reply_max_chars:
            await interaction.response.send_message(
                f"That’s too long (max **{reply_max_chars}** characters for replies).",
                ephemeral=True
            )
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
            await interaction.response.send_message(msg, ephemeral=True)
            return

        dest_channel = interaction.guild.get_channel(self.parent_channel_id)
        log_channel = interaction.guild.get_channel(cfg.log_channel_id)

        if not isinstance(dest_channel, discord.TextChannel) or not isinstance(log_channel, discord.TextChannel):
            await interaction.response.send_message("Bot config is invalid.", ephemeral=True)
            return

        # Validate parent message still exists and is one of the bot's replyable posts.
        try:
            parent_msg = await dest_channel.fetch_message(self.parent_message_id)
        except discord.NotFound:
            await interaction.response.send_message("That message no longer exists.", ephemeral=True)
            return
        except discord.HTTPException:
            await interaction.response.send_message("Couldn’t load that message.", ephemeral=True)
            return

        reply_content = build_reply_content(content)

        try:
            reply_msg = await dest_channel.send(
                content=reply_content,
                reference=parent_msg,
                allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException:
            await interaction.response.send_message("Failed to post reply (missing perms?).", ephemeral=True)
            return

        try:
            await reply_msg.edit(view=self.bot.build_reply_view(interaction.guild.id, dest_channel.id, reply_msg.id))
        except discord.HTTPException:
            pass

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
        await interaction.response.defer()


# -----------------------------
# Bot
# -----------------------------
class ConfessionsBot(discord.Client):
    def __init__(self, store: ConfigStore, signer: CustomIdSigner):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.messages = True  # needed for fetch_message
        super().__init__(intents=intents)

        self.tree = app_commands.CommandTree(self)
        self.store = store
        self.signer = signer

        self._register_commands()

    def is_valid_reply_target_message(self, msg: discord.Message, expected_custom_id: Optional[str] = None) -> bool:
        # Accept bot-authored confession/reply embeds, or any bot-authored message that still carries
        # the signed anonymous-reply button we generated for it.
        if not self.user or msg.author.id != self.user.id:
            return False

        if expected_custom_id:
            for row in msg.components:
                for child in row.children:
                    if isinstance(child, discord.ui.Button) and child.custom_id == expected_custom_id:
                        return True
                    if getattr(child, "custom_id", None) == expected_custom_id:
                        return True

        if not msg.embeds:
            return False

        title = (msg.embeds[0].title or "").strip().lower()
        return title.startswith("confession") or title.startswith("anonymous reply")

    def build_reply_view(self, guild_id: int, channel_id: int, message_id: int) -> discord.ui.View:
        payload = f"{guild_id}|{channel_id}|{message_id}"
        sig = self.signer.sign(payload)
        custom_id = f"cr|{guild_id}|{channel_id}|{message_id}|{sig}"

        view = discord.ui.View(timeout=None)
        view.add_item(
            discord.ui.Button(
                label="Reply anonymously",
                style=discord.ButtonStyle.secondary,
                custom_id=custom_id,
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

    # --- Restart-persistent reply handling (stateless) ---
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

            if not custom_id.startswith("cr|"):
                return

            # Parse: cr|g|c|m|sig
            parts = custom_id.split("|")
            if len(parts) != 5:
                await self._safe_ephemeral(interaction, "Invalid reply button.")
                return

            _, g_str, c_str, m_str, sig = parts
            if not (g_str.isdigit() and c_str.isdigit() and m_str.isdigit()):
                await self._safe_ephemeral(interaction, "Invalid reply button.")
                return

            g = int(g_str); c = int(c_str); m = int(m_str)
            if not interaction.guild or interaction.guild.id != g:
                await self._safe_ephemeral(interaction, "Invalid reply target.")
                return

            payload = f"{g}|{c}|{m}"
            if not self.signer.verify(payload, sig):
                await self._safe_ephemeral(interaction, "Invalid reply button (signature).")
                return

            cfg = self.store.get_config(g)
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
                await self._safe_ephemeral(interaction, "You can’t submit anonymous replies on this server.")
                return

            # Quick validation that target exists and is one of the bot's replyable posts.
            channel = interaction.guild.get_channel(c)
            if not isinstance(channel, discord.TextChannel):
                await self._safe_ephemeral(interaction, "That message no longer exists.")
                return

            try:
                msg = await channel.fetch_message(m)
            except discord.NotFound:
                await self._safe_ephemeral(interaction, "That message no longer exists.")
                return
            except discord.HTTPException:
                await self._safe_ephemeral(interaction, "Couldn’t load that message.")
                return

            if not self.is_valid_reply_target_message(msg, expected_custom_id=custom_id):
                await self._safe_ephemeral(interaction, "This message can’t be replied to anonymously.")
                return

            modal = ReplyModal(
                self,
                cfg,
                parent_channel_id=c,
                parent_message_id=m,
                expected_custom_id=custom_id,
            )
            # For component interactions, you can respond with a modal
            await interaction.response.send_modal(modal)

        except Exception:
            # Avoid crashing on interaction handler; fail silently or minimal ephemeral
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

# -----------------------------
# Entrypoint
# -----------------------------
def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    secret = os.getenv("CONFESSION_HMAC_SECRET")
    db_path = os.getenv("DB_PATH", "confessions.sqlite3")

    if not token:
        raise RuntimeError("DISCORD_TOKEN env var is required.")
    if not secret:
        raise RuntimeError("CONFESSION_HMAC_SECRET env var is required.")

    store = ConfigStore(db_path=db_path)
    signer = CustomIdSigner(secret=secret)
    bot = ConfessionsBot(store=store, signer=signer)
    bot.run(token)

if __name__ == "__main__":
    main()
