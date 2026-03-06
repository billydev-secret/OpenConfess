# OpenConfess

Anonymous confession bot for Discord with restart-safe anonymous replies, moderation logging, and server-level controls.

## Features
- Anonymous confession modal (`/confess`)
- Anonymous reply modal via message button
- Private DM request modal (`/dmrequest`)
- Per-user cooldown and per-day posting limits
- Optional DM notifications to original posters when replies arrive
- Admin controls for destination/log channels and behavior toggles
- SQLite persistence for config, limits, and reply-thread metadata

## Requirements
- Python 3.10+
- A Discord bot token

## Setup
1. Install dependencies:
```bash
pip install discord.py python-dotenv
```
2. Create a `.env` file:
```env
DISCORD_TOKEN=your_bot_token_here
DB_PATH=confessions.sqlite3
```
3. Run the bot:
```bash
python OpenConfess.py
```

## Slash Commands

### User Commands
- `/confess` - Open the anonymous confession form.
- `/dmrequest` - Send moderators a private DM request.

### Admin Commands (`/confession ...`)
Requires `Manage Server` or `Administrator`.

- `/confession status` - Show this server's confession settings.
- `/confession set-dest` - Set where anonymous confessions are posted.
- `/confession set-log` - Set where private moderation logs are posted.
- `/confession cooldown` - Set per-user cooldown between posts (seconds).
- `/confession maxchars` - Set max characters for confessions and replies.
- `/confession maxattachments` - Set max attachments allowed per confession.
- `/confession panic` - Enable or disable panic mode (pauses confessions/replies).
- `/confession replies` - Enable or disable anonymous replies.
- `/confession ping-op` - DM original posters when new anonymous replies are posted.
- `/confession perday` - Set per-user daily confession limit (`0` to disable).
- `/confession block` - Block or unblock a member from confessions/replies.
- `/confession post-button` - Post or move the persistent Confess button.

## Notes
- The bot syncs commands on startup.
- If `DB_PATH` is omitted, it defaults to `confessions.sqlite3`.
