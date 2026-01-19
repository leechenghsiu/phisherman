# Phisherman

[![Deployed on Zeabur](https://zeabur.com/deployed-on-zeabur-dark.svg)](https://zeabur.com/referral?referralCode=leechenghsiu&utm_source=leechenghsiu)

Automated scam site monitor and abuse reporter. Monitors target domains, detects hosting providers via WHOIS, and sends abuse reports with one click through Discord.

## Features

- Periodic DNS monitoring to detect if scam sites are online
- Automatic WHOIS lookup to find hosting provider abuse contacts
- Discord notifications with one-click abuse report sending
- One-time secure tokens for report links (24h expiry)
- Email delivery via Resend

## Setup

### 1. Install dependencies

```bash
bun install
```

### 2. Configure environment variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description | Required |
|----------|-------------|----------|
| `TARGET_URL` | Domain to monitor (without protocol) | Yes |
| `DISCORD_WEBHOOK` | Discord webhook URL for notifications | Yes |
| `RESEND_API_KEY` | Resend API key for sending emails | Yes |
| `MY_EMAIL` | Sender email address (must be verified in Resend) | Yes |
| `TEST_EMAIL` | Your email for test sends via Discord | Yes |
| `CRON_SCHEDULE` | Cron expression for check frequency (default: `0 */6 * * *`) | No |
| `SERVER_URL` | Override server URL (auto-detected on Zeabur) | No |

### 3. Run

```bash
bun start     # Production
bun dev       # Development with watch mode
```

## Cron Schedule Examples

| Schedule | Expression |
|----------|------------|
| Every 6 hours | `0 */6 * * *` |
| Every hour | `0 * * * *` |
| Every 30 minutes | `*/30 * * * *` |
| Daily at midnight | `0 0 * * *` |
| Every 12 hours | `0 */12 * * *` |

## Deployment

### Zeabur

1. Connect your GitHub repo to Zeabur
2. Add environment variables in Zeabur dashboard
3. Deploy - `ZEABUR_WEB_DOMAIN` is auto-detected

## How It Works

1. **Monitor**: Cron job checks if target domain resolves to an IP
2. **Lookup**: If online, performs WHOIS to find abuse email
3. **Alert**: Sends Discord embed with one-time report link
4. **Report**: Clicking the link sends abuse email via Resend

## License

MIT
