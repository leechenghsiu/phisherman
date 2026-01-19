// Bun auto-loads .env files, no dotenv needed
const crypto = require('crypto');
const express = require('express');
const cron = require('node-cron');
const axios = require('axios');
const dns = require('dns').promises;
const whois = require('whois-json');
const { Resend } = require('resend');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// Auto-detect server URL (Zeabur or custom)
const SERVER_URL = process.env.SERVER_URL ||
    (process.env.ZEABUR_WEB_DOMAIN ? `https://${process.env.ZEABUR_WEB_DOMAIN}` : 'http://localhost:3000');

// --- One-time Token Storage ---
const pendingReports = new Map();
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

function generateReportToken(reportData) {
    const token = crypto.randomBytes(32).toString('hex');
    pendingReports.set(token, {
        ...reportData,
        createdAt: Date.now()
    });
    return token;
}

function consumeReportToken(token) {
    const report = pendingReports.get(token);
    if (!report) return null;

    // Check if expired
    if (Date.now() - report.createdAt > TOKEN_EXPIRY_MS) {
        pendingReports.delete(token);
        return null;
    }

    // One-time use, delete immediately
    pendingReports.delete(token);
    return report;
}

// Periodically clean up expired tokens
setInterval(() => {
    const now = Date.now();
    for (const [token, report] of pendingReports) {
        if (now - report.createdAt > TOKEN_EXPIRY_MS) {
            pendingReports.delete(token);
        }
    }
}, 60 * 60 * 1000); // Every hour

// --- Site Monitor ---
async function checkScamSite() {
    console.log(`[${new Date().toLocaleString()}] Checking target site...`);
    try {
        const addresses = await dns.resolve4(process.env.TARGET_URL);
        const ip = addresses[0];

        // Perform Whois lookup
        const whoisData = await whois(ip);
        const abuseEmail = whoisData.orgAbuseEmail || whoisData.abuseMailbox || whoisData.email;
        const orgName = whoisData.orgName || 'Unknown Provider';

        if (abuseEmail) {
            await sendDiscordAlert(ip, orgName, abuseEmail);
            console.log(`Target alive: ${ip}, Discord notified.`);
        }
    } catch (error) {
        if (error.code === 'ENOTFOUND') {
            console.log(`Target ${process.env.TARGET_URL} is offline.`);
        } else {
            console.error('Check failed:', error.message);
        }
    }
}

// --- Discord Notification ---
async function sendDiscordAlert(ip, orgName, abuseEmail) {
    // Generate one-time token, data stored server-side
    const token = generateReportToken({
        email: abuseEmail,
        ip: ip,
        target: process.env.TARGET_URL
    });

    const reportLink = `${SERVER_URL}/send-report?token=${token}`;

    const payload = {
        embeds: [{
            title: "Phisherman Alert",
            color: 0xE74C3C,
            fields: [
                { name: "Target", value: `\`${process.env.TARGET_URL}\``, inline: false },
                { name: "IP", value: `\`${ip}\``, inline: true },
                { name: "Provider", value: orgName, inline: true },
                { name: "Abuse Email", value: abuseEmail, inline: false }
            ],
            description: `### [Send Abuse Report to ${abuseEmail}](${reportLink})`,
            footer: { text: "Link valid for 24 hours, single use only" }
        }]
    };

    await axios.post(process.env.DISCORD_WEBHOOK, payload);
}

// --- Send Report Endpoint ---
app.get('/send-report', async (req, res) => {
    const { token } = req.query;

    // Validate and consume token (one-time)
    const report = consumeReportToken(token);
    if (!report) {
        return res.status(403).send('<h1>Invalid or Expired Link</h1><p>This link has already been used or has expired.</p>');
    }

    const { email, ip, target } = report;

    try {
        await resend.emails.send({
            from: `Phisherman Monitor <${process.env.MY_EMAIL}>`,
            to: email,
            subject: `URGENT: Abuse Report - Scam Website Detected (${target})`,
            html: `
                <div style="font-family: sans-serif; line-height: 1.6;">
                    <h2>Abuse Report</h2>
                    <p>To the Security/Abuse Department,</p>
                    <p>We have detected a fraudulent website <strong>${target}</strong> hosted on your network at IP <strong>${ip}</strong>.</p>
                    <p>This site is being used for phishing and financial scams. Please investigate and terminate the hosting services for this entity immediately.</p>
                    <hr>
                    <p><small>Sent via Phisherman Automated System</small></p>
                </div>
            `
        });
        res.send('<h1>Report Sent Successfully</h1><p>The hosting provider should receive the report shortly.</p>');
    } catch (err) {
        res.status(500).send('Failed to send: ' + err.message);
    }
});

// --- Start Server & Scheduler ---
const PORT = process.env.PORT || 3000;
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || '0 */6 * * *';

app.listen(PORT, () => {
    console.log(`Phisherman running on port ${PORT}`);
    console.log(`Cron schedule: ${CRON_SCHEDULE}`);
    cron.schedule(CRON_SCHEDULE, checkScamSite);
    // Initial check on startup
    checkScamSite();
});
