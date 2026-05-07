require('dotenv').config();
const { Client } = require('pg');
const bcrypt = require('bcryptjs');

const BASE_URL = 'http://127.0.0.1:3000';
const PASSWORD = 'Pass123!';

function buildClient() {
    return new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
}

function withJson(body) {
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

class SessionClient {
    constructor() {
        this.cookie = '';
    }
    async request(path, init = {}) {
        const headers = { ...(init.headers || {}) };
        if (this.cookie) headers.Cookie = this.cookie;
        const res = await fetch(`${BASE_URL}${path}`, { ...init, headers, redirect: 'manual' });
        const setCookie = res.headers.get('set-cookie');
        if (setCookie) {
            this.cookie = setCookie.split(';')[0];
        }
        return res;
    }
}

async function registerUser(name, email, referralCode, browserFingerprint, deviceFingerprint) {
    const payload = { name, email, password: PASSWORD, referralCode, browserFingerprint, deviceFingerprint };
    const res = await fetch(`${BASE_URL}/api/register`, { method: 'POST', ...withJson(payload) });
    if (!res.ok) throw new Error(`register failed ${email}: ${await res.text()}`);
}

async function loginSession(email) {
    const session = new SessionClient();
    const res = await session.request('/api/login', { method: 'POST', ...withJson({ email, password: PASSWORD }) });
    if (!res.ok) throw new Error(`login failed ${email}: ${await res.text()}`);
    return session;
}

async function submitPayment(session, amount, txid) {
    const form = new FormData();
    form.append('amount', String(amount));
    form.append('transaction_id', txid);
    const res = await session.request('/api/request-payment', { method: 'POST', body: form });
    if (!res.ok) throw new Error(`request-payment failed: ${await res.text()}`);
}

async function approveLatestPayment(session, userId) {
    const listRes = await session.request('/api/admin/payment-requests');
    if (!listRes.ok) throw new Error(`/api/admin/payment-requests failed: ${await listRes.text()}`);
    const items = await listRes.json();
    const pending = items.find((x) => Number(x.user_id) === Number(userId) && String(x.status).toLowerCase() === 'pending');
    if (!pending) throw new Error(`no pending request found for userId=${userId}`);
    const approveRes = await session.request(`/api/admin/payment-requests/${pending.id}/approve`, { method: 'POST' });
    if (!approveRes.ok) throw new Error(`approve failed: ${await approveRes.text()}`);
}

async function run() {
    const db = buildClient();
    await db.connect();
    const token = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const referrerEmail = `referrer_${token}@mail.com`;
    const referredEmail = `referred_${token}@mail.com`;
    const fraudEmail = `fraud_${token}@mail.com`;
    const adminEmail = `admin_${token}@mail.com`;
    const validBrowser = `BROWSER_VALID_${token}`;
    const validDevice = `DEVICE_VALID_${token}`;
    const sameBrowser = `BROWSER_FP_SAME_${token}`;
    const sameDevice = `DEVICE_FP_SAME_${token}`;

    try {
        await registerUser('Referrer', referrerEmail, '', 'REF_BROWSER', 'REF_DEVICE');
        const referrer = (await db.query('SELECT id, referral_code, balance FROM users WHERE email=$1', [referrerEmail])).rows[0];
        if (!referrer?.id || !referrer?.referral_code) throw new Error('referrer missing referral_code');

        await registerUser('Referred User', referredEmail, referrer.referral_code, validBrowser, validDevice);
        const referred = (await db.query('SELECT id, referred_by, balance FROM users WHERE email=$1', [referredEmail])).rows[0];
        const referralCaptured = Number(referred?.referred_by) === Number(referrer.id);

        await registerUser('Admin User', adminEmail, '', 'ADMIN_BROWSER', 'ADMIN_DEVICE');
        const admin = (await db.query('SELECT id FROM users WHERE email=$1', [adminEmail])).rows[0];
        await db.query('UPDATE users SET role=$1, is_admin=TRUE WHERE id=$2', ['admin', admin.id]);

        const referredSession = await loginSession(referredEmail);
        await submitPayment(referredSession, 170, `TX_VALID_${token}`);
        const adminSession = await loginSession(adminEmail);
        const referrerBalanceBefore = Number((await db.query('SELECT balance FROM users WHERE id=$1', [referrer.id])).rows[0].balance || 0);
        const referredBalanceBefore = Number((await db.query('SELECT balance FROM users WHERE id=$1', [referred.id])).rows[0].balance || 0);
        await approveLatestPayment(adminSession, referred.id);
        const referrerBalanceAfter = Number((await db.query('SELECT balance FROM users WHERE id=$1', [referrer.id])).rows[0].balance || 0);
        const referredBalanceAfter = Number((await db.query('SELECT balance FROM users WHERE id=$1', [referred.id])).rows[0].balance || 0);
        const validFlowPass = referralCaptured
            && Math.round((referrerBalanceAfter - referrerBalanceBefore) * 100) / 100 === 50
            && Math.round((referredBalanceAfter - referredBalanceBefore) * 100) / 100 === 190;

        await registerUser('Fraud User', fraudEmail, referrer.referral_code, sameBrowser, sameDevice);
        await db.query('UPDATE users SET browser_fingerprint=$1, device_fingerprint=$2 WHERE id=$3', [sameBrowser, sameDevice, referrer.id]);
        const fraudUser = (await db.query('SELECT id FROM users WHERE email=$1', [fraudEmail])).rows[0];
        const fraudSession = await loginSession(fraudEmail);
        await submitPayment(fraudSession, 170, `TX_FRAUD_${token}`);
        const fraudBonusBefore = Number((await db.query('SELECT balance FROM users WHERE id=$1', [fraudUser.id])).rows[0].balance || 0);
        await approveLatestPayment(adminSession, fraudUser.id);
        const fraudBonusAfter = Number((await db.query('SELECT balance FROM users WHERE id=$1', [fraudUser.id])).rows[0].balance || 0);
        const fraudAttempts = (await db.query('SELECT COUNT(*)::int AS total FROM referral_fraud_attempts WHERE referred_user_id=$1', [fraudUser.id])).rows[0];
        const fraudBlockedPass = Number(fraudAttempts.total || 0) > 0 && Math.round((fraudBonusAfter - fraudBonusBefore) * 100) / 100 === 170;

        const referralApiRes = await adminSession.request('/api/admin/referrals');
        const referralApiJson = referralApiRes.ok ? await referralApiRes.json() : null;
        const apiPass = Boolean(
            referralApiRes.ok
            && Array.isArray(referralApiJson?.bonuses)
            && Array.isArray(referralApiJson?.fraudAttempts)
            && referralApiJson.bonuses.length > 0
            && referralApiJson.fraudAttempts.length > 0
        );

        const allPass = validFlowPass && fraudBlockedPass && apiPass;
        console.log(JSON.stringify({
            referralCaptured,
            validFlowPass,
            fraudBlockedPass,
            apiPass,
            allPass
        }));
        process.exit(allPass ? 0 : 2);
    } finally {
        await db.end();
    }
}

run().catch((err) => {
    console.error(String(err && err.stack || err));
    process.exit(1);
});
