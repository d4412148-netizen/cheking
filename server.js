require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');

// PostgreSQL session store (SAFE)
let pgSession = null;

try {
    pgSession = require('connect-pg-simple')(session);
} catch (err) {
    console.error("❌ connect-pg-simple not loaded:", err.message);
}

// Nodemailer (SAFE)
let nodemailer = null;

try {
    nodemailer = require('nodemailer');
} catch (err) {
    console.error("❌ nodemailer not loaded:", err.message);
}

// Axios (SAFE)
let axios = null;

try {
    axios = require('axios');
} catch (err) {
    console.error("❌ axios not loaded:", err.message);
    axios = {
        get: async () => {
            throw new Error('axios is not available');
        }
    };
}
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
let bcrypt = null;

try {
    bcrypt = require('bcryptjs');
} catch (err) {
    console.error("❌ bcryptjs not loaded:", err.message);
}

const { Pool } = require('pg');
const passport = require('passport');
let createAuthRouter = null;

try {
    createAuthRouter = require('./routes/auth');
} catch (err) {
    console.error("❌ auth routes not loaded:", err.message);
}

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
const upload = multer({ dest: UPLOAD_DIR });

const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
if (!DATABASE_URL) {
    console.error('DATABASE_URL is missing. Starting without database connectivity.');
}

const RAW_SESSION_SECRET = String(process.env.SESSION_SECRET || '');
const SESSION_SECRET = RAW_SESSION_SECRET && RAW_SESSION_SECRET.length >= 32
    ? RAW_SESSION_SECRET
    : 'mrf-fallback-session-secret-change-me-now-please';
if (!RAW_SESSION_SECRET || RAW_SESSION_SECRET.length < 32) {
    console.error('SESSION_SECRET is missing or too short. Using fallback session secret.');
}

const SMSBOWER_API_KEY = process.env.SMSBOWER_API_KEY || 'CHANGE_THIS_API_KEY';
const SMSBOWER_URL = 'https://smsbower.page/stubs/handler_api.php';

const SMSBOWER_WA_SERVICE = 'wa';
const SMSBOWER_FB_SERVICE = 'fb';
const SMSBOWER_IG_SERVICE = 'ig';
const SMSBOWER_SNAPCHAT_SERVICE = 'fu';
const SMSBOWER_TIKTOK_SERVICE = 'lf';
const SMSBOWER_IMO_SERVICE = 'im';
const SMSBOWER_TINDER_SERVICE = 'oi';
const SMSBOWER_TWITTER_SERVICE = 'tw';
const SMSBOWER_AMAZON_SERVICE = 'am';
const SMSBOWER_ALIBABA_SERVICE = 'ab';
const SMSBOWER_CAREEM_SERVICE = 'ls';
const SMSBOWER_SPOTIFY_SERVICE = 'alj';
const SMSBOWER_OPENAI_SERVICE = 'dr';
const SMSBOWER_PAYPAL_SERVICE = 'ts';
const SMSBOWER_ALIEXPRESS_SERVICE = 'hx';
const SMSBOWER_WECHAT_SERVICE = 'wb';
const SMSBOWER_VIBER_SERVICE = 'vi';
const SMSBOWER_UBER_SERVICE = 'ub';
const SMSBOWER_MICROSOFT_SERVICE = 'mm';
const SMSBOWER_SIGNAL_SERVICE = 'bw';
const SMSBOWER_EASYPAY_SERVICE = 'rz';
const SMSBOWER_GOOGLE_SERVICE = 'go';

const EXPIRED_REFUND_MESSAGE = 'Time expired. Your money has been returned to your wallet.';
const ORDER_COOLDOWN_SECONDS = 30;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = String(process.env.BASE_URL || process.env.APP_BASE_URL || '').trim().replace(/\/+$/, '');
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `${BASE_URL}/auth/google/callback`;
const APP_BASE_URL = BASE_URL;
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || '';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_NAME = process.env.ADMIN_NAME || 'Admin';

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const PASSWORD_RESET_TOKEN_TTL_MS = 1000 * 60 * 60;

let databasePoolEnabled = Boolean(DATABASE_URL);

function createDatabaseUnavailableError(message = 'Database is not configured') {
    const error = new Error(message);
    error.code = 'DATABASE_UNAVAILABLE';
    return error;
}

function createFallbackPool(message = 'Database is not configured') {
    return {
        query: async () => {
            throw createDatabaseUnavailableError(message);
        },
        connect: async () => ({
            query: async (sql) => {
                const normalizedSql = String(sql || '').trim().replace(/;$/, '').toUpperCase();
                if (normalizedSql === 'BEGIN' || normalizedSql === 'COMMIT' || normalizedSql === 'ROLLBACK') {
                    return { rows: [], rowCount: 0 };
                }
                throw createDatabaseUnavailableError(message);
            },
            release: () => {}
        }),
        end: async () => {}
    };
}

function createDatabasePool() {
    if (!DATABASE_URL) {
        databasePoolEnabled = false;
        return createFallbackPool('DATABASE_URL is not configured');
    }
    try {
        return new Pool({
            connectionString: DATABASE_URL,
            ssl: IS_PROD ? { rejectUnauthorized: false } : false,
            connectionTimeoutMillis: 10000
        });
    } catch (err) {
        databasePoolEnabled = false;
        console.error(`Database pool initialization failed: ${formatSafeError(err, 'Unknown database pool error')}`);
        return createFallbackPool(formatSafeError(err, 'Database pool initialization failed'));
    }
}

const pool = createDatabasePool();

function createMailTransporter() {
    if (!SMTP_HOST || !SMTP_FROM) {
        return null;
    }
    if (!nodemailer || typeof nodemailer.createTransport !== 'function') {
        console.error('Email transport disabled: nodemailer is not available.');
        return null;
    }
    try {
        return nodemailer.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_SECURE,
            auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
        });
    } catch (err) {
        console.error(`Email transport initialization failed: ${formatSafeError(err, 'Unknown mail initialization error')}`);
        return null;
    }
}

const mailTransporter = createMailTransporter();

function createSessionStore() {
    if (!databasePoolEnabled) {
        console.error('Session store fallback enabled: database pool is not available.');
        return null;
    }
    if (!pgSession) {
        console.error('Session store fallback enabled: connect-pg-simple is not available.');
        return null;
    }
    try {
        return new pgSession({
            pool,
            tableName: 'user_sessions',
            createTableIfMissing: true
        });
    } catch (err) {
        console.error(`Session store initialization failed: ${formatSafeError(err, 'Unknown session store error')}`);
        return null;
    }
}

const sessionStore = createSessionStore();

const paymentRateLimiter = {};

async function removeUploadedFile(fileName) {
    const normalizedName = path.basename(String(fileName || '').trim());
    if (!normalizedName) return;
    const filePath = path.join(UPLOAD_DIR, normalizedName);
    try {
        await fs.promises.unlink(filePath);
    } catch (err) {
        if (err && err.code !== 'ENOENT') {
            console.warn(`Could not remove upload ${normalizedName}: ${err.message}`);
        }
    }
}

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.get(['/', '/index.html', '/dashboard'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.use(express.static('public', { index: false }));

app.use(session({
    ...(sessionStore ? { store: sessionStore } : {}),
    name: 'mrf.sid',
    secret: SESSION_SECRET,
    proxy: true,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    unset: 'destroy',
    cookie: {
        secure: 'auto',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

app.use(passport.initialize());
app.use(passport.session());

function normalizeUser(row) {
    if (!row) return null;
    return {
        ...row,
        balance: Number(row.balance || 0),
        is_admin: Boolean(row.is_admin),
        referralCode: row.referral_code,
        is_active: row.is_active,
        login_attempts: row.login_attempts
    };
}

function normalizeOrderStatus(row) {
    const rawStatus = String(row?.status || row?.order_status || '').toLowerCase();
    if (rawStatus === 'expired_refunded') return 'expired';
    if (rawStatus === 'otp_received') return 'active';
    if (rawStatus === 'retry_requested') return row?.otp_received ? 'active' : 'pending';
    if (rawStatus === 'active' && !row?.otp_received) return 'pending';
    if (rawStatus === 'pending' && row?.otp_received) return 'active';
    if (rawStatus === 'expired' || rawStatus === 'completed' || rawStatus === 'cancelled' || rawStatus === 'pending' || rawStatus === 'active') {
        return rawStatus;
    }
    if (row?.otp_received) return 'active';
    return 'pending';
}

function normalizeOrder(row) {
    if (!row) return null;
    const status = normalizeOrderStatus(row);
    return {
        ...row,
        price: Number(row.price || 0),
        provider_cost_pkr: Number(row.provider_cost_pkr || 0),
        client_balance_left: row.client_balance_left == null ? null : Number(row.client_balance_left),
        profit_pkr: row.profit_pkr == null ? null : Number(row.profit_pkr),
        otp_received: row.otp_received,
        status
    };
}

function isAdminUser(user) {
    return Boolean(user && (user.is_admin || String(user.role || '').toLowerCase() === 'admin'));
}

function normalizeTransaction(row) {
    if (!row) return null;
    return {
        ...row,
        amount: Number(row.amount || 0),
        user_name: row.user_name || '',
        user_email: row.user_email || ''
    };
}

function normalizePaymentRequest(row) {
    if (!row) return null;
    return {
        ...row,
        amount: Number(row.amount || 0),
        user_name: row.user_name || '',
        user_email: row.user_email || ''
    };
}

async function queryOne(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
}

async function queryAll(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows;
}

async function queryRun(sql, params = []) {
    return pool.query(sql, params);
}

function isPasswordHashed(password) {
    return typeof password === 'string' && /^\$2[aby]\$\d{2}\$/.test(password);
}

async function hashPassword(password) {
    if (!bcrypt || typeof bcrypt.hash !== 'function') {
        throw new Error('Password hashing is not available');
    }
    return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(inputPassword, storedPassword) {
    if (!storedPassword || typeof storedPassword !== 'string') {
        return { valid: false, needsUpgrade: false };
    }
    if (isPasswordHashed(storedPassword)) {
        if (!bcrypt || typeof bcrypt.compare !== 'function') {
            return { valid: false, needsUpgrade: false };
        }
        const valid = await bcrypt.compare(inputPassword, storedPassword);
        return { valid, needsUpgrade: false };
    }
    const valid = inputPassword === storedPassword;
    return { valid, needsUpgrade: valid };
}

function sanitizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
    return typeof password === 'string' && password.length >= 6;
}

function randomPassword() {
    return crypto.randomBytes(24).toString('hex');
}

function waitMs(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function pkrToUsd(pkr) {
    return parseFloat((pkr / 280).toFixed(3));
}

function formatSafeError(err, fallback = 'Server error') {
    if (!err) return fallback;
    if (typeof err.message === 'string' && err.message.trim()) return err.message;
    return fallback;
}

function isMailConfigured() {
    return Boolean(mailTransporter && typeof mailTransporter.sendMail === 'function');
}

function hashToken(value) {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function buildAbsoluteUrl(relativePath) {
    const normalizedPath = `/${String(relativePath || '').replace(/^\/+/, '')}`;
    if (!APP_BASE_URL) {
        return normalizedPath;
    }
    const base = APP_BASE_URL.endsWith('/') ? APP_BASE_URL : `${APP_BASE_URL}/`;
    return new URL(normalizedPath.replace(/^\//, ''), base).toString();
}

async function sendPasswordResetEmail(user, token) {
    if (!mailTransporter) {
        throw new Error('Password reset email is not configured');
    }
    const resetUrl = buildAbsoluteUrl(`/reset-password.html?token=${encodeURIComponent(token)}`);
    const recipientName = String(user.name || 'there').trim();
    try {
        await mailTransporter.sendMail({
            from: SMTP_FROM,
            to: user.email,
            subject: 'Reset your MRF SMS password',
            text: `Hello ${recipientName},\n\nUse this link to reset your password: ${resetUrl}\n\nThis link expires in 1 hour. If you did not request it, you can safely ignore this email.`,
            html: `
                <div style="font-family:Inter,Arial,sans-serif;background:#f8fafc;padding:32px;">
                    <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:24px;padding:32px;border:1px solid #e2e8f0;box-shadow:0 16px 40px rgba(15,23,42,0.08);">
                        <div style="font-size:12px;letter-spacing:0.16em;text-transform:uppercase;color:#64748b;margin-bottom:10px;">MRF SMS</div>
                        <h1 style="margin:0 0 12px;font-size:28px;line-height:1.2;color:#0f172a;">Reset your password</h1>
                        <p style="margin:0 0 20px;color:#475569;line-height:1.7;">Hello ${recipientName}, we received a request to reset your password. Click the button below to continue.</p>
                        <a href="${resetUrl}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:14px 22px;border-radius:14px;font-weight:700;">Reset Password</a>
                        <p style="margin:20px 0 0;color:#64748b;line-height:1.7;">This link will expire in 1 hour. If you did not request a password reset, you can safely ignore this email.</p>
                        <p style="margin:20px 0 0;color:#94a3b8;font-size:12px;word-break:break-all;">Direct link: ${resetUrl}</p>
                    </div>
                </div>
            `
        });
    } catch (err) {
        console.error(`Password reset email failed for ${user.email}: ${formatSafeError(err, 'Email delivery failed')}`);
        throw err;
    }
}

async function initDB() {
    await queryRun(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            balance NUMERIC(12,2) DEFAULT 0,
            role TEXT DEFAULT 'user',
            is_admin BOOLEAN DEFAULT FALSE,
            referral_code TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            login_attempts INTEGER DEFAULT 0,
            last_login TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await queryRun(`
        CREATE TABLE IF NOT EXISTS balance_adjustments (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            amount NUMERIC(12,2) NOT NULL,
            reason TEXT NOT NULL,
            admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await queryRun('CREATE INDEX IF NOT EXISTS idx_balance_adjustments_user_id ON balance_adjustments (user_id, created_at DESC)');
    await queryRun('CREATE INDEX IF NOT EXISTS idx_balance_adjustments_admin_id ON balance_adjustments (admin_id, created_at DESC)');

    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT');
    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMPTZ');
    await queryRun('CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users (reset_token)');
    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS "googleId" TEXT');
    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS "displayName" TEXT');
    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS "photo" TEXT');
    await queryRun('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE');
    await queryRun("UPDATE users SET is_admin = TRUE WHERE LOWER(COALESCE(role, 'user')) = 'admin'");
    await queryRun('CREATE UNIQUE INDEX IF NOT EXISTS users_googleId_unique_idx ON users ("googleId") WHERE "googleId" IS NOT NULL');

    await queryRun(`
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user_email TEXT,
            service_type TEXT,
            service_name TEXT,
            country TEXT,
            country_code TEXT,
            country_id INTEGER,
            price NUMERIC(12,2),
            provider_cost_pkr NUMERIC(12,2) DEFAULT 0,
            payment_method TEXT,
            payment_status TEXT DEFAULT 'pending',
            order_status TEXT DEFAULT 'pending',
            status TEXT DEFAULT 'pending',
            phone_number TEXT,
            activation_id TEXT,
            otp_received BOOLEAN DEFAULT FALSE,
            otp_code TEXT,
            expires_at TIMESTAMPTZ,
            cancel_available_at TIMESTAMPTZ,
            last_purchase_at TIMESTAMPTZ,
            idempotency_key TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMPTZ
        )
    `);

    await queryRun('ALTER TABLE orders ADD COLUMN IF NOT EXISTS provider_cost_pkr NUMERIC(12,2) DEFAULT 0');
    await queryRun('ALTER TABLE orders ADD COLUMN IF NOT EXISTS status TEXT DEFAULT \'pending\'');
    await queryRun('ALTER TABLE orders ADD COLUMN IF NOT EXISTS last_purchase_at TIMESTAMPTZ');
    await queryRun('ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key TEXT');
    await queryRun('UPDATE orders SET last_purchase_at = COALESCE(last_purchase_at, created_at, CURRENT_TIMESTAMP)');
    await queryRun(`
        UPDATE orders
        SET status = CASE
            WHEN LOWER(COALESCE(order_status, '')) = 'completed' THEN 'completed'
            WHEN LOWER(COALESCE(order_status, '')) IN ('expired_refunded', 'expired') THEN 'expired'
            WHEN LOWER(COALESCE(order_status, '')) = 'cancelled' THEN 'cancelled'
            WHEN otp_received = TRUE OR LOWER(COALESCE(order_status, '')) = 'otp_received' THEN 'active'
            WHEN LOWER(COALESCE(order_status, '')) = 'active' THEN 'pending'
            ELSE 'pending'
        END
    `);

    await queryRun(`
        UPDATE orders
        SET
            status = 'completed',
            order_status = 'completed',
            completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP)
        WHERE created_at <= CURRENT_TIMESTAMP - INTERVAL '1 hour'
          AND (
              COALESCE(otp_received, FALSE) = TRUE
              OR NULLIF(TRIM(COALESCE(otp_code, '')), '') IS NOT NULL
              OR LOWER(COALESCE(order_status, '')) = 'otp_received'
          )
          AND LOWER(COALESCE(status, order_status, 'pending')) NOT IN ('completed', 'cancelled', 'expired', 'expired_refunded')
    `);
    await queryRun('CREATE INDEX IF NOT EXISTS idx_orders_user_service_country_status ON orders (user_id, service_type, country_id, status)');
    await queryRun('CREATE INDEX IF NOT EXISTS idx_orders_user_service_last_purchase ON orders (user_id, service_type, last_purchase_at DESC)');
    await queryRun('CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_user_idempotency_key ON orders (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL');
    await queryRun('DROP INDEX IF EXISTS idx_orders_open_service_country_unique');

    await queryRun(`
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user_email TEXT,
            amount NUMERIC(12,2),
            screenshot TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await queryRun(`
        CREATE TABLE IF NOT EXISTS payment_requests (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user_email TEXT,
            amount NUMERIC(12,2),
            transaction_id TEXT UNIQUE,
            screenshot TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    `);

    if (ADMIN_EMAIL && ADMIN_PASSWORD) {
        const adminEmail = sanitizeEmail(ADMIN_EMAIL);
        const existingAdmin = normalizeUser(await queryOne('SELECT * FROM users WHERE email = $1', [adminEmail]));
        if (!existingAdmin) {
            const hashedAdminPassword = await hashPassword(ADMIN_PASSWORD);
            await queryRun(
                'INSERT INTO users (email, password, name, role, is_admin, referral_code) VALUES ($1, $2, $3, $4, $5, $6)',
                [adminEmail, hashedAdminPassword, ADMIN_NAME, 'admin', true, 'ADMIN']
            );
            console.log('Admin user created from environment variables');
        } else if (!isAdminUser(existingAdmin)) {
            await queryRun('UPDATE users SET role = $1, is_admin = TRUE WHERE id = $2', ['admin', existingAdmin.id]);
            console.log('Existing admin email promoted to admin privileges');
        }
    } else {
        console.log('ADMIN_EMAIL / ADMIN_PASSWORD not set, skipping admin auto-create');
    }

    await queryRun(`
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transactions' AND column_name='transaction_id') THEN
        ALTER TABLE transactions ADD COLUMN transaction_id TEXT;
    END IF;
END $$;
    `);
    await queryRun('ALTER TABLE transactions ADD COLUMN IF NOT EXISTS type TEXT DEFAULT \'deposit\'');
    await queryRun('ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT');
    await queryRun('UPDATE transactions SET type = $1 WHERE type IS NULL', ['deposit']);
}

async function findUser(email) {
    return normalizeUser(await queryOne('SELECT * FROM users WHERE email = $1', [sanitizeEmail(email)]));
}

async function findUserById(id) {
    return normalizeUser(await queryOne('SELECT * FROM users WHERE id = $1', [id]));
}

async function createUser(name, email, password) {
    const referralCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    const hashedPassword = await hashPassword(password);
    return queryRun(
        'INSERT INTO users (email, password, name, referral_code) VALUES ($1, $2, $3, $4)',
        [sanitizeEmail(email), hashedPassword, String(name || '').trim(), referralCode]
    );
}

async function updateUserPassword(userId, newPlainPassword) {
    const hashed = await hashPassword(newPlainPassword);
    return queryRun('UPDATE users SET password = $1 WHERE id = $2', [hashed, userId]);
}

async function updateUserPasswordHash(userId, hashedPassword) {
    return queryRun('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
}

async function savePasswordResetToken(userId, tokenHash, expiresAt) {
    return queryRun(
        'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
        [tokenHash, expiresAt, userId]
    );
}

async function clearPasswordResetToken(userId) {
    return queryRun(
        'UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = $1',
        [userId]
    );
}

async function findUserByResetToken(token) {
    const tokenHash = hashToken(token);
    return normalizeUser(await queryOne(
        'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > CURRENT_TIMESTAMP',
        [tokenHash]
    ));
}

async function getAllPaymentRequests() {
    const rows = await queryAll(`
        SELECT
            pr.*,
            COALESCE(u.name, '') AS user_name,
            COALESCE(u.email, pr.user_email) AS user_email
        FROM payment_requests pr
        LEFT JOIN users u ON u.id = pr.user_id
        ORDER BY pr.id DESC
    `);
    return rows.map(normalizePaymentRequest);
}

async function getPaymentHistoryByUser(userId) {
    const rows = await queryAll(`
        SELECT
            pr.*,
            COALESCE(u.name, '') AS user_name,
            COALESCE(u.email, pr.user_email) AS user_email
        FROM payment_requests pr
        LEFT JOIN users u ON u.id = pr.user_id
        WHERE pr.user_id = $1
        ORDER BY pr.id DESC
    `, [userId]);
    return rows.map(normalizePaymentRequest);
}

async function getPendingTransactions() {
    const rows = await queryAll(`
        SELECT
            t.*,
            COALESCE(u.name, '') AS user_name,
            COALESCE(u.email, t.user_email) AS user_email
        FROM transactions t
        LEFT JOIN users u ON u.id = t.user_id
        WHERE t.status = $1
        ORDER BY t.id DESC
    `, ['pending']);
    return rows.map(normalizeTransaction);
}

async function getTransactionHistory() {
    const rows = await queryAll(`
        SELECT
            t.*,
            COALESCE(u.name, '') AS user_name,
            COALESCE(u.email, t.user_email) AS user_email
        FROM transactions t
        LEFT JOIN users u ON u.id = t.user_id
        WHERE t.status <> $1
        ORDER BY t.id DESC
    `, ['pending']);
    return rows.map(normalizeTransaction);
}

async function approveTransaction(txId) {
    const client = await pool.connect();
    let screenshotToDelete = null;
    try {
        await client.query('BEGIN');
        const txRes = await client.query('SELECT * FROM transactions WHERE id = $1 FOR UPDATE', [txId]);
        const tx = txRes.rows[0];
        if (!tx) throw new Error('Transaction not found');
        if (tx.status !== 'pending') throw new Error('Only pending transactions can be approved');
        screenshotToDelete = tx.screenshot || null;
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [tx.user_id]);
        const user = userRes.rows[0];
        if (!user) throw new Error('User not found');
        await client.query('UPDATE transactions SET status = $1, type = COALESCE(type, $2), screenshot = NULL WHERE id = $3', ['approved', 'deposit', txId]);
        await client.query(
            'UPDATE users SET balance = $1 WHERE id = $2',
            [Number(user.balance || 0) + Number(tx.amount || 0), tx.user_id]
        );
        await client.query('COMMIT');
        await removeUploadedFile(screenshotToDelete);
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

async function cancelTransaction(txId) {
    const client = await pool.connect();
    let screenshotToDelete = null;
    try {
        await client.query('BEGIN');
        const txRes = await client.query('SELECT * FROM transactions WHERE id = $1 FOR UPDATE', [txId]);
        const tx = txRes.rows[0];
        if (!tx) throw new Error('Transaction not found');
        if (tx.status !== 'pending') throw new Error('Only pending transactions can be cancelled');
        screenshotToDelete = tx.screenshot || null;
        await client.query('UPDATE transactions SET status = $1, type = COALESCE(type, $2), screenshot = NULL WHERE id = $3', ['cancelled', 'deposit', txId]);
        await client.query('COMMIT');
        await removeUploadedFile(screenshotToDelete);
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

async function getOrdersByUser(userId) {
    const rows = await queryAll(`
        SELECT *
        FROM orders
        WHERE user_id = $1
          AND COALESCE(status, order_status, 'pending') IN ('pending', 'active')
          AND LOWER(COALESCE(status, 'pending')) NOT IN ('completed', 'cancelled', 'expired', 'expired_refunded')
          AND LOWER(COALESCE(order_status, 'pending')) NOT IN ('completed', 'cancelled', 'expired', 'expired_refunded')
        ORDER BY id DESC
    `, [userId]);
    return rows.map(normalizeOrder);
}

async function getAdminUsers() {
    const rows = await queryAll(`
        SELECT id, name, email, balance, role, is_admin, created_at
        FROM users
        ORDER BY id DESC
    `);
    return rows.map(normalizeUser);
}

async function getAllBalanceAdjustments(limit = 300) {
    const rows = await queryAll(`
        SELECT
            ba.*,
            COALESCE(target_user.email, '') AS user_email,
            COALESCE(target_user.name, '') AS user_name,
            COALESCE(admin_user.email, '') AS admin_email,
            COALESCE(admin_user.name, '') AS admin_name
        FROM balance_adjustments ba
        LEFT JOIN users target_user ON target_user.id = ba.user_id
        LEFT JOIN users admin_user ON admin_user.id = ba.admin_id
        ORDER BY ba.created_at DESC
        LIMIT $1
    `, [limit]);
    return rows.map((row) => ({
        ...row,
        amount: Number(row.amount || 0)
    }));
}

async function getUserCombinedHistory(userId, limit = 300) {
    const rows = await queryAll(`
        SELECT *
        FROM (
            SELECT
                'purchase'::text AS entry_type,
                o.id::text AS reference_id,
                -COALESCE(o.price, 0)::numeric AS amount,
                CONCAT(COALESCE(o.service_name, 'Service'), ' • ', COALESCE(o.country, 'Unknown country')) AS details,
                COALESCE(o.status, o.order_status, 'pending') AS status,
                o.created_at AS created_at
            FROM orders o
            WHERE o.user_id = $1

            UNION ALL

            SELECT
                'deposit'::text AS entry_type,
                t.id::text AS reference_id,
                COALESCE(t.amount, 0)::numeric AS amount,
                COALESCE(t.description, 'Wallet deposit approved') AS details,
                COALESCE(t.status, 'approved') AS status,
                t.created_at AS created_at
            FROM transactions t
            WHERE t.user_id = $1
              AND LOWER(COALESCE(t.type, '')) IN ('deposit')

            UNION ALL

            SELECT
                'manual_adjustment'::text AS entry_type,
                ba.id::text AS reference_id,
                COALESCE(ba.amount, 0)::numeric AS amount,
                ba.reason AS details,
                'approved'::text AS status,
                ba.created_at AS created_at
            FROM balance_adjustments ba
            WHERE ba.user_id = $1
        ) ledger
        ORDER BY created_at DESC
        LIMIT $2
    `, [userId, limit]);
    return rows.map((row) => ({
        ...row,
        amount: Number(row.amount || 0)
    }));
}

async function applyAdminBalanceAdjustment({ userId, adminId, amount, reason }) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [userId]);
        const targetUser = userRes.rows[0];
        if (!targetUser) throw new Error('Target user not found');

        const updatedUserRes = await client.query(
            'UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE id = $2 RETURNING *',
            [amount, userId]
        );
        const updatedUser = updatedUserRes.rows[0];

        await client.query(
            'INSERT INTO balance_adjustments (user_id, amount, reason, admin_id) VALUES ($1, $2, $3, $4)',
            [userId, amount, reason, adminId]
        );

        await client.query(
            'INSERT INTO transactions (user_id, user_email, amount, type, status, description) VALUES ($1, $2, $3, $4, $5, $6)',
            [userId, targetUser.email, amount, 'manual_adjustment', 'approved', `Manual balance adjustment: ${reason}`]
        );

        await client.query('COMMIT');
        return normalizeUser(updatedUser);
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

async function getOrderById(orderId) {
    return normalizeOrder(await queryOne('SELECT * FROM orders WHERE id = $1', [orderId]));
}

async function updateOrder(orderId, updates) {
    const keys = Object.keys(updates);
    if (!keys.length) return;
    const fields = keys.map((key, index) => `${key} = $${index + 1}`).join(', ');
    const values = keys.map((key) => updates[key]);
    values.push(orderId);
    await queryRun(`UPDATE orders SET ${fields} WHERE id = $${values.length}`, values);
}

async function updateProviderActivationStatus(activationId, status) {
    if (!activationId) return { success: false, skipped: true };
    try {
        const url = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=setStatus&id=${activationId}&status=${status}`;
        await axios.get(url, { timeout: 15000 });
        return { success: true };
    } catch (err) {
        return { success: false, error: err.message };
    }
}

async function expireOrderAndRefund(orderId) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const orderRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
        const order = orderRes.rows[0];
        if (!order) {
            await client.query('ROLLBACK');
            return { found: false, expired: false, refunded: false, order: null };
        }
        if (String(order.status || order.order_status || '').toLowerCase() === 'expired') {
            await client.query('COMMIT');
            return {
                found: true,
                expired: true,
                refunded: true,
                order: normalizeOrder(order),
                message: EXPIRED_REFUND_MESSAGE
            };
        }
        const expiry = order.expires_at ? new Date(order.expires_at) : null;
        const now = new Date();
        if (String(order.status || order.order_status || '').toLowerCase() !== 'pending' || order.otp_received || !expiry || now < expiry) {
            await client.query('COMMIT');
            return {
                found: true,
                expired: false,
                refunded: false,
                order: normalizeOrder(order)
            };
        }
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [order.user_id]);
        const user = userRes.rows[0] || null;
        await updateProviderActivationStatus(order.activation_id, 8);
        if (user) {
            await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE id = $2', [
                Number(order.price || 0),
                user.id
            ]);
        }
        const updatedRes = await client.query(
            'UPDATE orders SET order_status = $1, status = $2 WHERE id = $3 RETURNING *',
            ['expired', 'expired', order.id]
        );
        await client.query('COMMIT');
        return {
            found: true,
            expired: true,
            refunded: Boolean(user),
            order: normalizeOrder(updatedRes.rows[0]),
            message: EXPIRED_REFUND_MESSAGE
        };
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

async function reconcileExpiredOrdersForUser(userId) {
    const rows = await queryAll(`
        SELECT id
        FROM orders
        WHERE user_id = $1
          AND COALESCE(status, order_status, 'pending') = 'pending'
          AND otp_received = FALSE
          AND expires_at <= CURRENT_TIMESTAMP
        ORDER BY id DESC
    `, [userId]);
    for (const row of rows) {
        await expireOrderAndRefund(row.id);
    }
}

async function getAllOrders() {
    const rows = await queryAll(`
        SELECT
            o.*,
            COALESCE(u.email, o.user_email) AS user_email,
            COALESCE(u.balance, 0) AS client_balance_left,
            CASE
                WHEN COALESCE(o.provider_cost_pkr, 0) > 0
                    THEN ROUND((COALESCE(o.price, 0) - COALESCE(o.provider_cost_pkr, 0))::numeric, 2)
                ELSE NULL
            END AS profit_pkr
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        ORDER BY o.id DESC
    `);
    return rows.map(normalizeOrder);
}

async function updateUserLoginAttempts(userId, attempts) {
    return queryRun('UPDATE users SET login_attempts = $1 WHERE id = $2', [attempts, userId]);
}

async function updateUserLastLogin(userId) {
    return queryRun('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [userId]);
}

const whatsappCountries = [
    { name: 'South Africa', code: '+27', price: 80, countryId: 31, flag: '🇿🇦' },
    { name: 'Indonesia', code: '+62', price: 170, countryId: 6, flag: '🇮🇩' },
    { name: 'Canada', code: '+1', price: 170, countryId: 36, flag: '🇨🇦' },
    { name: 'Philippines', code: '+63', price: 190, countryId: 4, flag: '🇵🇭' },
    { name: 'Thailand', code: '+66', price: 300, countryId: 52, flag: '🇹🇭' },
    { name: 'Vietnam', code: '+84', price: 210, countryId: 10, flag: '🇻🇳' },
    { name: 'Colombia', code: '+57', price: 240, countryId: 33, flag: '🇨🇴' },
    { name: 'Saudi Arabia', code: '+966', price: 240, countryId: 53, flag: '🇸🇦' },
    { name: 'Brazil', code: '+55', price: 370, countryId: 73, flag: '🇧🇷' },
    { name: 'USA', code: '+1', price: 370, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 300, countryId: 16, flag: '🇬🇧' }
];

const facebookCountries = [
    { name: 'Canada', code: '+1', price: 75, countryId: 36, flag: '🇨🇦' },
    { name: 'United Kingdom', code: '+44', price: 40, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 75, countryId: 187, flag: '🇺🇸' },
    { name: 'Pakistan', code: '+92', price: 24, countryId: 66, flag: '🇵🇰' },
    { name: 'Indonesia', code: '+62', price: 11, countryId: 6, flag: '🇮🇩' },
    { name: 'Philippines', code: '+63', price: 29, countryId: 4, flag: '🇵🇭' },
    { name: 'Ethiopia', code: '+251', price: 31, countryId: 71, flag: '🇪🇹' },
    { name: 'USA Virtual', code: '+1', price: 70, countryId: 12, flag: '🇺🇸' },
    { name: 'Afghanistan', code: '+93', price: 31, countryId: 74, flag: '🇦🇫' },
    { name: 'Peru', code: '+51', price: 33, countryId: 65, flag: '🇵🇪' },
    { name: 'Egypt', code: '+20', price: 30, countryId: 21, flag: '🇪🇬' },
    { name: 'Georgia', code: '+995', price: 34, countryId: 128, flag: '🇬🇪' },
    { name: 'Finland', code: '+358', price: 29, countryId: 163, flag: '🇫🇮' },
    { name: 'Papua New Guinea', code: '+675', price: 70, countryId: 79, flag: '🇵🇬' },
    { name: "Ivory Coast", code: '+225', price: 32, countryId: 27, flag: '🇨🇮' },
    { name: 'Chad', code: '+235', price: 31, countryId: 42, flag: '🇹🇩' },
    { name: 'Nepal', code: '+977', price: 33, countryId: 81, flag: '🇳🇵' },
    { name: 'Moldova', code: '+373', price: 30, countryId: 85, flag: '🇲🇩' },
    { name: 'Croatia', code: '+385', price: 34, countryId: 45, flag: '🇭🇷' },
    { name: 'Nicaragua', code: '+505', price: 29, countryId: 90, flag: '🇳🇮' },
    { name: 'Cuba', code: '+53', price: 120, countryId: 113, flag: '🇨🇺' },
    { name: 'Mongolia', code: '+976', price: 32, countryId: 72, flag: '🇲🇳' },
    { name: 'Slovenia', code: '+386', price: 31, countryId: 59, flag: '🇸🇮' },
    { name: 'Benin', code: '+229', price: 33, countryId: 120, flag: '🇧🇯' },
    { name: 'Belarus', code: '+375', price: 100, countryId: 51, flag: '🇧🇾' },
    { name: 'Botswana', code: '+267', price: 100, countryId: 123, flag: '🇧🇼' },
    { name: 'DR Congo', code: '+243', price: 30, countryId: 18, flag: '🇨🇩' },
    { name: 'Madagascar', code: '+261', price: 34, countryId: 17, flag: '🇲🇬' },
    { name: 'Colombia', code: '+57', price: 19, countryId: 33, flag: '🇨🇴' },
    { name: 'Algeria', code: '+213', price: 29, countryId: 58, flag: '🇩🇿' },
    { name: 'Austria', code: '+43', price: 32, countryId: 50, flag: '🇦🇹' },
    { name: 'Panama', code: '+507', price: 31, countryId: 112, flag: '🇵🇦' },
    { name: 'Norway', code: '+47', price: 33, countryId: 174, flag: '🇳🇴' },
    { name: 'Ireland', code: '+353', price: 30, countryId: 23, flag: '🇮🇪' },
    { name: 'Mauritius', code: '+230', price: 34, countryId: 157, flag: '🇲🇺' },
    { name: 'Switzerland', code: '+41', price: 29, countryId: 173, flag: '🇨🇭' },
    { name: 'Costa Rica', code: '+506', price: 60, countryId: 93, flag: '🇨🇷' },
    { name: 'Bahrain', code: '+973', price: 90, countryId: 145, flag: '🇧🇭' },
    { name: 'Gambia', code: '+220', price: 32, countryId: 28, flag: '🇬🇲' },
    { name: 'Liberia', code: '+231', price: 31, countryId: 135, flag: '🇱🇷' },
    { name: 'Angola', code: '+244', price: 33, countryId: 76, flag: '🇦🇴' },
    { name: 'Armenia', code: '+374', price: 30, countryId: 148, flag: '🇦🇲' },
    { name: 'Gabon', code: '+241', price: 34, countryId: 154, flag: '🇬🇦' },
    { name: 'Hungary', code: '+36', price: 29, countryId: 84, flag: '🇭🇺' },
    { name: 'Guinea', code: '+224', price: 32, countryId: 68, flag: '🇬🇳' },
    { name: 'Serbia', code: '+381', price: 31, countryId: 29, flag: '🇷🇸' },
    { name: 'Burundi', code: '+257', price: 33, countryId: 119, flag: '🇧🇮' },
    { name: 'South Sudan', code: '+211', price: 30, countryId: 177, flag: '🇸🇸' },
    { name: 'Maldives', code: '+960', price: 200, countryId: 159, flag: '🇲🇻' },
    { name: 'Albania', code: '+355', price: 80, countryId: 155, flag: '🇦🇱' },
    { name: 'Guinea-Bissau', code: '+245', price: 80, countryId: 130, flag: '🇬🇼' },
    { name: 'Sierra Leone', code: '+232', price: 34, countryId: 115, flag: '🇸🇱' },
    { name: 'Azerbaijan', code: '+994', price: 29, countryId: 35, flag: '🇦🇿' },
    { name: 'Slovakia', code: '+421', price: 32, countryId: 141, flag: '🇸🇰' },
    { name: 'North Macedonia', code: '+389', price: 31, countryId: 183, flag: '🇲🇰' },
    { name: 'Togo', code: '+228', price: 33, countryId: 99, flag: '🇹🇬' },
    { name: 'Lebanon', code: '+961', price: 170, countryId: 153, flag: '🇱🇧' },
    { name: 'Hong Kong', code: '+852', price: 30, countryId: 14, flag: '🇭🇰' },
    { name: 'Denmark', code: '+45', price: 33, countryId: 172, flag: '🇩🇰' },
{ name: 'Tunisia', code: '+216', price: 80, countryId: 89, flag: '🇹🇳' },
{ name: 'Kazakhstan', code: '+7', price: 30, countryId: 2, flag: '🇰🇿' },
{ name: 'Latvia', code: '+371', price: 34, countryId: 49, flag: '🇱🇻' },
{ name: 'Uganda', code: '+256', price: 29, countryId: 75, flag: '🇺🇬' },
{ name: 'Greece', code: '+30', price: 32, countryId: 129, flag: '🇬🇷' },
{ name: 'Estonia', code: '+372', price: 31, countryId: 34, flag: '🇪🇪' },
{ name: 'Fiji', code: '+679', price: 70, countryId: 189, flag: '🇫🇯' },
{ name: 'Taiwan', code: '+886', price: 33, countryId: 55, flag: '🇹🇼' },
{ name: 'Kyrgyzstan', code: '+996', price: 30, countryId: 11, flag: '🇰🇬' },
{ name: 'Bolivia', code: '+591', price: 34, countryId: 92, flag: '🇧🇴' },
{ name: 'Haiti', code: '+509', price: 29, countryId: 26, flag: '🇭🇹' },
{ name: 'Myanmar', code: '+95', price: 32, countryId: 5, flag: '🇲🇲' },
{ name: 'Dominican Republic', code: '+1', price: 70, countryId: 109, flag: '🇩🇴' },
{ name: 'Belgium', code: '+32', price: 31, countryId: 82, flag: '🇧🇪' },
{ name: 'Eswatini', code: '+268', price: 33, countryId: 106, flag: '🇸🇿' },
{ name: 'Kuwait', code: '+965', price: 90, countryId: 100, flag: '🇰🇼' },
{ name: 'Laos', code: '+856', price: 30, countryId: 25, flag: '🇱🇦' },
{ name: 'Niger', code: '+227', price: 100, countryId: 139, flag: '🇳🇪' },
{ name: 'Tajikistan', code: '+992', price: 34, countryId: 143, flag: '🇹🇯' },
{ name: 'Qatar', code: '+974', price: 90, countryId: 111, flag: '🇶🇦' },
{ name: 'El Salvador', code: '+503', price: 80, countryId: 101, flag: '🇸🇻' },
{ name: 'New Zealand', code: '+64', price: 80, countryId: 67, flag: '🇳🇿' },
{ name: 'Libya', code: '+218', price: 90, countryId: 102, flag: '🇱🇾' },
{ name: 'Honduras', code: '+504', price: 29, countryId: 88, flag: '🇭🇳' },
{ name: 'United Arab Emirates', code: '+971', price: 60, countryId: 95, flag: '🇦🇪' },
{ name: 'Namibia', code: '+264', price: 60, countryId: 138, flag: '🇳🇦' },
{ name: 'Equatorial Guinea', code: '+240', price: 80, countryId: 167, flag: '🇬🇶' },
{ name: 'Somalia', code: '+252', price: 70, countryId: 149, flag: '🇸🇴' },
{ name: 'Jordan', code: '+962', price: 32, countryId: 116, flag: '🇯🇴' },
{ name: 'Central African Republic', code: '+236', price: 32, countryId: 125, flag: '🇨🇫' },
{ name: 'Zimbabwe', code: '+263', price: 80, countryId: 96, flag: '🇿🇼' },
{ name: 'Turkmenistan', code: '+993', price: 31, countryId: 161, flag: '🇹🇲' },
{ name: 'Rwanda', code: '+250', price: 80, countryId: 140, flag: '🇷🇼' },
{ name: 'Sudan', code: '+249', price: 90, countryId: 1010, flag: '🇸🇩' },
{ name: 'Reunion', code: '+262', price: 60, countryId: 146, flag: '🇷🇪' },
{ name: 'Oman', code: '+968', price: 80, countryId: 107, flag: '🇴🇲' },
{ name: 'Bhutan', code: '+975', price: 33, countryId: 158, flag: '🇧🇹' },
{ name: 'China', code: '+86', price: 30, countryId: 3, flag: '🇨🇳' },
{ name: 'Barbados', code: '+1', price: 34, countryId: 118, flag: '🇧🇧' },
{ name: 'Martinique', code: '+596', price: 29, countryId: 1011, flag: '🇲🇶' },
{ name: 'Puerto Rico', code: '+1', price: 60, countryId: 97, flag: '🇵🇷' },
{ name: 'Guadeloupe', code: '+590', price: 32, countryId: 160, flag: '🇬🇵' },
{ name: 'Luxembourg', code: '+352', price: 31, countryId: 165, flag: '🇱🇺' },
{ name: 'Antigua and Barbuda', code: '+1', price: 33, countryId: 169, flag: '🇦🇬' },
{ name: 'Djibouti', code: '+253', price: 30, countryId: 168, flag: '🇩🇯' },
{ name: 'French Guiana', code: '+594', price: 34, countryId: 162, flag: '🇬🇫' },
{ name: 'Saint Lucia', code: '+1', price: 29, countryId: 164, flag: '🇱🇨' },
{ name: 'Montenegro', code: '+382', price: 80, countryId: 171, flag: '🇲🇪' },
{ name: 'Bahamas', code: '+1', price: 70, countryId: 122, flag: '🇧🇸' },
{ name: 'Grenada', code: '+1', price: 90, countryId: 127, flag: '🇬🇩' },
{ name: 'Brunei', code: '+673', price: 170, countryId: 121, flag: '🇧🇳' },
{ name: 'Cayman Islands', code: '+1', price: 32, countryId: 170, flag: '🇰🇾' },
{ name: 'Saint Vincent', code: '+1', price: 31, countryId: 166, flag: '🇻🇨' },
{ name: 'Saint Kitts and Nevis', code: '+1', price: 33, countryId: 134, flag: '🇰🇳' },
{ name: 'Aruba', code: '+297', price: 30, countryId: 179, flag: '🇦🇼' },
{ name: 'Comoros', code: '+269', price: 80, countryId: 133, flag: '🇰🇲' },
{ name: 'Malta', code: '+356', price: 34, countryId: 199, flag: '🇲🇹' },
{ name: 'Singapore', code: '+65', price: 29, countryId: 196, flag: '🇸🇬' },
{ name: 'Anguilla', code: '+1', price: 80, countryId: 181, flag: '🇦🇮' },
{ name: 'Sao Tome and Principe', code: '+239', price: 32, countryId: 178, flag: '🇸🇹' },
{ name: 'Palestine', code: '+970', price: 31, countryId: 188, flag: '🇵🇸' },
{ name: 'Monaco', code: '+377', price: 33, countryId: 144, flag: '🇲🇨' },
{ name: 'Belize', code: '+501', price: 70, countryId: 124, flag: '🇧🇿' },
{ name: 'New Caledonia', code: '+687', price: 30, countryId: 185, flag: '🇳🇨' },
{ name: 'Seychelles', code: '+248', price: 34, countryId: 184, flag: '🇸🇨' },
{ name: 'Montserrat', code: '+1', price: 29, countryId: 180, flag: '🇲🇸' },
{ name: 'Dominica', code: '+1', price: 32, countryId: 126, flag: '🇩🇲' },
{ name: 'South Korea', code: '+82', price: 31, countryId: 1002, flag: '🇰🇷' },
{ name: 'Macau', code: '+853', price: 120, countryId: 20, flag: '🇲🇴' },
{ name: 'Iceland', code: '+354', price: 100, countryId: 132, flag: '🇮🇸' },
{ name: 'Eritrea', code: '+291', price: 33, countryId: 176, flag: '🇪🇷' },
{ name: 'Kosovo', code: '+383', price: 30, countryId: 1004, flag: '🇽🇰' },
{ name: 'Uzbekistan', code: '+998', price: 34, countryId: 40, flag: '🇺🇿' },
    ];

const instagramCountries = [
    { name: 'Indonesia', code: '+62', price: 30, countryId: 6, flag: '🇮🇩' },
    { name: 'Belgium', code: '+32', price: 20, countryId: 82, flag: '🇧🇪' },
    { name: 'Indonesia', code: '+62', price: 16, countryId: 6, flag: '🇮🇩' },
    { name: 'Colombia', code: '+57', price: 10, countryId: 33, flag: '🇨🇴' },
    { name: 'United States (Virtual)', code: '+1', price: 30, countryId: 12, flag: '🇺🇸' },
    { name: 'Netherlands', code: '+31', price: 18, countryId: 48, flag: '🇳🇱' },
    { name: 'United Kingdom', code: '+44', price: 19, countryId: 16, flag: '🇬🇧' },
    { name: 'South Africa', code: '+27', price: 34, countryId: 31, flag: '🇿🇦' },
    { name: 'Germany', code: '+49', price: 18, countryId: 43, flag: '🇩🇪' },
    { name: 'Philippines', code: '+63', price: 19, countryId: 4, flag: '🇵🇭' },
    { name: 'Thailand', code: '+66', price: 42, countryId: 52, flag: '🇹🇭' },
    { name: 'Brazil', code: '+55', price: 38, countryId: 73, flag: '🇧🇷' },
    { name: 'Kenya', code: '+254', price: 41, countryId: 8, flag: '🇰🇪' },
    { name: 'Cambodia', code: '+855', price: 39, countryId: 24, flag: '🇰🇭' },
    { name: 'Yemen', code: '+967', price: 44, countryId: 30, flag: '🇾🇪' },
    { name: 'Ukraine', code: '+380', price: 37, countryId: 1, flag: '🇺🇦' },
    { name: 'Morocco', code: '+212', price: 43, countryId: 37, flag: '🇲🇦' },
    { name: 'Nigeria', code: '+234', price: 40, countryId: 19, flag: '🇳🇬' },
    { name: 'Uzbekistan', code: '+998', price: 45, countryId: 40, flag: '🇺🇿' },
    { name: 'Sweden', code: '+46', price: 38, countryId: 46, flag: '🇸🇪' },
    { name: 'Tanzania', code: '+255', price: 42, countryId: 9, flag: '🇹🇿' },
    { name: 'Chile', code: '+56', price: 37, countryId: 151, flag: '🇨🇱' },
    { name: 'India', code: '+91', price: 44, countryId: 22, flag: '🇮🇳' },
    { name: 'Mozambique', code: '+258', price: 40, countryId: 80, flag: '🇲🇿' },
    { name: 'Ghana', code: '+233', price: 60, countryId: 38, flag: '🇬🇭' },
    { name: 'Cameroon', code: '+237', price: 41, countryId: 41, flag: '🇨🇲' },
    { name: 'Senegal', code: '+221', price: 39, countryId: 61, flag: '🇸🇳' },
    { name: 'Poland', code: '+48', price: 43, countryId: 15, flag: '🇵🇱' },
    { name: 'Saudi Arabia', code: '+966', price: 38, countryId: 53, flag: '🇸🇦' },
    { name: 'Egypt', code: '+20', price: 45, countryId: 21, flag: '🇪🇬' },
    { name: 'Romania', code: '+40', price: 40, countryId: 32, flag: '🇷🇴' },
    { name: 'Ivory Coast', code: '+225', price: 42, countryId: 27, flag: '🇨🇮' },
    { name: 'Hong Kong', code: '+852', price: 37, countryId: 14, flag: '🇭🇰' },
    { name: 'Jamaica', code: '+1', price: 44, countryId: 103, flag: '🇯🇲' },
    { name: 'France', code: '+33', price: 39, countryId: 78, flag: '🇫🇷' },
    { name: 'DR Congo', code: '+243', price: 43, countryId: 18, flag: '🇨🇩' },
    { name: 'Zambia', code: '+260', price: 38, countryId: 147, flag: '🇿🇲' },
    { name: 'Algeria', code: '+213', price: 45, countryId: 58, flag: '🇩🇿' },
    { name: 'Vietnam', code: '+84', price: 10, countryId: 10, flag: '🇻🇳' },
    { name: 'Angola', code: '+244', price: 41, countryId: 76, flag: '🇦🇴' },
    { name: 'Canada', code: '+1', price: 17, countryId: 36, flag: '🇨🇦' },
    { name: 'Portugal', code: '+351', price: 39, countryId: 117, flag: '🇵🇹' },
    { name: 'Greece', code: '+30', price: 43, countryId: 129, flag: '🇬🇷' },
    { name: 'Moldova', code: '+373', price: 40, countryId: 85, flag: '🇲🇩' },
    { name: 'Madagascar', code: '+261', price: 44, countryId: 17, flag: '🇲🇬' },
    { name: 'Benin', code: '+229', price: 37, countryId: 120, flag: '🇧🇯' },
    { name: 'Afghanistan', code: '+93', price: 42, countryId: 74, flag: '🇦🇫' },
    { name: 'Uganda', code: '+256', price: 39, countryId: 75, flag: '🇺🇬' },
    { name: 'Ecuador', code: '+593', price: 45, countryId: 105, flag: '🇪🇨' },
    { name: 'UAE', code: '+971', price: 38, countryId: 95, flag: '🇦🇪' },
    { name: 'Nepal', code: '+977', price: 43, countryId: 81, flag: '🇳🇵' },
    { name: 'Bulgaria', code: '+359', price: 40, countryId: 83, flag: '🇧🇬' },
    { name: 'Guinea', code: '+224', price: 44, countryId: 68, flag: '🇬🇳' },
    { name: 'Malawi', code: '+265', price: 37, countryId: 137, flag: '🇲🇼' },
    { name: 'Italy', code: '+39', price: 42, countryId: 86, flag: '🇮🇹' },
    { name: 'South Sudan', code: '+211', price: 39, countryId: 177, flag: '🇸🇸' },
    { name: 'Argentina', code: '+54', price: 45, countryId: 39, flag: '🇦🇷' },
    { name: 'Czech Republic', code: '+420', price: 38, countryId: 63, flag: '🇨🇿' },
    { name: 'Peru', code: '+51', price: 43, countryId: 65, flag: '🇵🇪' },
    { name: 'Paraguay', code: '+595', price: 40, countryId: 87, flag: '🇵🇾' },
    { name: 'Spain', code: '+34', price: 60, countryId: 56, flag: '🇪🇸' },
    { name: 'Turkey', code: '+90', price: 44, countryId: 62, flag: '🇹🇷' },
    { name: 'Syria', code: '+963', price: 42, countryId: 1333, flag: '🇸🇾' },
    { name: 'Malaysia', code: '+60', price: 39, countryId: 7, flag: '🇲🇾' },
    { name: 'Bolivia', code: '+591', price: 45, countryId: 92, flag: '🇧🇴' },
    { name: 'Niger', code: '+227', price: 80, countryId: 139, flag: '🇳🇪' },
    { name: 'Denmark', code: '+45', price: 38, countryId: 172, flag: '🇩🇰' },
    { name: 'Uruguay', code: '+598', price: 100, countryId: 156, flag: '🇺🇾' },
    { name: 'Switzerland', code: '+41', price: 43, countryId: 173, flag: '🇨🇭' },
    { name: 'Mexico', code: '+52', price: 40, countryId: 54, flag: '🇲🇽' },
    { name: 'Nicaragua', code: '+505', price: 44, countryId: 90, flag: '🇳🇮' },
    { name: 'Trinidad and Tobago', code: '+1', price: 37, countryId: 104, flag: '🇹🇹' },
    { name: 'Guatemala', code: '+502', price: 90, countryId: 94, flag: '🇬🇹' },
    { name: 'Gambia', code: '+220', price: 42, countryId: 28, flag: '🇬🇲' },
    { name: 'Estonia', code: '+372', price: 39, countryId: 34, flag: '🇪🇪' },
    { name: 'Liberia', code: '+231', price: 45, countryId: 135, flag: '🇱🇷' },
    { name: 'Costa Rica', code: '+506', price: 70, countryId: 93, flag: '🇨🇷' },
    { name: 'Puerto Rico', code: '+1', price: 100, countryId: 97, flag: '🇵🇷' },
    { name: 'Guyana', code: '+592', price: 80, countryId: 131, flag: '🇬🇾' },
    { name: 'Ethiopia', code: '+251', price: 38, countryId: 71, flag: '🇪🇹' },
    { name: 'Papua New Guinea', code: '+675', price: 70, countryId: 79, flag: '🇵🇬' },
    { name: 'Mauritius', code: '+230', price: 43, countryId: 157, flag: '🇲🇺' },
    { name: 'Chad', code: '+235', price: 40, countryId: 42, flag: '🇹🇩' },
    { name: 'Lebanon', code: '+961', price: 60, countryId: 153, flag: '🇱🇧' },
    { name: 'Pakistan', code: '+92', price: 44, countryId: 66, flag: '🇵🇰' },
    { name: 'Sri Lanka', code: '+94', price: 37, countryId: 64, flag: '🇱🇰' },
    { name: 'Libya', code: '+218', price: 42, countryId: 102, flag: '🇱🇾' },
    { name: 'Honduras', code: '+504', price: 39, countryId: 88, flag: '🇭🇳' },
    { name: 'Mauritania', code: '+222', price: 45, countryId: 114, flag: '🇲🇷' },
    { name: 'Burkina Faso', code: '+226', price: 70, countryId: 152, flag: '🇧🇫' },
    { name: 'Macedonia', code: '+389', price: 38, countryId: 183, flag: '🇲🇰' },
    { name: 'Qatar', code: '+974', price: 100, countryId: 111, flag: '🇶🇦' },
    { name: 'Somalia', code: '+252', price: 43, countryId: 149, flag: '🇸🇴' },
    { name: 'Congo', code: '+242', price: 40, countryId: 150, flag: '🇨🇬' },
    { name: 'New Zealand', code: '+64', price: 44, countryId: 67, flag: '🇳🇿' },
    { name: 'Sudan', code: '+249', price: 110, countryId: 1010, flag: '🇸🇩' },
    { name: 'Georgia', code: '+995', price: 37, countryId: 128, flag: '🇬🇪' },
    { name: 'Bahamas', code: '+1', price: 90, countryId: 122, flag: '🇧🇸' },
    { name: 'Taiwan', code: '+886', price: 42, countryId: 55, flag: '🇹🇼' },
    { name: 'El Salvador', code: '+503', price: 110, countryId: 101, flag: '🇸🇻' },
    { name: 'Cuba', code: '+53', price: 100, countryId: 113, flag: '🇨🇺' },
    { name: 'Venezuela', code: '+58', price: 39, countryId: 70, flag: '🇻🇪' },
    { name: 'Mali', code: '+223', price: 45, countryId: 69, flag: '🇲🇱' },
    { name: 'USA', code: '+1', price: 40, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 40, countryId: 16, flag: '🇬🇧' }
];

const snapchatCountries = [
    { name: 'Indonesia', code: '+62', price: 40, countryId: 6, flag: '🇮🇩' },
    { name: 'USA', code: '+1', price: 40, countryId: 187, flag: '🇺🇸' },
    { name: 'Lesotho', code: '+266', price: 31, countryId: 136, flag: '🇱🇸' },
    { name: 'Ecuador', code: '+593', price: 100, countryId: 105, flag: '🇪🇨' },
    { name: 'El Salvador', code: '+503', price: 90, countryId: 101, flag: '🇸🇻' },
    { name: 'Uganda', code: '+256', price: 33, countryId: 75, flag: '🇺🇬' },
    { name: 'Malawi', code: '+265', price: 29, countryId: 137, flag: '🇲🇼' },
    { name: 'Kenya', code: '+254', price: 34, countryId: 8, flag: '🇰🇪' },
    { name: 'Panama', code: '+507', price: 30, countryId: 112, flag: '🇵🇦' },
    { name: 'Jamaica', code: '+1', price: 90, countryId: 103, flag: '🇯🇲' },
    { name: 'Venezuela', code: '+58', price: 200, countryId: 70, flag: '🇻🇪' },
    { name: 'Kazakhstan', code: '+7', price: 32, countryId: 2, flag: '🇰🇿' },
    { name: 'Paraguay', code: '+595', price: 100, countryId: 87, flag: '🇵🇾' },
    { name: 'Kyrgyzstan', code: '+996', price: 200, countryId: 11, flag: '🇰🇬' },
    { name: 'Jordan', code: '+962', price: 100, countryId: 116, flag: '🇯🇴' },
    { name: 'Cameroon', code: '+237', price: 31, countryId: 41, flag: '🇨🇲' },
    { name: 'Ivory Coast', code: '+225', price: 29, countryId: 27, flag: '🇨🇮' },
    { name: 'Bulgaria', code: '+359', price: 34, countryId: 83, flag: '🇧🇬' },
    { name: 'Libya', code: '+218', price: 80, countryId: 102, flag: '🇱🇾' },
    { name: 'Mauritius', code: '+230', price: 100, countryId: 157, flag: '🇲🇺' },
    { name: 'Mali', code: '+223', price: 30, countryId: 69, flag: '🇲🇱' },
    { name: 'Rwanda', code: '+250', price: 33, countryId: 140, flag: '🇷🇼' },
    { name: 'Gabon', code: '+241', price: 32, countryId: 154, flag: '🇬🇦' },
    { name: 'Nicaragua', code: '+505', price: 29, countryId: 90, flag: '🇳🇮' },
    { name: 'Moldova', code: '+373', price: 31, countryId: 85, flag: '🇲🇩' },
    { name: 'Thailand', code: '+66', price: 34, countryId: 52, flag: '🇹🇭' },
    { name: 'Benin', code: '+229', price: 100, countryId: 120, flag: '🇧🇯' },
    { name: 'Costa Rica', code: '+506', price: 100, countryId: 93, flag: '🇨🇷' },
    { name: 'Burkina Faso', code: '+226', price: 30, countryId: 152, flag: '🇧🇫' },
    { name: 'Qatar', code: '+974', price: 100, countryId: 111, flag: '🇶🇦' },
    { name: 'Reunion', code: '+262', price: 110, countryId: 146, flag: '🇷🇪' },
    { name: 'Oman', code: '+968', price: 110, countryId: 107, flag: '🇴🇲' },
    { name: 'Congo', code: '+242', price: 33, countryId: 150, flag: '🇨🇬' },
    { name: 'Yemen', code: '+967', price: 70, countryId: 30, flag: '🇾🇪' },
    { name: 'Uruguay', code: '+598', price: 32, countryId: 156, flag: '🇺🇾' },
    { name: 'Iraq', code: '+964', price: 100, countryId: 47, flag: '🇮🇶' },
    { name: 'Togo', code: '+228', price: 29, countryId: 99, flag: '🇹🇬' },
    { name: 'Niger', code: '+227', price: 34, countryId: 139, flag: '🇳🇪' },
    { name: 'Bhutan', code: '+975', price: 70, countryId: 158, flag: '🇧🇹' },
    { name: 'Burundi', code: '+257', price: 31, countryId: 119, flag: '🇧🇮' },
    { name: 'Equatorial Guinea', code: '+240', price: 100, countryId: 167, flag: '🇬🇶' },
    { name: 'Trinidad and Tobago', code: '+1', price: 60, countryId: 104, flag: '🇹🇹' },
    { name: 'South Sudan', code: '+211', price: 30, countryId: 177, flag: '🇸🇸' },
    { name: 'Mauritania', code: '+222', price: 100, countryId: 114, flag: '🇲🇷' },
    { name: 'China', code: '+86', price: 130, countryId: 3, flag: '🇨🇳' },
    { name: 'Kuwait', code: '+965', price: 110, countryId: 100, flag: '🇰🇼' },
    { name: 'Guinea-Bissau', code: '+245', price: 110, countryId: 130, flag: '🇬🇼' },
    { name: 'Maldives', code: '+960', price: 100, countryId: 159, flag: '🇲🇻' },
    { name: 'Bosnia and Herzegovina', code: '+387', price: 140, countryId: 108, flag: '🇧🇦' },
    { name: 'Somalia', code: '+252', price: 33, countryId: 149, flag: '🇸🇴' },
    { name: 'Barbados', code: '+1', price: 200, countryId: 118, flag: '🇧🇧' },
    { name: 'Gambia', code: '+220', price: 100, countryId: 28, flag: '🇬🇲' },
    { name: 'Armenia', code: '+374', price: 230, countryId: 148, flag: '🇦🇲' },
    { name: 'Guyana', code: '+592', price: 29, countryId: 131, flag: '🇬🇾' },
    { name: 'Chad', code: '+235', price: 100, countryId: 42, flag: '🇹🇩' },
    { name: 'Switzerland', code: '+41', price: 130, countryId: 173, flag: '🇨🇭' },
    { name: 'Serbia', code: '+381', price: 140, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 40, countryId: 34, flag: '🇪🇪' },
    { name: 'Bahrain', code: '+973', price: 32, countryId: 145, flag: '🇧🇭' },
    { name: 'Guadeloupe', code: '+590', price: 100, countryId: 160, flag: '🇬🇵' },
    { name: 'Cyprus', code: '+357', price: 30, countryId: 77, flag: '🇨🇾' },
    { name: 'Luxembourg', code: '+352', price: 140, countryId: 165, flag: '🇱🇺' },
    { name: 'Suriname', code: '+597', price: 34, countryId: 142, flag: '🇸🇷' },
    { name: 'Guatemala', code: '+502', price: 31, countryId: 94, flag: '🇬🇹' },
    { name: 'Madagascar', code: '+261', price: 110, countryId: 17, flag: '🇲🇬' },
    { name: 'Antigua and Barbuda', code: '+1', price: 110, countryId: 169, flag: '🇦🇬' },
    { name: 'Djibouti', code: '+253', price: 110, countryId: 168, flag: '🇩🇯' },
    { name: 'French Guiana', code: '+594', price: 100, countryId: 162, flag: '🇬🇫' },
    { name: 'Saint Lucia', code: '+1', price: 100, countryId: 164, flag: '🇱🇨' },
    { name: 'Montenegro', code: '+382', price: 29, countryId: 171, flag: '🇲🇪' },
    { name: 'Cuba', code: '+53', price: 33, countryId: 113, flag: '🇨🇺' },
    { name: 'Sierra Leone', code: '+232', price: 30, countryId: 115, flag: '🇸🇱' },
    { name: 'Bahamas', code: '+1', price: 100, countryId: 122, flag: '🇧🇸' },
    { name: 'Bolivia', code: '+591', price: 32, countryId: 92, flag: '🇧🇴' },
    { name: 'Grenada', code: '+1', price: 100, countryId: 127, flag: '🇬🇩' },
    { name: 'Latvia', code: '+371', price: 31, countryId: 49, flag: '🇱🇻' },
    { name: 'Tajikistan', code: '+992', price: 34, countryId: 143, flag: '🇹🇯' },
    { name: 'Brunei', code: '+673', price: 29, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 170, countryId: 170, flag: '🇰🇾' },
    { name: 'Saint Vincent', code: '+1', price: 120, countryId: 166, flag: '🇻🇨' },
    { name: 'Albania', code: '+355', price: 140, countryId: 155, flag: '🇦🇱' },
    { name: 'Slovenia', code: '+386', price: 30, countryId: 59, flag: '🇸🇮' },
    { name: 'Saint Kitts and Nevis', code: '+1', price: 33, countryId: 134, flag: '🇰🇳' },
    { name: 'Lithuania', code: '+370', price: 200, countryId: 44, flag: '🇱🇹' },
    { name: 'CAF', code: '+236', price: 32, countryId: 125, flag: '🇨🇫' },
    { name: 'Liberia', code: '+231', price: 110, countryId: 135, flag: '🇱🇷' },
    { name: 'Japan', code: '+81', price: 110, countryId: 1001, flag: '🇯🇵' },
    { name: 'Guinea', code: '+224', price: 29, countryId: 68, flag: '🇬🇳' },
    { name: 'Aruba', code: '+297', price: 34, countryId: 179, flag: '🇦🇼' },
    { name: 'Comoros', code: '+269', price: 100, countryId: 133, flag: '🇰🇲' },
    { name: 'Slovakia', code: '+421', price: 110, countryId: 141, flag: '🇸🇰' },
    { name: 'Anguilla', code: '+1', price: 80, countryId: 181, flag: '🇦🇮' },
    { name: 'Sao Tome and Principe', code: '+239', price: 31, countryId: 178, flag: '🇸🇹' },
    { name: 'Croatia', code: '+385', price: 30, countryId: 45, flag: '🇭🇷' },
    { name: 'Cape Verde', code: '+238', price: 33, countryId: 186, flag: '🇨🇻' },
    { name: 'Monaco', code: '+377', price: 100, countryId: 144, flag: '🇲🇨' },
    { name: 'Macedonia', code: '+389', price: 110, countryId: 183, flag: '🇲🇰' },
    { name: 'Belize', code: '+501', price: 29, countryId: 124, flag: '🇧🇿' },
    { name: 'New Caledonia', code: '+687', price: 100, countryId: 185, flag: '🇳🇨' },
    { name: 'New Zealand', code: '+64', price: 78, countryId: 67, flag: '🇳🇿' },
    { name: 'Mongolia', code: '+976', price: 34, countryId: 72, flag: '🇲🇳' },
    { name: 'Seychelles', code: '+248', price: 32, countryId: 184, flag: '🇸🇨' },
    { name: 'Montserrat', code: '+1', price: 100, countryId: 180, flag: '🇲🇸' },
    { name: 'Dominica', code: '+1', price: 70, countryId: 126, flag: '🇩🇲' },
    { name: 'Macau', code: '+853', price: 70, countryId: 20, flag: '🇲🇴' },
    { name: 'Iceland', code: '+354', price: 31, countryId: 132, flag: '🇮🇸' },
    { name: 'Eritrea', code: '+291', price: 100, countryId: 176, flag: '🇪🇷' },
    { name: 'Gibraltar', code: '+350', price: 400, countryId: 201, flag: '🇬🇮' }
];

const googleCountries = [
    { name: 'USA Virtual', code: '+1', price: 90, countryId: 12, flag: '🇺🇸' },
    { name: 'Indonesia', code: '+62', price: 90, countryId: 6, flag: '🇮🇩' },
    { name: 'Brazil', code: '+55', price: 90, countryId: 73, flag: '🇧🇷' },
    { name: 'USA', code: '+1', price: 120, countryId: 187, flag: '🇺🇸' },
    { name: 'Colombia', code: '+57', price: 89, countryId: 33, flag: '🇨🇴' },
    { name: 'India', code: '+91', price: 50, countryId: 22, flag: '🇮🇳' },
    { name: 'Chile', code: '+56', price: 40, countryId: 151, flag: '🇨🇱' },
    { name: 'Sweden', code: '+46', price: 40, countryId: 46, flag: '🇸🇪' },
    { name: 'Argentina', code: '+54', price: 40, countryId: 39, flag: '🇦🇷' },
    { name: 'Algeria', code: '+213', price: 100, countryId: 58, flag: '🇩🇿' },
    { name: 'France', code: '+33', price: 90, countryId: 78, flag: '🇫🇷' },
    { name: 'Greece', code: '+30', price: 130, countryId: 129, flag: '🇬🇷' },
    { name: 'United Kingdom', code: '+44', price: 40, countryId: 16, flag: '🇬🇧' },
    { name: 'South Africa', code: '+27', price: 35, countryId: 31, flag: '🇿🇦' },
    { name: 'Canada', code: '+1', price: 80, countryId: 36, flag: '🇨🇦' },
    { name: 'Bangladesh', code: '+880', price: 70, countryId: 60, flag: '🇧🇩' },
    { name: 'Italy', code: '+39', price: 80, countryId: 86, flag: '🇮🇹' },
    { name: 'Poland', code: '+48', price: 100, countryId: 15, flag: '🇵🇱' },
    { name: 'Nigeria', code: '+234', price: 90, countryId: 19, flag: '🇳🇬' },
    { name: 'Germany', code: '+49', price: 98, countryId: 43, flag: '🇩🇪' },
    { name: 'Spain', code: '+34', price: 100, countryId: 56, flag: '🇪🇸' },
    { name: 'Ghana', code: '+233', price: 40, countryId: 38, flag: '🇬🇭' },
    { name: 'Portugal', code: '+351', price: 40, countryId: 117, flag: '🇵🇹' },
    { name: 'Netherlands', code: '+31', price: 40, countryId: 48, flag: '🇳🇱' }
];


const tiktokCountries = [
    { name: 'Afghanistan', code: '', price: 32, countryId: 74, flag: '🇦🇫' },
    { name: 'Albania', code: '', price: 22.53, countryId: 155, flag: '🇦🇱' },
    { name: 'Angola', code: '', price: 18, countryId: 76, flag: '🇦🇴' },
    { name: 'Argentina', code: '', price: 13, countryId: 39, flag: '🇦🇷' },
    { name: 'Australia', code: '', price: 29.63, countryId: 175, flag: '🇦🇺' },
    { name: 'Austria', code: '', price: 17.53, countryId: 50, flag: '🇦🇹' },
    { name: 'Bangladesh', code: '', price: 18, countryId: 60, flag: '🇧🇩' },
    { name: 'Belarus', code: '', price: 48.40, countryId: 51, flag: '🇧🇾' },
    { name: 'Belgium', code: '', price: 45.90, countryId: 82, flag: '🇧🇪' },
    { name: 'Bulgaria', code: '', price: 2.50, countryId: 83, flag: '🇧🇬' },
    { name: 'Canada', code: '', price: 8.35, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '', price: 4.17, countryId: 151, flag: '🇨🇱' },
    { name: 'China', code: '', price: 45.07, countryId: 3, flag: '🇨🇳' },
    { name: 'Cyprus', code: '', price: 2.50, countryId: 77, flag: '🇨🇾' },
    { name: 'Czech Republic', code: '', price: 15.86, countryId: 63, flag: '🇨🇿' },
    { name: 'Denmark', code: '', price: 5.01, countryId: 172, flag: '🇩🇰' },
    { name: 'Estonia', code: '', price: 10.85, countryId: 34, flag: '🇪🇪' },
    { name: 'France', code: '', price: 7.51, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '', price: 5.84, countryId: 43, flag: '🇩🇪' },
    { name: 'Greece', code: '', price: 14.19, countryId: 129, flag: '🇬🇷' },
    { name: 'Guinea-Bissau', code: '', price: 2.50, countryId: 130, flag: '🇬🇼' },
    { name: 'Hong Kong', code: '', price: 48.40, countryId: 14, flag: '🇭🇰' },
    { name: 'Hungary', code: '', price: 5.01, countryId: 84, flag: '🇭🇺' },
    { name: 'India', code: '', price: 9.60, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '', price: 1.67, countryId: 6, flag: '🇮🇩' },
    { name: 'Italy', code: '', price: 5.84, countryId: 86, flag: '🇮🇹' },
    { name: 'Latvia', code: '', price: 13.35, countryId: 49, flag: '🇱🇻' },
    { name: 'Macau', code: '', price: 48.40, countryId: 20, flag: '🇲🇴' },
    { name: 'Malaysia', code: '', price: 30, countryId: 7, flag: '🇲🇾' },
    { name: 'Maldives', code: '', price: 2.50, countryId: 159, flag: '🇲🇻' },
    { name: 'Mauritania', code: '', price: 48.40, countryId: 114, flag: '🇲🇷' },
    { name: 'Mauritius', code: '', price: 40.06, countryId: 157, flag: '🇲🇺' },
    { name: 'Mexico', code: '', price: 4.59, countryId: 54, flag: '🇲🇽' },
    { name: 'Mongolia', code: '', price: 48.40, countryId: 72, flag: '🇲🇳' },
    { name: 'Nepal', code: '', price: 19, countryId: 81, flag: '🇳🇵' },
    { name: 'Netherlands', code: '', price: 7.93, countryId: 48, flag: '🇳🇱' },
    { name: 'Nigeria', code: '', price: 6.26, countryId: 19, flag: '🇳🇬' },
    { name: 'Pakistan', code: '', price: 30, countryId: 66, flag: '🇵🇰' },
    { name: 'Philippines', code: '', price: 3.34, countryId: 4, flag: '🇵🇭' },
    { name: 'Poland', code: '', price: 7.51, countryId: 15, flag: '🇵🇱' },
    { name: 'Puerto Rico', code: '', price: 48.40, countryId: 97, flag: '🇵🇷' },
    { name: 'Reunion', code: '', price: 48.40, countryId: 146, flag: '🇷🇪' },
    { name: 'Saudi Arabia', code: '', price: 28.37, countryId: 53, flag: '🇸🇦' },
    { name: 'South Sudan', code: '', price: 2.50, countryId: 177, flag: '🇸🇸' },
    { name: 'Spain', code: '', price: 16.69, countryId: 56, flag: '🇪🇸' },
    { name: 'Sri Lanka', code: '', price: 2.50, countryId: 64, flag: '🇱🇰' },
    { name: 'Sweden', code: '', price: 1.67, countryId: 46, flag: '🇸🇪' },
    { name: 'Switzerland', code: '', price: 12.94, countryId: 173, flag: '🇨🇭' },
    { name: 'Taiwan', code: '', price: 48.40, countryId: 55, flag: '🇹🇼' },
    { name: 'Turkey', code: '', price: 48.40, countryId: 62, flag: '🇹🇷' },
    { name: 'UAE', code: '', price: 17.94, countryId: 95, flag: '🇦🇪' },
    { name: 'Ukraine', code: '', price: 11.27, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '', price: 60, countryId: 16, flag: '🇬🇧' }, 
    { name: 'USA', code: '', price: 60, countryId: 187, flag: '🇺🇸' },    
    { name: 'Uzbekistan', code: '', price: 2.50, countryId: 40, flag: '🇺🇿' },
    { name: 'Vietnam', code: '', price: 15.86, countryId: 10, flag: '🇻🇳' },
    { name: 'Yemen', code: '', price: 2.50, countryId: 30, flag: '🇾🇪' }
];
const imoCountries = [
    { name: 'Saudi Arabia', code: '+966', price: 14, countryId: 53, flag: '🇸🇦' },
    { name: 'Thailand', code: '+66', price: 20, countryId: 52, flag: '🇹🇭' },
    { name: 'USA Virtual', code: '+1', price: 12, countryId: 12, flag: '🇺🇸' },
    { name: 'Malaysia', code: '+60', price: 19, countryId: 7, flag: '🇲🇾' },
    { name: 'Indonesia', code: '+62', price: 6, countryId: 6, flag: '🇮🇩' },
    { name: 'Italy', code: '+39', price: 60, countryId: 86, flag: '🇮🇹' },
    { name: 'USA', code: '+1', price: 10, countryId: 187, flag: '🇺🇸' },
    { name: 'Australia', code: '+61', price: 70, countryId: 175, flag: '🇦🇺' },
    { name: 'South Africa', code: '+27', price: 9, countryId: 31, flag: '🇿🇦' },
    { name: 'Portugal', code: '+351', price: 28, countryId: 117, flag: '🇵🇹' },
    { name: 'Canada', code: '+1', price: 9, countryId: 36, flag: '🇨🇦' },
    { name: 'Vietnam', code: '+84', price: 14, countryId: 10, flag: '🇻🇳' },
    { name: 'United Kingdom', code: '+44', price: 10, countryId: 16, flag: '🇬🇧' },
    { name: 'Hungary', code: '+36', price: 140, countryId: 84, flag: '🇭🇺' },
    { name: 'Sweden', code: '+46', price: 27, countryId: 46, flag: '🇸🇪' },
    { name: 'Bangladesh', code: '+880', price: 30, countryId: 60, flag: '🇧🇩' },
    { name: 'Turkey', code: '+90', price: 70, countryId: 62, flag: '🇹🇷' },
    { name: 'Austria', code: '+43', price: 80, countryId: 50, flag: '🇦🇹' },
    { name: 'Qatar', code: '+974', price: 190, countryId: 111, flag: '🇶🇦' },
    { name: 'Taiwan', code: '+886', price: 90, countryId: 55, flag: '🇹🇼' },
    { name: 'UAE', code: '+971', price: 40, countryId: 95, flag: '🇦🇪' },
    { name: 'Pakistan', code: '+92', price: 40, countryId: 66, flag: '🇵🇰' },
    { name: 'Mexico', code: '+52', price: 26, countryId: 54, flag: '🇲🇽' },
    { name: 'Bahamas', code: '+1', price: 200, countryId: 122, flag: '🇧🇸' },
    { name: 'Finland', code: '+358', price: 80, countryId: 163, flag: '🇫🇮' },
    { name: 'Oman', code: '+968', price: 200, countryId: 107, flag: '🇴🇲' },
    { name: 'Kuwait', code: '+965', price: 200, countryId: 100, flag: '🇰🇼' },
    { name: 'Spain', code: '+34', price: 60, countryId: 56, flag: '🇪🇸' },
    { name: 'Mongolia', code: '+976', price: 28, countryId: 72, flag: '🇲🇳' },
    { name: 'Cyprus', code: '+357', price: 40, countryId: 77, flag: '🇨🇾' },
    { name: 'Brazil', code: '+55', price: 9, countryId: 73, flag: '🇧🇷' },
    { name: 'France', code: '+33', price: 20, countryId: 78, flag: '🇫🇷' },
    { name: 'Netherlands', code: '+31', price: 25, countryId: 48, flag: '🇳🇱' },
    { name: 'Iraq', code: '+964', price: 200, countryId: 47, flag: '🇮🇶' },
    { name: 'Colombia', code: '+57', price: 29, countryId: 33, flag: '🇨🇴' },
    { name: 'Lithuania', code: '+370', price: 240, countryId: 44, flag: '🇱🇹' },
    { name: 'Yemen', code: '+967', price: 24, countryId: 30, flag: '🇾🇪' },
    { name: 'Philippines', code: '+63', price: 27, countryId: 4, flag: '🇵🇭' },
    { name: 'Poland', code: '+48', price: 26, countryId: 15, flag: '🇵🇱' },
    { name: 'Venezuela', code: '+58', price: 70, countryId: 70, flag: '🇻🇪' },
    { name: 'Romania', code: '+40', price: 40, countryId: 32, flag: '🇷🇴' },
    { name: 'Belarus', code: '+375', price: 90, countryId: 51, flag: '🇧🇾' },
    { name: 'Armenia', code: '+374', price: 200, countryId: 148, flag: '🇦🇲' },
    { name: 'Germany', code: '+49', price: 28, countryId: 43, flag: '🇩🇪' },
    { name: 'India', code: '+91', price: 25, countryId: 22, flag: '🇮🇳' },
    { name: 'Zambia', code: '+260', price: 29, countryId: 147, flag: '🇿🇲' },
    { name: 'Namibia', code: '+264', price: 24, countryId: 138, flag: '🇳🇦' },
    { name: 'Papua New Guinea', code: '+675', price: 30, countryId: 79, flag: '🇵🇬' },
    { name: 'Algeria', code: '+213', price: 27, countryId: 58, flag: '🇩🇿' },
    { name: 'Ethiopia', code: '+251', price: 40, countryId: 71, flag: '🇪🇹' },
    { name: 'Mozambique', code: '+258', price: 40, countryId: 80, flag: '🇲🇿' },
    { name: 'Angola', code: '+244', price: 10, countryId: 76, flag: '🇦🇴' },
    { name: 'Ukraine', code: '+380', price: 9, countryId: 1, flag: '🇺🇦' },
    { name: 'Egypt', code: '+20', price: 60, countryId: 21, flag: '🇪🇬' },
    { name: 'Haiti', code: '+509', price: 200, countryId: 26, flag: '🇭🇹' },
    { name: 'Iran', code: '+98', price: 40, countryId: 57, flag: '🇮🇷' },
    { name: 'Peru', code: '+51', price: 26, countryId: 65, flag: '🇵🇪' },
    { name: 'Zimbabwe', code: '+263', price: 28, countryId: 96, flag: '🇿🇼' },
    { name: 'Nepal', code: '+977', price: 40, countryId: 81, flag: '🇳🇵' },
    { name: 'Uzbekistan', code: '+998', price: 25, countryId: 40, flag: '🇺🇿' },
    { name: 'Nigeria', code: '+234', price: 29, countryId: 19, flag: '🇳🇬' },
    { name: 'Swaziland', code: '+268', price: 24, countryId: 106, flag: '🇸🇿' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 27, countryId: 18, flag: '🇨🇩' },
    { name: 'Botswana', code: '+267', price: 30, countryId: 123, flag: '🇧🇼' },
    { name: 'Tanzania', code: '+255', price: 26, countryId: 9, flag: '🇹🇿' },
    { name: 'Sri Lanka', code: '+94', price: 40, countryId: 64, flag: '🇱🇰' },
    { name: 'Honduras', code: '+504', price: 28, countryId: 88, flag: '🇭🇳' },
    { name: 'Argentina', code: '+54', price: 25, countryId: 39, flag: '🇦🇷' },
    { name: 'Myanmar', code: '+95', price: 29, countryId: 5, flag: '🇲🇲' },
    { name: 'Tunisia', code: '+216', price: 24, countryId: 89, flag: '🇹🇳' },
    { name: 'Timor-Leste', code: '+670', price: 27, countryId: 91, flag: '🇹🇱' },
    { name: 'Lesotho', code: '+266', price: 30, countryId: 136, flag: '🇱🇸' },
    { name: 'Ecuador', code: '+593', price: 40, countryId: 105, flag: '🇪🇨' },
    { name: 'El Salvador', code: '+503', price: 26, countryId: 101, flag: '🇸🇻' },
    { name: 'Morocco', code: '+212', price: 28, countryId: 37, flag: '🇲🇦' },
    { name: 'Uganda', code: '+256', price: 25, countryId: 75, flag: '🇺🇬' },
    { name: 'Malawi', code: '+265', price: 29, countryId: 137, flag: '🇲🇼' },
    { name: 'Ghana', code: '+233', price: 24, countryId: 38, flag: '🇬🇭' },
    { name: 'Kenya', code: '+254', price: 27, countryId: 8, flag: '🇰🇪' },
    { name: 'Panama', code: '+507', price: 30, countryId: 112, flag: '🇵🇦' },
    { name: 'Jamaica', code: '+1', price: 26, countryId: 103, flag: '🇯🇲' },
    { name: 'Kazakhstan', code: '+7', price: 28, countryId: 2, flag: '🇰🇿' },
    { name: 'Paraguay', code: '+595', price: 25, countryId: 87, flag: '🇵🇾' },
    { name: 'Kyrgyzstan', code: '+996', price: 29, countryId: 11, flag: '🇰🇬' },
    { name: 'Cameroon', code: '+237', price: 24, countryId: 41, flag: '🇨🇲' },
    { name: 'Cote d`Ivoire Ivory Coast', code: '+225', price: 27, countryId: 27, flag: '🇨🇮' },
    { name: 'Bulgaria', code: '+359', price: 30, countryId: 83, flag: '🇧🇬' },
    { name: 'Libya', code: '+218', price: 26, countryId: 102, flag: '🇱🇾' },
    { name: 'Mauritius', code: '+230', price: 28, countryId: 157, flag: '🇲🇺' },
    { name: 'Turkmenistan', code: '+993', price: 200, countryId: 161, flag: '🇹🇲' },
    { name: 'Azerbaijan', code: '+994', price: 90, countryId: 35, flag: '🇦🇿' },
    { name: 'Mali', code: '+223', price: 25, countryId: 69, flag: '🇲🇱' },
    { name: 'Rwanda', code: '+250', price: 40, countryId: 140, flag: '🇷🇼' },
    { name: 'Gabon', code: '+241', price: 200, countryId: 154, flag: '🇬🇦' },
    { name: 'Sudan', code: '+249', price: 120, countryId: 1010, flag: '🇸🇩' },
    { name: 'Nicaragua', code: '+505', price: 29, countryId: 90, flag: '🇳🇮' },
    { name: 'Moldova', code: '+373', price: 24, countryId: 85, flag: '🇲🇩' },
    { name: 'Benin', code: '+229', price: 27, countryId: 120, flag: '🇧🇯' },
    { name: 'Costa Rica', code: '+506', price: 30, countryId: 93, flag: '🇨🇷' },
    { name: 'Burkina Faso', code: '+226', price: 40, countryId: 152, flag: '🇧🇫' },
    { name: 'Belgium', code: '+32', price: 26, countryId: 82, flag: '🇧🇪' },
    { name: 'Reunion', code: '+262', price: 200, countryId: 146, flag: '🇷🇪' },
    { name: 'Congo', code: '+242', price: 28, countryId: 150, flag: '🇨🇬' },
    { name: 'Uruguay', code: '+598', price: 25, countryId: 156, flag: '🇺🇾' },
    { name: 'Senegal', code: '+221', price: 29, countryId: 61, flag: '🇸🇳' },
    { name: 'Laos', code: '+856', price: 24, countryId: 25, flag: '🇱🇦' },
    { name: 'Togo', code: '+228', price: 40, countryId: 99, flag: '🇹🇬' },
    { name: 'Niger', code: '+227', price: 40, countryId: 139, flag: '🇳🇪' },
    { name: 'Syria', code: '+963', price: 120, countryId: 1333, flag: '🇸🇾' },
    { name: 'Bhutan', code: '+975', price: 60, countryId: 158, flag: '🇧🇹' },
    { name: 'Burundi', code: '+257', price: 27, countryId: 119, flag: '🇧🇮' },
    { name: 'Equatorial Guinea', code: '+240', price: 200, countryId: 167, flag: '🇬🇶' },
    { name: 'Trinidad and Tobago', code: '+1', price: 60, countryId: 104, flag: '🇹🇹' },
    { name: 'Cambodia', code: '+855', price: 70, countryId: 24, flag: '🇰🇭' },
    { name: 'South Sudan', code: '+211', price: 26, countryId: 177, flag: '🇸🇸' },
    { name: 'Mauritania', code: '+222', price: 28, countryId: 114, flag: '🇲🇷' },
    { name: 'Guinea-Bissau', code: '+245', price: 200, countryId: 130, flag: '🇬🇼' },
    { name: 'Maldives', code: '+960', price: 25, countryId: 159, flag: '🇲🇻' },
    { name: 'Bosnia and Herzegovina', code: '+387', price: 29, countryId: 108, flag: '🇧🇦' },
    { name: 'Somalia', code: '+252', price: 24, countryId: 149, flag: '🇸🇴' },
    { name: 'Barbados', code: '+1', price: 27, countryId: 118, flag: '🇧🇧' },
    { name: 'Martinique', code: '+596', price: 30, countryId: 1011, flag: '🇲🇶' },
    { name: 'Dominican Republic', code: '+1', price: 26, countryId: 109, flag: '🇩🇴' },
    { name: 'Gambia', code: '+220', price: 28, countryId: 28, flag: '🇬🇲' },
    { name: 'Afghanistan', code: '+93', price: 25, countryId: 74, flag: '🇦🇫' },
    { name: 'Guyana', code: '+592', price: 29, countryId: 131, flag: '🇬🇾' },
    { name: 'Chad', code: '+235', price: 24, countryId: 42, flag: '🇹🇩' },
    { name: 'Switzerland', code: '+41', price: 27, countryId: 173, flag: '🇨🇭' },
    { name: 'Puerto Rico', code: '+1', price: 30, countryId: 97, flag: '🇵🇷' },
    { name: 'Ireland', code: '+353', price: 26, countryId: 23, flag: '🇮🇪' },
    { name: 'Serbia', code: '+381', price: 28, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 25, countryId: 34, flag: '🇪🇪' },
    { name: 'Bahrain', code: '+973', price: 29, countryId: 145, flag: '🇧🇭' },
    { name: 'Czech Republic', code: '+420', price: 24, countryId: 63, flag: '🇨🇿' },
    { name: 'Guadeloupe', code: '+590', price: 27, countryId: 160, flag: '🇬🇵' },
    { name: 'Luxembourg', code: '+352', price: 30, countryId: 165, flag: '🇱🇺' },
    { name: 'Suriname', code: '+597', price: 26, countryId: 142, flag: '🇸🇷' },
    { name: 'Guatemala', code: '+502', price: 28, countryId: 94, flag: '🇬🇹' },
    { name: 'Madagascar', code: '+261', price: 25, countryId: 17, flag: '🇲🇬' },
    { name: 'Antigua and Barbuda', code: '+1', price: 29, countryId: 169, flag: '🇦🇬' },
    { name: 'Djibouti', code: '+253', price: 24, countryId: 168, flag: '🇩🇯' },
    { name: 'French Guiana', code: '+594', price: 27, countryId: 162, flag: '🇬🇫' },
    { name: 'Saint Lucia', code: '+1', price: 30, countryId: 164, flag: '🇱🇨' },
    { name: 'Montenegro', code: '+382', price: 26, countryId: 171, flag: '🇲🇪' },
    { name: 'Cuba', code: '+53', price: 28, countryId: 113, flag: '🇨🇺' },
    { name: 'Greece', code: '+30', price: 25, countryId: 129, flag: '🇬🇷' },
    { name: 'Chile', code: '+56', price: 29, countryId: 151, flag: '🇨🇱' },
    { name: 'Georgia', code: '+995', price: 24, countryId: 128, flag: '🇬🇪' },
    { name: 'Sierra Leone', code: '+232', price: 27, countryId: 115, flag: '🇸🇱' },
    { name: 'Bolivia', code: '+591', price: 30, countryId: 92, flag: '🇧🇴' },
    { name: 'Grenada', code: '+1', price: 26, countryId: 127, flag: '🇬🇩' },
    { name: 'Latvia', code: '+371', price: 28, countryId: 49, flag: '🇱🇻' },
    { name: 'Tajikistan', code: '+992', price: 25, countryId: 143, flag: '🇹🇯' },
    { name: 'Brunei Darussalam', code: '+673', price: 29, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 24, countryId: 170, flag: '🇰🇾' },
    { name: 'Saint Vincent', code: '+1', price: 27, countryId: 166, flag: '🇻🇨' },
    { name: 'Albania', code: '+355', price: 30, countryId: 155, flag: '🇦🇱' },
    { name: 'Slovenia', code: '+386', price: 26, countryId: 59, flag: '🇸🇮' },
    { name: 'Hong Kong', code: '+852', price: 120, countryId: 14, flag: '🇭🇰' },
    { name: 'Saint Kitts and Nevis', code: '+1', price: 28, countryId: 134, flag: '🇰🇳' },
    { name: 'CAF', code: '+236', price: 25, countryId: 125, flag: '🇨🇫' },
    { name: 'Liberia', code: '+231', price: 29, countryId: 135, flag: '🇱🇷' },
    { name: 'Guinea', code: '+224', price: 24, countryId: 68, flag: '🇬🇳' },
    { name: 'Aruba', code: '+297', price: 60, countryId: 179, flag: '🇦🇼' },
    { name: 'Comoros', code: '+269', price: 27, countryId: 133, flag: '🇰🇲' },
    { name: 'Malta', code: '+356', price: 90, countryId: 199, flag: '🇲🇹' },
    { name: 'Singapore', code: '+65', price: 120, countryId: 196, flag: '🇸🇬' },
    { name: 'Slovakia', code: '+421', price: 26, countryId: 141, flag: '🇸🇰' },
    { name: 'Anguilla', code: '+1', price: 90, countryId: 181, flag: '🇦🇮' },
    { name: 'Sao Tome and Principe', code: '+239', price: 28, countryId: 178, flag: '🇸🇹' },
    { name: 'Fiji', code: '+679', price: 120, countryId: 189, flag: '🇫🇯' },
    { name: 'Croatia', code: '+385', price: 25, countryId: 45, flag: '🇭🇷' },
    { name: 'Cape Verde', code: '+238', price: 29, countryId: 186, flag: '🇨🇻' },
    { name: 'Monaco', code: '+377', price: 100, countryId: 144, flag: '🇲🇨' },
    { name: 'North Macedonia', code: '+389', price: 24, countryId: 183, flag: '🇲🇰' },
    { name: 'Belize', code: '+501', price: 27, countryId: 124, flag: '🇧🇿' },
    { name: 'New Caledonia', code: '+687', price: 200, countryId: 185, flag: '🇳🇨' },
    { name: 'New Zealand', code: '+64', price: 26, countryId: 67, flag: '🇳🇿' },
    { name: 'Lebanon', code: '+961', price: 28, countryId: 153, flag: '🇱🇧' },
    { name: 'Denmark', code: '+45', price: 25, countryId: 172, flag: '🇩🇰' },
    { name: 'Seychelles', code: '+248', price: 29, countryId: 184, flag: '🇸🇨' },
    { name: 'Montserrat', code: '+1', price: 24, countryId: 180, flag: '🇲🇸' },
    { name: 'Dominica', code: '+1', price: 27, countryId: 126, flag: '🇩🇲' },
    { name: 'Macau', code: '+853', price: 40, countryId: 20, flag: '🇲🇴' },
    { name: 'Iceland', code: '+354', price: 40, countryId: 132, flag: '🇮🇸' },
    { name: 'Eritrea', code: '+291', price: 40, countryId: 176, flag: '🇪🇷' }
];
const tinderCountries = [
    { name: 'USA', code: '', price: 70, countryId: 187, flag: '🇺🇸' },
    { name: 'Colombia', code: '', price: 9, countryId: 33, flag: '🇨🇴' },
    { name: 'France', code: '', price: 60, countryId: 78, flag: '🇫🇷' },
    { name: 'Italy', code: '', price: 40, countryId: 86, flag: '🇮🇹' },
    { name: 'Spain', code: '', price: 70, countryId: 56, flag: '🇪🇸' },
    { name: 'Turkey', code: '', price: 60, countryId: 62, flag: '🇹🇷' },
    { name: 'Germany', code: '', price: 60, countryId: 43, flag: '🇩🇪' },
    { name: 'India', code: '', price: 60, countryId: 22, flag: '🇮🇳' },
    { name: 'Greece', code: '', price: 60, countryId: 129, flag: '🇬🇷' },
    { name: 'Ukraine', code: '', price: 20, countryId: 1, flag: '🇺🇦' },
    { name: 'Brazil', code: '', price: 8, countryId: 73, flag: '🇧🇷' },
    { name: 'Portugal', code: '', price: 70, countryId: 117, flag: '🇵🇹' },
    { name: 'Poland', code: '', price: 40, countryId: 15, flag: '🇵🇱' },
    { name: 'Switzerland', code: '', price: 60, countryId: 173, flag: '🇨🇭' },
    { name: 'Argentina', code: '', price: 60, countryId: 39, flag: '🇦🇷' },
    { name: 'South Africa', code: '', price: 10, countryId: 31, flag: '🇿🇦' },
    { name: 'United Kingdom', code: '', price: 10, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '', price: 40, countryId: 48, flag: '🇳🇱' },
    { name: 'Vietnam', code: '', price: 20, countryId: 10, flag: '🇻🇳' },
    { name: 'Madagascar', code: '', price: 20, countryId: 17, flag: '🇲🇬' },
    { name: 'Estonia', code: '', price: 40, countryId: 34, flag: '🇪🇪' },
    { name: 'Philippines', code: '', price: 20, countryId: 4, flag: '🇵🇭' },
    { name: 'Malawi', code: '', price: 60, countryId: 137, flag: '🇲🇼' },
    { name: 'Croatia', code: '', price: 60, countryId: 45, flag: '🇭🇷' },
    { name: 'Nigeria', code: '', price: 40, countryId: 19, flag: '🇳🇬' },
    { name: 'Saudi Arabia', code: '', price: 70, countryId: 53, flag: '🇸🇦' },
    { name: 'Hungary', code: '', price: 60, countryId: 84, flag: '🇭🇺' },
    { name: 'Lithuania', code: '', price: 60, countryId: 44, flag: '🇱🇹' },
    { name: 'Yemen', code: '', price: 60, countryId: 30, flag: '🇾🇪' },
    { name: 'Austria', code: '', price: 60, countryId: 50, flag: '🇦🇹' },
    { name: 'Mozambique', code: '', price: 10, countryId: 80, flag: '🇲🇿' },
    { name: 'Slovakia', code: '', price: 66, countryId: 141, flag: '🇸🇰' },
    { name: 'Ireland', code: '', price: 60, countryId: 23, flag: '🇮🇪' },
    { name: 'Angola', code: '', price: 60, countryId: 76, flag: '🇦🇴' },
    { name: 'Peru', code: '', price: 60, countryId: 65, flag: '🇵🇪' },
    { name: 'Thailand', code: '', price: 20, countryId: 52, flag: '🇹🇭' },
    { name: 'Indonesia', code: '', price: 10, countryId: 6, flag: '🇮🇩' },
    { name: 'Botswana', code: '', price: 70, countryId: 123, flag: '🇧🇼' },
    { name: 'Sweden', code: '', price: 60, countryId: 46, flag: '🇸🇪' },
    { name: 'Latvia', code: '', price: 60, countryId: 49, flag: '🇱🇻' },
    { name: 'Belgium', code: '', price: 60, countryId: 82, flag: '🇧🇪' },
    { name: 'Cyprus', code: '', price: 60, countryId: 77, flag: '🇨🇾' },
    { name: 'Kenya', code: '', price: 40, countryId: 8, flag: '🇰🇪' },
    { name: 'Norway', code: '', price: 60, countryId: 174, flag: '🇳🇴' },
    { name: 'Chile', code: '', price: 19, countryId: 151, flag: '🇨🇱' },
    { name: 'Georgia', code: '', price: 60, countryId: 128, flag: '🇬🇪' },
    { name: 'Libya', code: '', price: 10, countryId: 102, flag: '🇱🇾' },
    { name: 'Egypt', code: '', price: 30, countryId: 21, flag: '🇪🇬' },
    { name: 'Liberia', code: '', price: 28, countryId: 135, flag: '🇱🇷' },
    { name: 'Romania', code: '', price: 40, countryId: 32, flag: '🇷🇴' },
    { name: 'Kazakhstan', code: '', price: 40, countryId: 2, flag: '🇰🇿' },
    { name: 'Australia', code: '', price: 60, countryId: 175, flag: '🇦🇺' },
    { name: 'Ghana', code: '', price: 30, countryId: 38, flag: '🇬🇭' },
    { name: 'UAE', code: '', price: 20, countryId: 95, flag: '🇦🇪' },
    { name: 'Albania', code: '', price: 100, countryId: 155, flag: '🇦🇱' },
    { name: 'Bosnia and Herzegovina', code: '', price: 60, countryId: 108, flag: '🇧🇦' },
    { name: 'Macedonia', code: '', price: 60, countryId: 183, flag: '🇲🇰' },
    { name: 'Bulgaria', code: '', price: 60, countryId: 83, flag: '🇧🇬' },
    { name: 'Bahrain', code: '', price: 200, countryId: 145, flag: '🇧🇭' },
    { name: 'Serbia', code: '', price: 60, countryId: 29, flag: '🇷🇸' },
    { name: 'Costa Rica', code: '', price: 200, countryId: 93, flag: '🇨🇷' },
    { name: 'Nepal', code: '', price: 60, countryId: 81, flag: '🇳🇵' },
    { name: 'Niger', code: '', price: 14, countryId: 139, flag: '🇳🇪' },
    { name: 'Trinidad and Tobago', code: '', price: 60, countryId: 104, flag: '🇹🇹' },
    { name: 'Laos', code: '', price: 30, countryId: 25, flag: '🇱🇦' },
    { name: 'Canada', code: '', price: 40, countryId: 36, flag: '🇨🇦' },
    { name: 'Finland', code: '', price: 60, countryId: 163, flag: '🇫🇮' },
    { name: 'Taiwan', code: '', price: 60, countryId: 55, flag: '🇹🇼' },
    { name: 'Papua New Guinea', code: '', price: 60, countryId: 79, flag: '🇵🇬' },
    { name: 'Hong Kong', code: '', price: 60, countryId: 14, flag: '🇭🇰' },
    { name: 'Mexico', code: '', price: 60, countryId: 54, flag: '🇲🇽' },
    { name: 'Bangladesh', code: '', price: 40, countryId: 60, flag: '🇧🇩' },
    { name: 'USA Virtual', code: '', price: 9, countryId: 12, flag: '🇺🇸' },
    { name: 'Singapore', code: '', price: 10, countryId: 196, flag: '🇸🇬' },
    { name: 'Malaysia', code: '', price: 40, countryId: 7, flag: '🇲🇾' },
    { name: 'Mauritania', code: '', price: 60, countryId: 114, flag: '🇲🇷' },
    { name: 'Tanzania', code: '', price: 60, countryId: 9, flag: '🇹🇿' },
    { name: 'Togo', code: '', price: 60, countryId: 99, flag: '🇹🇬' },
    { name: 'Moldova', code: '', price: 60, countryId: 85, flag: '🇲🇩' },
    { name: 'Belarus', code: '', price: 200, countryId: 51, flag: '🇧🇾' },
    { name: 'Namibia', code: '', price: 14, countryId: 138, flag: '🇳🇦' },
    { name: 'Jamaica', code: '', price: 30, countryId: 103, flag: '🇯🇲' },
    { name: 'Cambodia', code: '', price: 30, countryId: 24, flag: '🇰🇭' },
    { name: 'Cameroon', code: '', price: 14, countryId: 41, flag: '🇨🇲' },
    { name: 'Chad', code: '', price: 60, countryId: 42, flag: '🇹🇩' },
    { name: 'Mali', code: '', price: 18, countryId: 69, flag: '🇲🇱' },
    { name: 'Azerbaijan', code: '', price: 60, countryId: 35, flag: '🇦🇿' },
    { name: 'Sao Tome and Principe', code: '', price: 90, countryId: 178, flag: '🇸🇹' },
    { name: 'Slovenia', code: '', price: 30, countryId: 59, flag: '🇸🇮' },
    { name: 'Senegal', code: '', price: 19, countryId: 61, flag: '🇸🇳' },
    { name: 'Macau', code: '', price: 20, countryId: 20, flag: '🇲🇴' }
];
const twitterCountries = [
    { name: 'Brazil', code: '', price: 9, countryId: 73, flag: '🇧🇷' },
    { name: 'United Kingdom', code: '', price: 10, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '', price: 40, countryId: 187, flag: '🇺🇸' },
    { name: 'Croatia', code: '', price: 30, countryId: 45, flag: '🇭🇷' },
    { name: 'USA Virtual', code: '', price: 20, countryId: 12, flag: '🇺🇸' },
    { name: 'Germany', code: '', price: 14, countryId: 43, flag: '🇩🇪' },
    { name: 'Romania', code: '', price: 30, countryId: 32, flag: '🇷🇴' },
    { name: 'Malaysia', code: '', price: 30, countryId: 7, flag: '🇲🇾' },
    { name: 'Bangladesh', code: '', price: 40, countryId: 60, flag: '🇧🇩' },
    { name: 'Netherlands', code: '', price: 14, countryId: 48, flag: '🇳🇱' },
    { name: 'Libya', code: '', price: 20, countryId: 102, flag: '🇱🇾' },
    { name: 'Latvia', code: '', price: 10, countryId: 49, flag: '🇱🇻' },
    { name: 'Saudi Arabia', code: '', price: 30, countryId: 53, flag: '🇸🇦' },
    { name: 'Taiwan', code: '', price: 70, countryId: 55, flag: '🇹🇼' },
    { name: 'South Africa', code: '', price: 20, countryId: 31, flag: '🇿🇦' },
    { name: 'Philippines', code: '', price: 20, countryId: 4, flag: '🇵🇭' },
    { name: 'Spain', code: '', price: 20, countryId: 56, flag: '🇪🇸' },
    { name: 'Tajikistan', code: '', price: 40, countryId: 143, flag: '🇹🇯' },
    { name: 'Indonesia', code: '', price: 7, countryId: 6, flag: '🇮🇩' },
    { name: 'Canada', code: '', price: 10, countryId: 36, flag: '🇨🇦' },
    { name: 'Ukraine', code: '', price: 20, countryId: 1, flag: '🇺🇦' },
    { name: 'India', code: '', price: 60, countryId: 22, flag: '🇮🇳' },
    { name: 'Pakistan', code: '', price: 70, countryId: 66, flag: '🇵🇰' }
];
const amazonCountries = [
    { name: 'Colombia', code: '+57', price: 19, countryId: 33, flag: '🇨🇴' },
    { name: 'Brazil', code: '+55', price: 17, countryId: 73, flag: '🇧🇷' },
    { name: 'USA Virtual', code: '+1', price: 20, countryId: 12, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 30, countryId: 36, flag: '🇨🇦' },
    { name: 'Saudi Arabia', code: '+966', price: 40, countryId: 53, flag: '🇸🇦' },
    { name: 'United Kingdom', code: '+44', price: 30, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 30, countryId: 187, flag: '🇺🇸' },
    { name: 'South Africa', code: '+27', price: 30, countryId: 31, flag: '🇿🇦' },
    { name: 'Thailand', code: '+66', price: 20, countryId: 52, flag: '🇹🇭' },
    { name: 'India', code: '+91', price: 60, countryId: 22, flag: '🇮🇳' },
    { name: 'Italy', code: '+39', price: 40, countryId: 86, flag: '🇮🇹' },
    { name: 'France', code: '+33', price: 40, countryId: 78, flag: '🇫🇷' },
    { name: 'Spain', code: '+34', price: 30, countryId: 56, flag: '🇪🇸' },
    { name: 'UAE', code: '+971', price: 80, countryId: 95, flag: '🇦🇪' },
    { name: 'Indonesia', code: '+62', price: 8, countryId: 6, flag: '🇮🇩' },
    { name: 'Pakistan', code: '+92', price: 40, countryId: 66, flag: '🇵🇰' }
];
const alibabaCountries = [
    { name: 'Indonesia', code: '+62', price: 9, countryId: 6, flag: '🇮🇩' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Pakistan', code: '+92', price: 8.37, countryId: 66, flag: '🇵🇰' },
    { name: 'France', code: '+33', price: 6.55, countryId: 78, flag: '🇫🇷' },
    { name: 'Turkey', code: '+90', price: 42.22, countryId: 62, flag: '🇹🇷' },
    { name: 'Hungary', code: '+36', price: 42.22, countryId: 84, flag: '🇭🇺' },
    { name: 'Italy', code: '+39', price: 42.22, countryId: 86, flag: '🇮🇹' },
    { name: 'Saudi Arabia', code: '+966', price: 25.48, countryId: 53, flag: '🇸🇦' },
    { name: 'Guatemala', code: '+502', price: 42.22, countryId: 94, flag: '🇬🇹' },
    { name: 'Finland', code: '+358', price: 42.22, countryId: 163, flag: '🇫🇮' },
    { name: 'USA', code: '+1', price: 37.86, countryId: 187, flag: '🇺🇸' },
    { name: 'Botswana', code: '+267', price: 42.22, countryId: 123, flag: '🇧🇼' },
    { name: 'Bangladesh', code: '+880', price: 42.22, countryId: 60, flag: '🇧🇩' },
    { name: 'Costa Rica', code: '+506', price: 42.22, countryId: 93, flag: '🇨🇷' },
    { name: 'Hong Kong', code: '+852', price: 42.22, countryId: 14, flag: '🇭🇰' },
    { name: 'Sierra Leone', code: '+232', price: 42.22, countryId: 115, flag: '🇸🇱' },
    { name: 'Mongolia', code: '+976', price: 42.22, countryId: 72, flag: '🇲🇳' },
    { name: 'Canada', code: '+1', price: 18.56, countryId: 36, flag: '🇨🇦' },
    { name: 'Czech Republic', code: '+420', price: 40.77, countryId: 63, flag: '🇨🇿' },
    { name: 'Mexico', code: '+52', price: 42.22, countryId: 54, flag: '🇲🇽' },
    { name: 'Madagascar', code: '+261', price: 42.22, countryId: 17, flag: '🇲🇬' },
    { name: 'Cambodia', code: '+855', price: 42.22, countryId: 24, flag: '🇰🇭' },
    { name: 'Taiwan', code: '+886', price: 42.22, countryId: 55, flag: '🇹🇼' },
    { name: 'Spain', code: '+34', price: 40.04, countryId: 56, flag: '🇪🇸' },
    { name: 'Portugal', code: '+351', price: 42.22, countryId: 117, flag: '🇵🇹' },
    { name: 'Niger', code: '+227', price: 42.22, countryId: 139, flag: '🇳🇪' },
    { name: 'Austria', code: '+43', price: 42.22, countryId: 50, flag: '🇦🇹' },
    { name: 'Myanmar', code: '+95', price: 42.22, countryId: 5, flag: '🇲🇲' },
    { name: 'United Kingdom', code: '+44', price: 42.22, countryId: 16, flag: '🇬🇧' },
    { name: 'Dominican Republic', code: '+1', price: 42.22, countryId: 109, flag: '🇩🇴' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 42.22, countryId: 18, flag: '🇨🇩' },
    { name: 'Norway', code: '+47', price: 42.22, countryId: 174, flag: '🇳🇴' },
    { name: 'India', code: '+91', price: 42.22, countryId: 22, flag: '🇮🇳' },
    { name: 'Zambia', code: '+260', price: 42.22, countryId: 147, flag: '🇿🇲' },
    { name: 'Algeria', code: '+213', price: 42.22, countryId: 58, flag: '🇩🇿' },
    { name: 'Ethiopia', code: '+251', price: 42.22, countryId: 71, flag: '🇪🇹' },
    { name: 'Papua new gvineya', code: '+675', price: 42.22, countryId: 79, flag: '🇵🇬' }
];
const careemCountries = [
    { name: 'Austria', code: '+43', price: 114.07, countryId: 50, flag: '🇦🇹' },
    { name: 'Bangladesh', code: '+880', price: 49.78, countryId: 60, flag: '🇧🇩' },
    { name: 'Brazil', code: '+55', price: 1.57, countryId: 73, flag: '🇧🇷' },
    { name: 'Canada', code: '+1', price: 27.83, countryId: 36, flag: '🇨🇦' },
    { name: 'Colombia', code: '+57', price: 83.10, countryId: 33, flag: '🇨🇴' },
    { name: 'Czech Republic', code: '+420', price: 33.71, countryId: 63, flag: '🇨🇿' },
    { name: 'Egypt', code: '+20', price: 74.87, countryId: 21, flag: '🇪🇬' },
    { name: 'El Salvador', code: '+503', price: 98.78, countryId: 101, flag: '🇸🇻' },
    { name: 'Germany', code: '+49', price: 54.49, countryId: 43, flag: '🇩🇪' },
    { name: 'Ghana', code: '+233', price: 35.28, countryId: 38, flag: '🇬🇭' },
    { name: 'Haiti', code: '+509', price: 150.53, countryId: 26, flag: '🇭🇹' },
    { name: 'Hungary', code: '+36', price: 275.18, countryId: 84, flag: '🇭🇺' },
    { name: 'India', code: '+91', price: 10.58, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '+62', price: 13.72, countryId: 6, flag: '🇮🇩' },
    { name: 'Iran', code: '+98', price: 112.90, countryId: 57, flag: '🇮🇷' },
    { name: 'Jamaica', code: '+1', price: 98.78, countryId: 103, flag: '🇯🇲' },
    { name: 'Kazakhstan', code: '+7', price: 43.12, countryId: 2, flag: '🇰🇿' },
    { name: 'Kenya', code: '+254', price: 4.31, countryId: 8, flag: '🇰🇪' },
    { name: 'Malawi', code: '+265', price: 49.78, countryId: 137, flag: '🇲🇼' },
    { name: 'Malaysia', code: '+60', price: 75.26, countryId: 7, flag: '🇲🇾' },
    { name: 'Morocco', code: '+212', price: 65.46, countryId: 37, flag: '🇲🇦' },
    { name: 'Nepal', code: '+977', price: 59.58, countryId: 81, flag: '🇳🇵' },
    { name: 'Nigeria', code: '+234', price: 44.69, countryId: 19, flag: '🇳🇬' },
    { name: 'Pakistan', code: '+92', price: 59.58, countryId: 66, flag: '🇵🇰' },
    { name: 'Panama', code: '+507', price: 98.78, countryId: 112, flag: '🇵🇦' },
    { name: 'Paraguay', code: '+595', price: 98.78, countryId: 87, flag: '🇵🇾' },
    { name: 'Peru', code: '+51', price: 59.58, countryId: 65, flag: '🇵🇪' },
    { name: 'Philippines', code: '+63', price: 3.14, countryId: 4, flag: '🇵🇭' },
    { name: 'Saudi Arabia', code: '+966', price: 87.42, countryId: 53, flag: '🇸🇦' },
    { name: 'Singapore', code: '+65', price: 157.58, countryId: 196, flag: '🇸🇬' },
    { name: 'South Africa', code: '+27', price: 1.57, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '+34', price: 51.74, countryId: 56, flag: '🇪🇸' },
    { name: 'Uganda', code: '+256', price: 74.87, countryId: 75, flag: '🇺🇬' },
    { name: 'Ukraine', code: '+380', price: 38.81, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 62.72, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 29.40, countryId: 187, flag: '🇺🇸' },
    { name: 'Venezuela', code: '+58', price: 77.62, countryId: 70, flag: '🇻🇪' },
    { name: 'Zambia', code: '+260', price: 59.58, countryId: 147, flag: '🇿🇲' },
    { name: 'Zimbabwe', code: '+263', price: 98.78, countryId: 96, flag: '🇿🇼' }
];
const spotifyCountries = [
    { name: 'USA', code: '+1', price: 160, countryId: 187, flag: '🇺🇸' }
];
const openaiCountries = [
    { name: 'Afghanistan', code: '', price: 38.81, countryId: 74, flag: '🇦🇫' },
    { name: 'Algeria', code: '', price: 123.87, countryId: 58, flag: '🇩🇿' },
    { name: 'Argentina', code: '', price: 1.57, countryId: 39, flag: '🇦🇷' },
    { name: 'Azerbaijan', code: '', price: 123.87, countryId: 35, flag: '🇦🇿' },
    { name: 'Belgium', code: '', price: 2.35, countryId: 82, flag: '🇧🇪' },
    { name: 'Brazil', code: '', price: 1.57, countryId: 73, flag: '🇧🇷' },
    { name: 'Burundi', code: '', price: 123.87, countryId: 119, flag: '🇧🇮' },
    { name: 'Canada', code: '', price: 13.33, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '', price: 2.35, countryId: 151, flag: '🇨🇱' },
    { name: 'Ecuador', code: '', price: 123.87, countryId: 105, flag: '🇪🇨' },
    { name: 'Finland', code: '', price: 264.99, countryId: 163, flag: '🇫🇮' },
    { name: 'France', code: '', price: 2.35, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '', price: 3.92, countryId: 43, flag: '🇩🇪' },
    { name: 'Hong Kong', code: '', price: 2.35, countryId: 14, flag: '🇭🇰' },
    { name: 'Hungary', code: '', price: 281.46, countryId: 84, flag: '🇭🇺' },
    { name: 'India', code: '', price: 26.26, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '', price: 3.92, countryId: 6, flag: '🇮🇩' },
    { name: 'Italy', code: '', price: 52.53, countryId: 86, flag: '🇮🇹' },
    { name: 'Latvia', code: '', price: 42.34, countryId: 49, flag: '🇱🇻' },
    { name: 'Mexico', code: '', price: 88.59, countryId: 54, flag: '🇲🇽' },
    { name: 'Myanmar', code: '', price: 78.40, countryId: 5, flag: '🇲🇲' },
    { name: 'Netherlands', code: '', price: 2.35, countryId: 48, flag: '🇳🇱' },
    { name: 'Norway', code: '', price: 264.99, countryId: 174, flag: '🇳🇴' },
    { name: 'Pakistan', code: '', price: 106.23, countryId: 66, flag: '🇵🇰' },
    { name: 'Peru', code: '', price: 88.59, countryId: 65, flag: '🇵🇪' },
    { name: 'Poland', code: '', price: 10.58, countryId: 15, flag: '🇵🇱' },
    { name: 'Portugal', code: '', price: 2.35, countryId: 117, flag: '🇵🇹' },
    { name: 'Saudi Arabia', code: '', price: 92.51, countryId: 53, flag: '🇸🇦' },
    { name: 'Singapore', code: '', price: 2.35, countryId: 196, flag: '🇸🇬' },
    { name: 'South Africa', code: '', price: 1.57, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '', price: 3.14, countryId: 56, flag: '🇪🇸' },
    { name: 'Sweden', code: '', price: 10.58, countryId: 46, flag: '🇸🇪' },
    { name: 'Taiwan', code: '', price: 353.58, countryId: 55, flag: '🇹🇼' },
    { name: 'Tajikistan', code: '', price: 196.78, countryId: 143, flag: '🇹🇯' },
    { name: 'Thailand', code: '', price: 2.35, countryId: 52, flag: '🇹🇭' },
    { name: 'Turkey', code: '', price: 123.87, countryId: 62, flag: '🇹🇷' },
    { name: 'UAE', code: '', price: 194.43, countryId: 95, flag: '🇦🇪' },
    { name: 'Ukraine', code: '', price: 4.31, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '', price: 15.29, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '', price: 41.94, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '', price: 1.57, countryId: 12, flag: '🇺🇸' },
    { name: 'Vietnam', code: '', price: 2.35, countryId: 10, flag: '🇻🇳' }
];
const paypalCountries = [
    { name: 'Iran', code: '', price: 2.35, countryId: 57, flag: '🇮🇷' },
    { name: 'Serbia', code: '', price: 196.78, countryId: 29, flag: '🇷🇸' },
    { name: 'Turkey', code: '', price: 196.78, countryId: 62, flag: '🇹🇷' },
    { name: 'Azerbaijan', code: '', price: 278.71, countryId: 35, flag: '🇦🇿' },
    { name: 'Nigeria', code: '', price: 1.57, countryId: 19, flag: '🇳🇬' },
    { name: 'Uruguay', code: '', price: 245.78, countryId: 156, flag: '🇺🇾' },
    { name: 'Belarus', code: '', price: 196.78, countryId: 51, flag: '🇧🇾' },
    { name: 'Honduras', code: '', price: 196.78, countryId: 88, flag: '🇭🇳' },
    { name: 'Georgia', code: '', price: 161.11, countryId: 128, flag: '🇬🇪' },
    { name: 'Malaysia', code: '', price: 88.59, countryId: 7, flag: '🇲🇾' },
    { name: 'Mongolia', code: '', price: 2.35, countryId: 72, flag: '🇲🇳' },
    { name: 'Algeria', code: '', price: 54.49, countryId: 58, flag: '🇩🇿' },
    { name: 'Egypt', code: '', price: 1.57, countryId: 21, flag: '🇪🇬' },
    { name: 'New Zealand', code: '', price: 896.90, countryId: 67, flag: '🇳🇿' },
    { name: 'Botswana', code: '', price: 2.35, countryId: 123, flag: '🇧🇼' },
    { name: 'Pakistan', code: '', price: 2.35, countryId: 66, flag: '🇵🇰' },
    { name: 'Bahrain', code: '', price: 174.83, countryId: 145, flag: '🇧🇭' },
    { name: 'Saudi Arabia', code: '', price: 60.37, countryId: 53, flag: '🇸🇦' },
    { name: 'Cuba', code: '', price: 2.35, countryId: 113, flag: '🇨🇺' },
    { name: 'Kazakhstan', code: '', price: 27.44, countryId: 2, flag: '🇰🇿' },
    { name: 'Bosnia and Herzegovina', code: '', price: 196.78, countryId: 108, flag: '🇧🇦' },
    { name: 'Venezuela', code: '', price: 7.06, countryId: 70, flag: '🇻🇪' },
    { name: 'Tajikistan', code: '', price: 29.79, countryId: 143, flag: '🇹🇯' },
    { name: 'Estonia', code: '', price: 122.30, countryId: 34, flag: '🇪🇪' },
    { name: 'Slovenia', code: '', price: 4.31, countryId: 59, flag: '🇸🇮' },
    { name: 'Japan', code: '', price: 4043.87, countryId: 1001, flag: '🇯🇵' },
    { name: 'Mexico', code: '', price: 91.73, countryId: 54, flag: '🇲🇽' },
    { name: 'Taiwan', code: '', price: 212.46, countryId: 55, flag: '🇹🇼' },
    { name: 'Hong Kong', code: '', price: 5.49, countryId: 14, flag: '🇭🇰' },
    { name: 'Vietnam', code: '', price: 16.86, countryId: 10, flag: '🇻🇳' },
    { name: 'Qatar', code: '', price: 174.83, countryId: 111, flag: '🇶🇦' },
    { name: 'India', code: '', price: 1.57, countryId: 22, flag: '🇮🇳' },
    { name: 'Guyana', code: '', price: 196.78, countryId: 131, flag: '🇬🇾' },
    { name: 'Norway', code: '', price: 276.36, countryId: 174, flag: '🇳🇴' },
    { name: 'Cameroon', code: '', price: 2.35, countryId: 41, flag: '🇨🇲' },
    { name: 'Macedonia', code: '', price: 161.11, countryId: 183, flag: '🇲🇰' },
    { name: 'Argentina', code: '', price: 10.58, countryId: 39, flag: '🇦🇷' },
    { name: 'Lithuania', code: '', price: 473.54, countryId: 44, flag: '🇱🇹' },
    { name: 'Czech Republic', code: '', price: 120.34, countryId: 63, flag: '🇨🇿' },
    { name: 'Ireland', code: '', price: 264.99, countryId: 23, flag: '🇮🇪' },
    { name: 'Bulgaria', code: '', price: 81.14, countryId: 83, flag: '🇧🇬' },
    { name: 'Austria', code: '', price: 158.37, countryId: 50, flag: '🇦🇹' },
    { name: 'Poland', code: '', price: 4.70, countryId: 15, flag: '🇵🇱' },
    { name: 'Italy', code: '', price: 73.30, countryId: 86, flag: '🇮🇹' },
    { name: 'Canada', code: '', price: 53.31, countryId: 36, flag: '🇨🇦' },
    { name: 'Netherlands', code: '', price: 73.30, countryId: 48, flag: '🇳🇱' },
    { name: 'Brazil', code: '', price: 1.57, countryId: 73, flag: '🇧🇷' },
    { name: 'Indonesia', code: '', price: 2.35, countryId: 6, flag: '🇮🇩' },
    { name: 'Singapore', code: '', price: 152.88, countryId: 196, flag: '🇸🇬' },
    { name: 'Spain', code: '', price: 152.88, countryId: 56, flag: '🇪🇸' },
    { name: 'UAE', code: '', price: 73.30, countryId: 95, flag: '🇦🇪' },
    { name: 'Romania', code: '', price: 73.30, countryId: 32, flag: '🇷🇴' },
    { name: 'Chile', code: '', price: 1.57, countryId: 151, flag: '🇨🇱' },
    { name: 'Belgium', code: '', price: 73.30, countryId: 82, flag: '🇧🇪' },
    { name: 'Thailand', code: '', price: 5.49, countryId: 52, flag: '🇹🇭' },
    { name: 'Hungary', code: '', price: 73.30, countryId: 84, flag: '🇭🇺' },
    { name: 'Sweden', code: '', price: 102.70, countryId: 46, flag: '🇸🇪' },
    { name: 'Bangladesh', code: '', price: 75.26, countryId: 60, flag: '🇧🇩' },
    { name: 'Israel', code: '', price: 152.88, countryId: 13, flag: '🇮🇱' },
    { name: 'Madagascar', code: '', price: 2.35, countryId: 17, flag: '🇲🇬' },
    { name: 'Ecuador', code: '', price: 73.30, countryId: 105, flag: '🇪🇨' }
];
const aliexpressCountries = [
    { name: 'Gibraltar', code: '+350', price: 400, countryId: 201, flag: '🇬🇮' }
];
const wechatCountries = [
    { name: 'Tanzania', code: '', price: 176.79, countryId: 9, flag: '🇹🇿' },
    { name: 'Sri Lanka', code: '', price: 143.47, countryId: 64, flag: '🇱🇰' },
    { name: 'Honduras', code: '', price: 473.54, countryId: 88, flag: '🇭🇳' },
    { name: 'Tunisia', code: '', price: 306.54, countryId: 89, flag: '🇹🇳' },
    { name: 'India', code: '', price: 44.69, countryId: 22, flag: '🇮🇳' },
    { name: 'Pakistan', code: '', price: 278.32, countryId: 66, flag: '🇵🇰' },
    { name: 'Zambia', code: '', price: 2.35, countryId: 147, flag: '🇿🇲' },
    { name: 'Namibia', code: '', price: 276.75, countryId: 138, flag: '🇳🇦' },
    { name: 'Papua New Guinea', code: '', price: 145.04, countryId: 79, flag: '🇵🇬' },
    { name: 'Cyprus', code: '', price: 98.78, countryId: 77, flag: '🇨🇾' },
    { name: 'Bulgaria', code: '', price: 180.32, countryId: 83, flag: '🇧🇬' },
    { name: 'Nigeria', code: '', price: 121.52, countryId: 19, flag: '🇳🇬' },
    { name: 'Cameroon', code: '', price: 6.27, countryId: 41, flag: '🇨🇲' },
    { name: 'Malawi', code: '', price: 2.35, countryId: 137, flag: '🇲🇼' },
    { name: 'Laos', code: '', price: 77.62, countryId: 25, flag: '🇱🇦' },
    { name: 'Malaysia', code: '', price: 90.55, countryId: 7, flag: '🇲🇾' },
    { name: 'Turkey', code: '', price: 367.70, countryId: 62, flag: '🇹🇷' },
    { name: 'Kazakhstan', code: '', price: 32.54, countryId: 2, flag: '🇰🇿' },
    { name: 'South Africa', code: '', price: 1.57, countryId: 31, flag: '🇿🇦' },
    { name: 'Germany', code: '', price: 3.14, countryId: 43, flag: '🇩🇪' },
    { name: 'Philippines', code: '', price: 3.14, countryId: 4, flag: '🇵🇭' },
    { name: 'Myanmar', code: '', price: 152.88, countryId: 5, flag: '🇲🇲' },
    { name: 'Yemen', code: '', price: 52.53, countryId: 30, flag: '🇾🇪' },
    { name: 'Netherlands', code: '', price: 5.88, countryId: 48, flag: '🇳🇱' },
    { name: 'Austria', code: '', price: 188.94, countryId: 50, flag: '🇦🇹' },
    { name: 'United Kingdom', code: '', price: 5.49, countryId: 16, flag: '🇬🇧' },
    { name: 'Latvia', code: '', price: 101.53, countryId: 49, flag: '🇱🇻' },
    { name: 'Romania', code: '', price: 36.46, countryId: 32, flag: '🇷🇴' },
    { name: 'Kenya', code: '', price: 2.35, countryId: 8, flag: '🇰🇪' },
    { name: 'Thailand', code: '', price: 26.26, countryId: 52, flag: '🇹🇭' },
    { name: 'Finland', code: '', price: 392.78, countryId: 163, flag: '🇫🇮' },
    { name: 'Peru', code: '', price: 196.78, countryId: 65, flag: '🇵🇪' },
    { name: 'Cambodia', code: '', price: 151.70, countryId: 24, flag: '🇰🇭' },
    { name: 'Australia', code: '', price: 142.30, countryId: 175, flag: '🇦🇺' },
    { name: 'Greece', code: '', price: 60.37, countryId: 129, flag: '🇬🇷' },
    { name: 'Ivory Coast', code: '', price: 87.42, countryId: 27, flag: '🇨🇮' },
    { name: 'Hong Kong', code: '', price: 203.45, countryId: 14, flag: '🇭🇰' },
    { name: 'Ukraine', code: '', price: 18.03, countryId: 1, flag: '🇺🇦' },
    { name: 'Portugal', code: '', price: 41.55, countryId: 117, flag: '🇵🇹' },
    { name: 'Indonesia', code: '', price: 1.57, countryId: 6, flag: '🇮🇩' },
    { name: 'Vietnam', code: '', price: 56.06, countryId: 10, flag: '🇻🇳' },
    { name: 'Argentina', code: '', price: 58.02, countryId: 39, flag: '🇦🇷' },
    { name: 'USA Virtual', code: '', price: 46.65, countryId: 12, flag: '🇺🇸' },
    { name: 'USA', code: '', price: 36.85, countryId: 187, flag: '🇺🇸' },
    { name: 'Italy', code: '', price: 35.67, countryId: 86, flag: '🇮🇹' },
    { name: 'Poland', code: '', price: 3.14, countryId: 15, flag: '🇵🇱' },
    { name: 'France', code: '', price: 35.67, countryId: 78, flag: '🇫🇷' },
    { name: 'Spain', code: '', price: 48.22, countryId: 56, flag: '🇪🇸' },
    { name: 'Brazil', code: '', price: 1.57, countryId: 73, flag: '🇧🇷' },
    { name: 'Colombia', code: '', price: 4.70, countryId: 33, flag: '🇨🇴' },
    { name: 'Canada', code: '', price: 15.68, countryId: 36, flag: '🇨🇦' },
    { name: 'Saudi Arabia', code: '', price: 52.53, countryId: 53, flag: '🇸🇦' },
    { name: 'Chile', code: '', price: 14.90, countryId: 151, flag: '🇨🇱' }
];
const viberCountries = [
    { name: 'Guinea-Bissau', code: '', price: 32.93, countryId: 130, flag: '🇬🇼' },
    { name: 'Portugal', code: '', price: 10.00, countryId: 117, flag: '🇵🇹' },
    { name: 'Somalia', code: '', price: 23.52, countryId: 149, flag: '🇸🇴' },
    { name: 'Barbados', code: '', price: 10.00, countryId: 118, flag: '🇧🇧' },
    { name: 'Zimbabwe', code: '', price: 27.44, countryId: 96, flag: '🇿🇼' },
    { name: 'Nepal', code: '', price: 45.47, countryId: 81, flag: '🇳🇵' },
    { name: 'Nigeria', code: '', price: 29.01, countryId: 19, flag: '🇳🇬' },
    { name: 'Swaziland', code: '', price: 24.30, countryId: 106, flag: '🇸🇿' },
    { name: 'Maldives', code: '', price: 45.47, countryId: 159, flag: '🇲🇻' },
    { name: 'Bangladesh', code: '', price: 25.09, countryId: 60, flag: '🇧🇩' },
    { name: 'Zambia', code: '', price: 26.66, countryId: 147, flag: '🇿🇲' },
    { name: 'Namibia', code: '', price: 21.95, countryId: 138, flag: '🇳🇦' },
    { name: 'Argentina', code: '', price: 10.00, countryId: 39, flag: '🇦🇷' },
    { name: 'India', code: '', price: 25.87, countryId: 22, flag: '🇮🇳' },
    { name: 'Tanzania', code: '', price: 41.55, countryId: 9, flag: '🇹🇿' },
    { name: 'Australia', code: '', price: 10.00, countryId: 175, flag: '🇦🇺' },
    { name: 'Cambodia', code: '', price: 26.26, countryId: 24, flag: '🇰🇭' },
    { name: 'Azerbaijan', code: '', price: 45.47, countryId: 35, flag: '🇦🇿' },
    { name: 'Finland', code: '', price: 45.47, countryId: 163, flag: '🇫🇮' },
    { name: 'Serbia', code: '', price: 45.47, countryId: 29, flag: '🇷🇸' },
    { name: 'Mexico', code: '', price: 45.47, countryId: 54, flag: '🇲🇽' },
    { name: 'Malaysia', code: '', price: 10.00, countryId: 7, flag: '🇲🇾' },
    { name: 'Austria', code: '', price: 45.47, countryId: 50, flag: '🇦🇹' },
    { name: 'Kazakhstan', code: '', price: 10.00, countryId: 2, flag: '🇰🇿' },
    { name: 'USA Virtual', code: '', price: 10.00, countryId: 12, flag: '🇺🇸' },
    { name: 'Estonia', code: '', price: 26.26, countryId: 34, flag: '🇪🇪' },
    { name: 'Turkey', code: '', price: 45.47, countryId: 62, flag: '🇹🇷' },
    { name: 'Uzbekistan', code: '', price: 45.47, countryId: 40, flag: '🇺🇿' },
    { name: 'Canada', code: '', price: 12.15, countryId: 36, flag: '🇨🇦' },
    { name: 'Kenya', code: '', price: 10.00, countryId: 8, flag: '🇰🇪' },
    { name: 'Pakistan', code: '', price: 45.47, countryId: 66, flag: '🇵🇰' },
    { name: 'UAE', code: '', price: 45.47, countryId: 95, flag: '🇦🇪' },
    { name: 'Croatia', code: '', price: 20.38, countryId: 45, flag: '🇭🇷' },
    { name: 'Peru', code: '', price: 39.98, countryId: 65, flag: '🇵🇪' },
    { name: 'Poland', code: '', price: 10.00, countryId: 15, flag: '🇵🇱' },
    { name: 'Saudi Arabia', code: '', price: 32.93, countryId: 53, flag: '🇸🇦' },
    { name: 'Bosnia and Herzegovina', code: '', price: 45.47, countryId: 108, flag: '🇧🇦' },
    { name: 'Bulgaria', code: '', price: 45.47, countryId: 83, flag: '🇧🇬' },
    { name: 'Armenia', code: '', price: 45.47, countryId: 148, flag: '🇦🇲' },
    { name: 'Taiwan', code: '', price: 45.47, countryId: 55, flag: '🇹🇼' },
    { name: 'Hong Kong', code: '', price: 10.00, countryId: 14, flag: '🇭🇰' },
    { name: 'Colombia', code: '', price: 10.00, countryId: 33, flag: '🇨🇴' },
    { name: 'Philippines', code: '', price: 10.00, countryId: 4, flag: '🇵🇭' },
    { name: 'Ethiopia', code: '', price: 30.97, countryId: 71, flag: '🇪🇹' },
    { name: 'South Africa', code: '', price: 10.00, countryId: 31, flag: '🇿🇦' },
    { name: 'Ukraine', code: '', price: 31.36, countryId: 1, flag: '🇺🇦' },
    { name: 'USA', code: '', price: 24.70, countryId: 187, flag: '🇺🇸' },
    { name: 'Italy', code: '', price: 45.47, countryId: 86, flag: '🇮🇹' },
    { name: 'Indonesia', code: '', price: 10.00, countryId: 6, flag: '🇮🇩' },
    { name: 'Algeria', code: '', price: 21.17, countryId: 58, flag: '🇩🇿' },
    { name: 'United Kingdom', code: '', price: 22.74, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '', price: 10.00, countryId: 43, flag: '🇩🇪' },
    { name: 'Vietnam', code: '', price: 18.03, countryId: 10, flag: '🇻🇳' },
    { name: 'Spain', code: '', price: 10.00, countryId: 56, flag: '🇪🇸' },
    { name: 'Myanmar', code: '', price: 18.42, countryId: 5, flag: '🇲🇲' },
    { name: 'Brazil', code: '', price: 10.00, countryId: 73, flag: '🇧🇷' }
];
const uberCountries = [
    { name: 'Afghanistan', code: '', price: 30.58, countryId: 74, flag: '🇦🇫' },
    { name: 'Argentina', code: '', price: 10, countryId: 39, flag: '🇦🇷' },
    { name: 'Aruba', code: '', price: 10, countryId: 179, flag: '🇦🇼' },
    { name: 'Australia', code: '', price: 46.26, countryId: 175, flag: '🇦🇺' },
    { name: 'Azerbaijan', code: '', price: 150.53, countryId: 35, flag: '🇦🇿' },
    { name: 'Bangladesh', code: '', price: 10, countryId: 60, flag: '🇧🇩' },
    { name: 'Botswana', code: '', price: 10, countryId: 123, flag: '🇧🇼' },
    { name: 'Brazil', code: '', price: 10, countryId: 73, flag: '🇧🇷' },
    { name: 'Bulgaria', code: '', price: 35.67, countryId: 83, flag: '🇧🇬' },
    { name: 'Canada', code: '', price: 10, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '', price: 10, countryId: 151, flag: '🇨🇱' },
    { name: 'China', code: '', price: 115.25, countryId: 3, flag: '🇨🇳' },
    { name: 'Colombia', code: '', price: 10, countryId: 33, flag: '🇨🇴' },
    { name: 'Comoros', code: '', price: 10, countryId: 133, flag: '🇰🇲' },
    { name: "Cote d'Ivoire", code: '', price: 10, countryId: 27, flag: '🇨🇮' },
    { name: 'Cyprus', code: '', price: 10, countryId: 77, flag: '🇨🇾' },
    { name: 'Egypt', code: '', price: 41.94, countryId: 21, flag: '🇪🇬' },
    { name: 'Finland', code: '', price: 36.85, countryId: 163, flag: '🇫🇮' },
    { name: 'France', code: '', price: 38.42, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '', price: 10, countryId: 43, flag: '🇩🇪' },
    { name: 'Guadeloupe', code: '', price: 36.85, countryId: 160, flag: '🇬🇵' },
    { name: 'Guinea-Bissau', code: '', price: 36.85, countryId: 130, flag: '🇬🇼' },
    { name: 'Hong Kong', code: '', price: 10, countryId: 14, flag: '🇭🇰' },
    { name: 'Hungary', code: '', price: 218.74, countryId: 84, flag: '🇭🇺' },
    { name: 'India', code: '', price: 36.85, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '', price: 10, countryId: 6, flag: '🇮🇩' },
    { name: 'Israel', code: '', price: 10, countryId: 13, flag: '🇮🇱' },
    { name: 'Italy', code: '', price: 44.69, countryId: 86, flag: '🇮🇹' },
    { name: 'Kazakhstan', code: '', price: 36.85, countryId: 2, flag: '🇰🇿' },
    { name: 'Kenya', code: '', price: 10, countryId: 8, flag: '🇰🇪' },
    { name: 'Kuwait', code: '', price: 30.58, countryId: 100, flag: '🇰🇼' },
    { name: 'Malaysia', code: '', price: 54.88, countryId: 7, flag: '🇲🇾' },
    { name: 'Maldives', code: '', price: 10, countryId: 159, flag: '🇲🇻' },
    { name: 'Mali', code: '', price: 10, countryId: 69, flag: '🇲🇱' },
    { name: 'Mauritania', code: '', price: 10, countryId: 114, flag: '🇲🇷' },
    { name: 'Mexico', code: '', price: 36.85, countryId: 54, flag: '🇲🇽' },
    { name: 'Mongolia', code: '', price: 10, countryId: 72, flag: '🇲🇳' },
    { name: 'Morocco', code: '', price: 10, countryId: 37, flag: '🇲🇦' },
    { name: 'Nepal', code: '', price: 10, countryId: 81, flag: '🇳🇵' },
    { name: 'Netherlands', code: '', price: 10, countryId: 48, flag: '🇳🇱' },
    { name: 'New Zealand', code: '', price: 36.85, countryId: 67, flag: '🇳🇿' },
    { name: 'Nigeria', code: '', price: 36.85, countryId: 19, flag: '🇳🇬' },
    { name: 'Norway', code: '', price: 36.85, countryId: 174, flag: '🇳🇴' },
    { name: 'Pakistan', code: '', price: 59.58, countryId: 66, flag: '🇵🇰' },
    { name: 'Peru', code: '', price: 36.85, countryId: 65, flag: '🇵🇪' },
    { name: 'Philippines', code: '', price: 10, countryId: 4, flag: '🇵🇭' },
    { name: 'Poland', code: '', price: 10, countryId: 15, flag: '🇵🇱' },
    { name: 'Portugal', code: '', price: 10, countryId: 117, flag: '🇵🇹' },
    { name: 'Romania', code: '', price: 10, countryId: 32, flag: '🇷🇴' },
    { name: 'Rwanda', code: '', price: 10, countryId: 140, flag: '🇷🇼' },
    { name: 'Saudi Arabia', code: '', price: 29.01, countryId: 53, flag: '🇸🇦' },
    { name: 'Singapore', code: '', price: 10, countryId: 196, flag: '🇸🇬' },
    { name: 'South Africa', code: '', price: 10, countryId: 31, flag: '🇿🇦' },
    { name: 'South Sudan', code: '', price: 36.85, countryId: 177, flag: '🇸🇸' },
    { name: 'Spain', code: '', price: 41.94, countryId: 56, flag: '🇪🇸' },
    { name: 'Sri Lanka', code: '', price: 10, countryId: 64, flag: '🇱🇰' },
    { name: 'Swaziland', code: '', price: 10, countryId: 106, flag: '🇸🇿' },
    { name: 'Sweden', code: '', price: 10, countryId: 46, flag: '🇸🇪' },
    { name: 'Taiwan', code: '', price: 329.28, countryId: 55, flag: '🇹🇼' },
    { name: 'Tanzania', code: '', price: 10, countryId: 9, flag: '🇹🇿' },
    { name: 'Thailand', code: '', price: 10, countryId: 52, flag: '🇹🇭' },
    { name: 'Timor-Leste', code: '', price: 10, countryId: 91, flag: '🇹🇱' },
    { name: 'Tunisia', code: '', price: 36.85, countryId: 89, flag: '🇹🇳' },
    { name: 'Turkey', code: '', price: 59.58, countryId: 62, flag: '🇹🇷' },
    { name: 'Turkmenistan', code: '', price: 10, countryId: 161, flag: '🇹🇲' },
    { name: 'UAE', code: '', price: 38.81, countryId: 95, flag: '🇦🇪' },
    { name: 'United Kingdom', code: '', price: 10, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '', price: 28.22, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '', price: 10, countryId: 12, flag: '🇺🇸' },
    { name: 'Uzbekistan', code: '', price: 10, countryId: 40, flag: '🇺🇿' },
    { name: 'Venezuela', code: '', price: 36.85, countryId: 70, flag: '🇻🇪' },
    { name: 'Vietnam', code: '', price: 24.30, countryId: 10, flag: '🇻🇳' },
    { name: 'Zimbabwe', code: '', price: 10, countryId: 96, flag: '🇿🇼' }
];
const microsoftCountries = [
    { name: 'Brazil', code: '+55', price: 9, countryId: 73, flag: '🇧🇷' },
    { name: 'USA Virtual', code: '+1', price: 10, countryId: 12, flag: '🇺🇸' },
    { name: 'Chile', code: '+56', price: 20, countryId: 151, flag: '🇨🇱' },
    { name: 'USA', code: '+1', price: 50, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 30, countryId: 16, flag: '🇬🇧' },
    { name: 'Colombia', code: '+57', price: 40, countryId: 33, flag: '🇨🇴' },
    { name: 'Netherlands', code: '+31', price: 30, countryId: 48, flag: '🇳🇱' },
    { name: 'Finland', code: '+358', price: 80, countryId: 163, flag: '🇫🇮' },
    { name: 'Poland', code: '+48', price: 40, countryId: 15, flag: '🇵🇱' },
    { name: 'Switzerland', code: '+41', price: 30, countryId: 173, flag: '🇨🇭' },
    { name: 'Portugal', code: '+351', price: 10, countryId: 117, flag: '🇵🇹' },
    { name: 'Hong Kong', code: '+852', price: 26, countryId: 14, flag: '🇭🇰' },
    { name: 'Canada', code: '+1', price: 29, countryId: 36, flag: '🇨🇦' },
    { name: 'Malaysia', code: '+60', price: 40, countryId: 7, flag: '🇲🇾' },
    { name: 'Spain', code: '+34', price: 50, countryId: 56, flag: '🇪🇸' },
    { name: 'UAE', code: '+971', price: 70, countryId: 95, flag: '🇦🇪' }
];
const signalCountries = [
    { name: 'USA', code: '+1', price: 40, countryId: 187, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 10, countryId: 36, flag: '🇨🇦' },
    { name: 'United Kingdom', code: '+44', price: 18, countryId: 16, flag: '🇬🇧' },
    { name: 'Poland', code: '+48', price: 80, countryId: 15, flag: '🇵🇱' },
    { name: 'Germany', code: '+49', price: 70, countryId: 43, flag: '🇩🇪' },
    { name: 'Colombia', code: '+57', price: 13, countryId: 33, flag: '🇨🇴' },
    { name: 'Romania', code: '+40', price: 20, countryId: 32, flag: '🇷🇴' },
    { name: 'Brazil', code: '+55', price: 4, countryId: 73, flag: '🇧🇷' },
    { name: 'Netherlands', code: '+31', price: 100, countryId: 48, flag: '🇳🇱' },
    { name: 'Portugal', code: '+351', price: 19, countryId: 117, flag: '🇵🇹' },
    { name: 'Czech Republic', code: '+420', price: 19, countryId: 63, flag: '🇨🇿' },
    { name: 'Malaysia', code: '+60', price: 39, countryId: 7, flag: '🇲🇾' },
    { name: 'Chile', code: '+56', price: 20, countryId: 151, flag: '🇨🇱' },
    { name: 'Spain', code: '+34', price: 40, countryId: 56, flag: '🇪🇸' },
    { name: 'Thailand', code: '+66', price: 90, countryId: 52, flag: '🇹🇭' },
    { name: 'France', code: '+33', price: 15, countryId: 78, flag: '🇫🇷' },
    { name: 'Sweden', code: '+46', price: 18, countryId: 46, flag: '🇸🇪' },
    { name: 'Argentina', code: '+54', price: 20, countryId: 39, flag: '🇦🇷' },
    { name: 'Maldives', code: '+960', price: 25, countryId: 159, flag: '🇲🇻' },
    { name: 'Vietnam', code: '+84', price: 60, countryId: 10, flag: '🇻🇳' },
    { name: 'Georgia', code: '+995', price: 20, countryId: 128, flag: '🇬🇪' },
    { name: 'Philippines', code: '+63', price: 9, countryId: 4, flag: '🇵🇭' },
    { name: 'India', code: '+91', price: 20, countryId: 22, flag: '🇮🇳' },
    { name: 'Kazakhstan', code: '+7', price: 23, countryId: 2, flag: '🇰🇿' },
    { name: 'Lithuania', code: '+370', price: 600, countryId: 44, flag: '🇱🇹' },
    { name: 'South Africa', code: '+27', price: 8, countryId: 31, flag: '🇿🇦' },
    { name: 'Indonesia', code: '+62', price: 8, countryId: 6, flag: '🇮🇩' },
    { name: 'Bulgaria', code: '+359', price: 30, countryId: 83, flag: '🇧🇬' },
    { name: 'Estonia', code: '+372', price: 20, countryId: 34, flag: '🇪🇪' },
    { name: 'Ukraine', code: '+380', price: 20, countryId: 1, flag: '🇺🇦' },
    { name: 'Myanmar', code: '+95', price: 30, countryId: 5, flag: '🇲🇲' },
    { name: 'Kenya', code: '+254', price: 20, countryId: 8, flag: '🇰🇪' },
    { name: 'Kyrgyzstan', code: '+996', price: 20, countryId: 11, flag: '🇰🇬' },
    { name: 'Moldova', code: '+373', price: 120, countryId: 85, flag: '🇲🇩' },
    { name: 'Laos', code: '+856', price: 20, countryId: 25, flag: '🇱🇦' },
    { name: 'Latvia', code: '+371', price: 24, countryId: 49, flag: '🇱🇻' },
    { name: 'Tajikistan', code: '+992', price: 220, countryId: 143, flag: '🇹🇯' },
    { name: 'Kosovo', code: '+383', price: 10, countryId: 1004, flag: '🇽🇰' }
];
const easypayCountries = [
    { name: 'Ukraine', code: '+380', price: 10, countryId: 1, flag: '🇺🇦' },
    { name: 'USA', code: '+1', price: 87, countryId: 187, flag: '🇺🇸' }
];

const mercadoCountries = [
    { name: 'Argentina', code: '+54', price: 15.65, countryId: 39, flag: '🇦🇷' },
    { name: 'Bolivia', code: '+591', price: 69.52, countryId: 92, flag: '🇧🇴' },
    { name: 'Brazil', code: '+55', price: 2.55, countryId: 73, flag: '🇧🇷' },
    { name: 'Chile', code: '+56', price: 4.33, countryId: 151, flag: '🇨🇱' },
    { name: 'Colombia', code: '+57', price: 2, countryId: 33, flag: '🇨🇴' },
    { name: 'Cuba', code: '+53', price: 69.52, countryId: 113, flag: '🇨🇺' },
    { name: 'Guatemala', code: '+502', price: 89.91, countryId: 94, flag: '🇬🇹' },
    { name: 'Mexico', code: '+52', price: 70.98, countryId: 54, flag: '🇲🇽' },
    { name: 'Paraguay', code: '+595', price: 69.52, countryId: 87, flag: '🇵🇾' },
    { name: 'Peru', code: '+51', price: 72.44, countryId: 65, flag: '🇵🇪' },
    { name: 'Uruguay', code: '+598', price: 120.12, countryId: 156, flag: '🇺🇾' },
    { name: 'USA', code: '+1', price: 10.92, countryId: 187, flag: '🇺🇸' }
];

const uklonCountries = [
    { name: 'Ukraine', code: '+380', price: 11.28, countryId: 1, flag: '🇺🇦' },
    { name: 'USA', code: '+1', price: 72.8, countryId: 187, flag: '🇺🇸' }
];

const rediffmailCountries = [
    { name: 'India', code: '+91', price: 9.83, countryId: 22, flag: '🇮🇳' }
];

const promCountries = [];

const uwinCountries = [
    { name: 'Malaysia', code: '+60', price: 48.78, countryId: 7, flag: '🇲🇾' }
];

const berealCountries = [];

const dotzCountries = [];

const redbusCountries = [
    { name: 'India', code: '+91', price: 17.65, countryId: 22, flag: '🇮🇳' }
];

const pocket52Countries = [];

const gemgalaCountries = [];

const irancellCountries = [];

const bazosCountries = [
    { name: 'France', code: '+33', price: 50.6, countryId: 78, flag: '🇫🇷' },
    { name: 'Czech Republic', code: '+420', price: 155.06, countryId: 63, flag: '🇨🇿' },
    { name: 'Japan', code: '+81', price: 1073.07, countryId: 1001, flag: '🇯🇵' },
    { name: 'Gibraltar', code: '+350', price: 527.44, countryId: 201, flag: '🇬🇮' }
];

const supersCountries = [
    { name: 'Italy', code: '+39', price: 47.68, countryId: 86, flag: '🇮🇹' }
];

const dosiCountries = [
    { name: 'France', code: '+33', price: 33.85, countryId: 78, flag: '🇫🇷' },
    { name: 'Vietnam', code: '+84', price: 26.21, countryId: 10, flag: '🇻🇳' },
    { name: 'Thailand', code: '+66', price: 57.51, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 16.74, countryId: 48, flag: '🇳🇱' },
    { name: 'Malaysia', code: '+60', price: 48.78, countryId: 7, flag: '🇲🇾' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Philippines', code: '+63', price: 25.48, countryId: 4, flag: '🇵🇭' }
];

const monobankindiaCountries = [];

const alfaCountries = [
    { name: 'Pakistan', code: '+92', price: 78.62, countryId: 66, flag: '🇵🇰' },
    { name: 'Gibraltar', code: '+350', price: 407.32, countryId: 201, flag: '🇬🇮' }
];

const tradeupCountries = [];

const adaniCountries = [
    { name: 'India', code: '+91', price: 11.65, countryId: 22, flag: '🇮🇳' }
];

const marketguruCountries = [];

const g2gCountries = [
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'USA', code: '+1', price: 26.21, countryId: 187, flag: '🇺🇸' },
    { name: 'Philippines', code: '+63', price: 25.84, countryId: 4, flag: '🇵🇭' },
    { name: 'India', code: '+91', price: 2.91, countryId: 22, flag: '🇮🇳' },
    { name: 'Ecuador', code: '+593', price: 82.26, countryId: 105, flag: '🇪🇨' },
    { name: 'Turkey', code: '+90', price: 2.91, countryId: 62, flag: '🇹🇷' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' }
];

const ys4funCountries = [
    { name: 'Malaysia', code: '+60', price: 212.58, countryId: 7, flag: '🇲🇾' },
    { name: 'Hong Kong', code: '+852', price: 104.83, countryId: 14, flag: '🇭🇰' },
    { name: 'USA Virtual', code: '+1', price: 4, countryId: 12, flag: '🇺🇸' }
];

const mixmartCountries = [];

const gcashCountries = [];

const lazypayCountries = [];

const citybaseCountries = [];

const rutenCountries = [
    { name: 'Taiwan', code: '+886', price: 131.77, countryId: 55, flag: '🇹🇼' }
];

const crefisamaisCountries = [];

const harajCountries = [];

const perfluenceCountries = [];

const wondermartCountries = [
    { name: 'India', code: '+91', price: 11.65, countryId: 22, flag: '🇮🇳' }
];

const glovoCountries = [
    { name: 'Greece', code: '+30', price: 8.74, countryId: 129, flag: '🇬🇷' },
    { name: 'Estonia', code: '+372', price: 30.58, countryId: 34, flag: '🇪🇪' },
    { name: 'Georgia', code: '+995', price: 11.28, countryId: 128, flag: '🇬🇪' },
    { name: 'Moldova', code: '+373', price: 13.83, countryId: 85, flag: '🇲🇩' },
    { name: 'Ukraine', code: '+380', price: 11.28, countryId: 1, flag: '🇺🇦' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Gibraltar', code: '+350', price: 439.71, countryId: 201, flag: '🇬🇮' }
];

const uu163Countries = [
    { name: 'Indonesia', code: '+62', price: 8.37, countryId: 6, flag: '🇮🇩' },
    { name: 'Hong Kong', code: '+852', price: 65.88, countryId: 14, flag: '🇭🇰' }
];

const galaxywinCountries = [
    { name: 'USA', code: '+1', price: 68.07, countryId: 187, flag: '🇺🇸' }
];

const itiCountries = [];

const proboCountries = [
    { name: 'India', code: '+91', price: 29.85, countryId: 22, flag: '🇮🇳' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Chile', code: '+56', price: 1.46, countryId: 151, flag: '🇨🇱' }
];

const alfagiftCountries = [
    { name: 'Indonesia', code: '+62', price: 2.18, countryId: 6, flag: '🇮🇩' }
];

const ininalCountries = [];

const quippCountries = [
    { name: 'Denmark', code: '+45', price: 164.16, countryId: 172, flag: '🇩🇰' },
    { name: 'Austria', code: '+43', price: 275.91, countryId: 50, flag: '🇦🇹' },
    { name: 'Gibraltar', code: '+350', price: 847.76, countryId: 201, flag: '🇬🇮' }
];

const twilioCountries = [
    { name: 'United Kingdom', code: '+44', price: 3.64, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 42.95, countryId: 7, flag: '🇲🇾' },
    { name: 'Gibraltar', code: '+350', price: 353.08, countryId: 201, flag: '🇬🇮' }
];

const hqtriviaCountries = [
    { name: 'Kyrgyzstan', code: '+996', price: 34.22, countryId: 11, flag: '🇰🇬' },
    { name: 'Azerbaijan', code: '+994', price: 34.22, countryId: 35, flag: '🇦🇿' },
    { name: 'USA', code: '+1', price: 43.32, countryId: 187, flag: '🇺🇸' },
    { name: 'Afghanistan', code: '+93', price: 34.22, countryId: 74, flag: '🇦🇫' },
    { name: 'Serbia', code: '+381', price: 34.22, countryId: 29, flag: '🇷🇸' },
    { name: 'Latvia', code: '+371', price: 34.22, countryId: 49, flag: '🇱🇻' },
    { name: 'Denmark', code: '+45', price: 34.22, countryId: 172, flag: '🇩🇰' },
    { name: 'Austria', code: '+43', price: 34.22, countryId: 50, flag: '🇦🇹' },
    { name: 'Cambodia', code: '+855', price: 36.4, countryId: 24, flag: '🇰🇭' },
    { name: 'Philippines', code: '+63', price: 34.22, countryId: 4, flag: '🇵🇭' },
    { name: 'Spain', code: '+34', price: 34.22, countryId: 56, flag: '🇪🇸' },
    { name: 'India', code: '+91', price: 34.22, countryId: 22, flag: '🇮🇳' },
    { name: 'Myanmar', code: '+95', price: 34.22, countryId: 5, flag: '🇲🇲' },
    { name: 'Morocco', code: '+212', price: 34.22, countryId: 37, flag: '🇲🇦' },
    { name: 'Kazakhstan', code: '+7', price: 34.22, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 34.22, countryId: 33, flag: '🇨🇴' },
    { name: 'Tajikistan', code: '+992', price: 50.96, countryId: 143, flag: '🇹🇯' },
    { name: 'Liberia', code: '+231', price: 50.96, countryId: 135, flag: '🇱🇷' },
    { name: 'Slovakia', code: '+421', price: 59.7, countryId: 141, flag: '🇸🇰' },
    { name: 'Croatia', code: '+385', price: 20.02, countryId: 45, flag: '🇭🇷' },
    { name: 'Monaco', code: '+377', price: 138.32, countryId: 144, flag: '🇲🇨' },
    { name: 'New Zealand', code: '+64', price: 45.86, countryId: 67, flag: '🇳🇿' },
    { name: 'Iceland', code: '+354', price: 83.72, countryId: 132, flag: '🇮🇸' },
    { name: 'Gibraltar', code: '+350', price: 421.88, countryId: 201, flag: '🇬🇮' },
    { name: 'Cameroon', code: '+237', price: 40.04, countryId: 41, flag: '🇨🇲' },
    { name: 'Ivory Coast', code: '+225', price: 171.08, countryId: 27, flag: '🇨🇮' },
    { name: 'Jordan', code: '+962', price: 64.79, countryId: 116, flag: '🇯🇴' },
    { name: 'Malawi', code: '+265', price: 60.42, countryId: 137, flag: '🇲🇼' },
    { name: 'Luxembourg', code: '+352', price: 64.79, countryId: 165, flag: '🇱🇺' },
    { name: 'El Salvador', code: '+503', price: 64.79, countryId: 101, flag: '🇸🇻' },
    { name: 'Uganda', code: '+256', price: 16.74, countryId: 75, flag: '🇺🇬' },
    { name: 'Botswana', code: '+267', price: 64.79, countryId: 123, flag: '🇧🇼' },
    { name: 'Ecuador', code: '+593', price: 64.79, countryId: 105, flag: '🇪🇨' },
    { name: 'Uzbekistan', code: '+998', price: 91.73, countryId: 40, flag: '🇺🇿' },
    { name: 'Peru', code: '+51', price: 69.52, countryId: 65, flag: '🇵🇪' },
    { name: 'Czech Republic', code: '+420', price: 6.92, countryId: 63, flag: '🇨🇿' },
    { name: 'Ukraine', code: '+380', price: 8.74, countryId: 1, flag: '🇺🇦' },
    { name: 'Benin', code: '+229', price: 64.79, countryId: 120, flag: '🇧🇯' },
    { name: 'Burkina Faso', code: '+226', price: 46.23, countryId: 152, flag: '🇧🇫' },
    { name: 'Oman', code: '+968', price: 64.79, countryId: 107, flag: '🇴🇲' },
    { name: 'Burundi', code: '+257', price: 61.15, countryId: 119, flag: '🇧🇮' },
    { name: 'Bosnia and Herzegovina', code: '+387', price: 83.72, countryId: 108, flag: '🇧🇦' },
    { name: 'Barbados', code: '+1', price: 56.78, countryId: 118, flag: '🇧🇧' },
    { name: 'Gambia', code: '+220', price: 50.23, countryId: 28, flag: '🇬🇲' },
    { name: 'Armenia', code: '+374', price: 55.33, countryId: 148, flag: '🇦🇲' },
    { name: 'Cuba', code: '+53', price: 64.79, countryId: 113, flag: '🇨🇺' },
    { name: 'Chile', code: '+56', price: 1.46, countryId: 151, flag: '🇨🇱' },
    { name: 'Sierra Leone', code: '+232', price: 46.23, countryId: 115, flag: '🇸🇱' }
];

const lykaCountries = [];

const doordashCountries = [
    { name: 'USA', code: '+1', price: 48.78, countryId: 187, flag: '🇺🇸' },
    { name: 'Japan', code: '+81', price: 1877.51, countryId: 1001, flag: '🇯🇵' },
    { name: 'New Zealand', code: '+64', price: 2011.46, countryId: 67, flag: '🇳🇿' },
    { name: 'Australia', code: '', price: 230.05, countryId: 175, flag: '🇦🇺' },
    { name: 'Gibraltar', code: '+350', price: 237.33, countryId: 201, flag: '🇬🇮' }
];

const celebeCountries = [
    { name: 'USA Virtual', code: '+1', price: 14, countryId: 12, flag: '🇺🇸' },
    { name: 'USA', code: '+1', price: 78.26, countryId: 187, flag: '🇺🇸' }
];

const taikangCountries = [];

const ninetynineappCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const hopiCountries = [
    { name: 'Kyrgyzstan', code: '+996', price: 34.22, countryId: 11, flag: '🇰🇬' },
    { name: 'Azerbaijan', code: '+994', price: 34.22, countryId: 35, flag: '🇦🇿' },
    { name: 'USA', code: '+1', price: 43.32, countryId: 187, flag: '🇺🇸' },
    { name: 'Afghanistan', code: '+93', price: 34.22, countryId: 74, flag: '🇦🇫' },
    { name: 'Serbia', code: '+381', price: 34.22, countryId: 29, flag: '🇷🇸' },
    { name: 'Latvia', code: '+371', price: 34.22, countryId: 49, flag: '🇱🇻' },
    { name: 'Denmark', code: '+45', price: 34.22, countryId: 172, flag: '🇩🇰' },
    { name: 'Austria', code: '+43', price: 34.22, countryId: 50, flag: '🇦🇹' },
    { name: 'Cambodia', code: '+855', price: 1.46, countryId: 24, flag: '🇰🇭' },
    { name: 'Philippines', code: '+63', price: 34.22, countryId: 4, flag: '🇵🇭' },
    { name: 'Spain', code: '+34', price: 34.22, countryId: 56, flag: '🇪🇸' },
    { name: 'India', code: '+91', price: 34.22, countryId: 22, flag: '🇮🇳' },
    { name: 'Myanmar', code: '+95', price: 34.22, countryId: 5, flag: '🇲🇲' },
    { name: 'Morocco', code: '+212', price: 34.22, countryId: 37, flag: '🇲🇦' },
    { name: 'Kazakhstan', code: '+7', price: 34.22, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 34.22, countryId: 33, flag: '🇨🇴' }
];

const mocospaceCountries = [
    { name: 'USA', code: '+1', price: 56.78, countryId: 187, flag: '🇺🇸' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Kazakhstan', code: '+7', price: 22.93, countryId: 2, flag: '🇰🇿' },
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const iqiyiCountries = [];

const zomatoCountries = [
    { name: 'India', code: '+91', price: 76.44, countryId: 22, flag: '🇮🇳' },
    { name: 'Gibraltar', code: '+350', price: 353.08, countryId: 201, flag: '🇬🇮' }
];

const trendyolCountries = [
    { name: 'Turkey', code: '+90', price: 35.67, countryId: 62, flag: '🇹🇷' },
    { name: 'Germany', code: '+49', price: 47.68, countryId: 43, flag: '🇩🇪' },
    { name: 'Tunisia', code: '+216', price: 35.67, countryId: 89, flag: '🇹🇳' },
    { name: 'Azerbaijan', code: '+994', price: 69.52, countryId: 35, flag: '🇦🇿' },
    { name: 'Gibraltar', code: '+350', price: 407.32, countryId: 201, flag: '🇬🇮' }
];

const ticketmasterCountries = [
    { name: 'USA', code: '+1', price: 42.22, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 37.86, countryId: 16, flag: '🇬🇧' },
    { name: 'Canada', code: '+1', price: 9.83, countryId: 36, flag: '🇨🇦' },
    { name: 'Netherlands', code: '+31', price: 19.66, countryId: 48, flag: '🇳🇱' },
    { name: 'Chile', code: '+56', price: 18.56, countryId: 151, flag: '🇨🇱' },
    { name: 'Portugal', code: '+351', price: 19.66, countryId: 117, flag: '🇵🇹' },
    { name: 'Greece', code: '+30', price: 19.66, countryId: 129, flag: '🇬🇷' },
    { name: 'Poland', code: '+48', price: 8.37, countryId: 15, flag: '🇵🇱' },
    { name: 'USA Virtual', code: '+1', price: 3.64, countryId: 12, flag: '🇺🇸' },
    { name: 'Austria', code: '+43', price: 19.66, countryId: 50, flag: '🇦🇹' },
    { name: 'Germany', code: '+49', price: 26.21, countryId: 43, flag: '🇩🇪' },
    { name: 'Sweden', code: '+46', price: 5.82, countryId: 46, flag: '🇸🇪' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Spain', code: '+34', price: 29.12, countryId: 56, flag: '🇪🇸' },
    { name: 'Denmark', code: '+45', price: 19.66, countryId: 172, flag: '🇩🇰' },
    { name: 'Italy', code: '+39', price: 19.66, countryId: 86, flag: '🇮🇹' },
    { name: 'Finland', code: '+358', price: 19.66, countryId: 163, flag: '🇫🇮' },
    { name: 'Romania', code: '+40', price: 19.66, countryId: 32, flag: '🇷🇴' },
    { name: 'Malaysia', code: '+60', price: 19.66, countryId: 7, flag: '🇲🇾' },
    { name: 'France', code: '+33', price: 19.66, countryId: 78, flag: '🇫🇷' },
    { name: 'Kenya', code: '+254', price: 19.66, countryId: 8, flag: '🇰🇪' },
    { name: 'Kazakhstan', code: '+7', price: 18.56, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 10.19, countryId: 33, flag: '🇨🇴' },
    { name: 'Belarus', code: '+375', price: 19.66, countryId: 51, flag: '🇧🇾' },
    { name: 'Bulgaria', code: '+359', price: 19.66, countryId: 83, flag: '🇧🇬' },
    { name: 'Azerbaijan', code: '+994', price: 19.66, countryId: 35, flag: '🇦🇿' },
    { name: 'Moldova', code: '+373', price: 18.2, countryId: 85, flag: '🇲🇩' },
    { name: 'Thailand', code: '+66', price: 19.66, countryId: 52, flag: '🇹🇭' },
    { name: 'China', code: '+86', price: 64.43, countryId: 3, flag: '🇨🇳' },
    { name: 'Armenia', code: '+374', price: 19.66, countryId: 148, flag: '🇦🇲' },
    { name: 'Ireland', code: '+353', price: 19.66, countryId: 23, flag: '🇮🇪' },
    { name: 'Serbia', code: '+381', price: 19.66, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 19.66, countryId: 34, flag: '🇪🇪' },
    { name: 'Czech Republic', code: '+420', price: 23.3, countryId: 63, flag: '🇨🇿' },
    { name: 'Georgia', code: '+995', price: 28.39, countryId: 128, flag: '🇬🇪' },
    { name: 'Latvia', code: '+371', price: 19.66, countryId: 49, flag: '🇱🇻' },
    { name: 'Slovenia', code: '+386', price: 19.66, countryId: 59, flag: '🇸🇮' },
    { name: 'Lithuania', code: '+370', price: 19.66, countryId: 44, flag: '🇱🇹' },
    { name: 'Japan', code: '+81', price: 747.93, countryId: 1001, flag: '🇯🇵' },
    { name: 'Croatia', code: '+385', price: 37.49, countryId: 45, flag: '🇭🇷' },
    { name: 'New Zealand', code: '+64', price: 19.66, countryId: 67, flag: '🇳🇿' },
    { name: 'Australia', code: '', price: 206.39, countryId: 175, flag: '🇦🇺' },
    { name: 'Gibraltar', code: '+350', price: 19.66, countryId: 201, flag: '🇬🇮' }
];

const qoo10Countries = [];

const fullrentCountries = [];

const dewupoisonCountries = [];

const onexbetCountries = [
    { name: 'Kosovo', code: '+383', price: 17, countryId: 1004, flag: '🇽🇰' }
];

const my11circleCountries = [];

const ximalayaCountries = [];

const airtelCountries = [
    { name: 'India', code: '+91', price: 26.21, countryId: 22, flag: '🇮🇳' }
];

const huyaCountries = [
    { name: 'Uzbekistan', code: '+998', price: 21.18, countryId: 40, flag: '🇺🇿' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'USA Virtual', code: '+1', price: 13.64, countryId: 12, flag: '🇺🇸' }
];

const douyuCountries = [
    { name: 'Malaysia', code: '+60', price: 121.58, countryId: 7, flag: '🇲🇾' },
    { name: 'USA', code: '+1', price: 82.26, countryId: 187, flag: '🇺🇸' }
];

const olacabsCountries = [
    { name: 'India', code: '+91', price: 30.58, countryId: 22, flag: '🇮🇳' },
    { name: 'Mauritius', code: '+230', price: 24.39, countryId: 157, flag: '🇲🇺' },
    { name: 'Gabon', code: '+241', price: 24.39, countryId: 154, flag: '🇬🇦' },
    { name: 'Reunion', code: '+262', price: 91.73, countryId: 146, flag: '🇷🇪' },
    { name: 'Uruguay', code: '+598', price: 24.39, countryId: 156, flag: '🇺🇾' },
    { name: 'Equatorial Guinea', code: '+240', price: 24.39, countryId: 167, flag: '🇬🇶' },
    { name: 'Maldives', code: '+960', price: 24.39, countryId: 159, flag: '🇲🇻' },
    { name: 'Barbados', code: '+1', price: 87.36, countryId: 118, flag: '🇧🇧' },
    { name: 'Suriname', code: '+597', price: 24.39, countryId: 142, flag: '🇸🇷' },
    { name: 'Djibouti', code: '+253', price: 87.36, countryId: 168, flag: '🇩🇯' },
    { name: 'Canada', code: '+1', price: 7.28, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '+56', price: 24.39, countryId: 151, flag: '🇨🇱' },
    { name: 'Sierra Leone', code: '+232', price: 24.39, countryId: 115, flag: '🇸🇱' },
    { name: 'Grenada', code: '+1', price: 87.36, countryId: 127, flag: '🇬🇩' },
    { name: 'Brunei Darussalam', code: '+673', price: 87.36, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 87.36, countryId: 170, flag: '🇰🇾' },
    { name: 'Liberia', code: '+231', price: 24.39, countryId: 135, flag: '🇱🇷' },
    { name: 'Comoros', code: '+269', price: 87.36, countryId: 133, flag: '🇰🇲' },
    { name: 'Slovakia', code: '+421', price: 24.39, countryId: 141, flag: '🇸🇰' },
    { name: 'Monaco', code: '+377', price: 24.39, countryId: 144, flag: '🇲🇨' },
    { name: 'Belize', code: '+501', price: 24.39, countryId: 124, flag: '🇧🇿' },
    { name: 'New Zealand', code: '+64', price: 24.39, countryId: 67, flag: '🇳🇿' },
    { name: 'Lebanon', code: '+961', price: 24.39, countryId: 153, flag: '🇱🇧' },
    { name: 'Iceland', code: '+354', price: 24.39, countryId: 132, flag: '🇮🇸' },
    { name: 'Gibraltar', code: '+350', price: 340.34, countryId: 201, flag: '🇬🇮' }
];

const dominospizzaCountries = [
    { name: 'Albania', code: '+355', price: 89.91, countryId: 155, flag: '🇦🇱' },
    { name: 'Azerbaijan', code: '+994', price: 48.78, countryId: 35, flag: '🇦🇿' },
    { name: 'Belize', code: '+501', price: 69.52, countryId: 124, flag: '🇧🇿' },
    { name: 'Brunei Darussalam', code: '+673', price: 65.88, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 65.88, countryId: 170, flag: '🇰🇾' },
    { name: 'Chile', code: '+56', price: 1.46, countryId: 151, flag: '🇨🇱' },
    { name: 'Comoros', code: '+269', price: 65.88, countryId: 133, flag: '🇰🇲' },
    { name: 'Djibouti', code: '+253', price: 65.88, countryId: 168, flag: '🇩🇯' },
    { name: 'Equatorial Guinea', code: '+240', price: 65.88, countryId: 167, flag: '🇬🇶' },
    { name: 'Gabon', code: '+241', price: 69.52, countryId: 154, flag: '🇬🇦' },
    { name: 'Gibraltar', code: '+350', price: 255.53, countryId: 201, flag: '🇬🇮' },
    { name: 'India', code: '+91', price: 13.1, countryId: 22, flag: '🇮🇳' },
    { name: 'Lebanon', code: '+961', price: 69.52, countryId: 153, flag: '🇱🇧' },
    { name: 'Liberia', code: '+231', price: 69.52, countryId: 135, flag: '🇱🇷' },
    { name: 'Maldives', code: '+960', price: 65.88, countryId: 159, flag: '🇲🇻' },
    { name: 'Monaco', code: '+377', price: 148.15, countryId: 144, flag: '🇲🇨' },
    { name: 'Puerto Rico', code: '+1', price: 46.23, countryId: 97, flag: '🇵🇷' },
    { name: 'Saint Lucia', code: '+1', price: 65.88, countryId: 164, flag: '🇱🇨' },
    { name: 'Slovakia', code: '+421', price: 89.91, countryId: 141, flag: '🇸🇰' },
    { name: 'Suriname', code: '+597', price: 69.52, countryId: 142, flag: '🇸🇷' },
    { name: 'Togo', code: '+228', price: 46.23, countryId: 99, flag: '🇹🇬' },
    { name: 'Uruguay', code: '+598', price: 114.3, countryId: 156, flag: '🇺🇾' }
];

const winzogameCountries = [
    { name: 'India', code: '+91', price: 19.66, countryId: 22, flag: '🇮🇳' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Gibraltar', code: '+350', price: 195.05, countryId: 201, flag: '🇬🇮' }
];

const tenchatCountries = [];

const switipsCountries = [];

const youstarCountries = [];

const ifoodCountries = [
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Mexico', code: '+52', price: 42.22, countryId: 54, flag: '🇲🇽' },
    { name: 'Colombia', code: '+57', price: 29.12, countryId: 33, flag: '🇨🇴' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Japan', code: '+81', price: 1877.51, countryId: 1001, flag: '🇯🇵' },
    { name: 'Gibraltar', code: '+350', price: 29.12, countryId: 201, flag: '🇬🇮' }
];

const deliveryclubCountries = [];

const courseheroCountries = [];

const tripCountries = [
    { name: 'Netherlands', code: '+31', price: 16.74, countryId: 48, flag: '🇳🇱' },
    { name: 'Gibraltar', code: '+350', price: 427.34, countryId: 201, flag: '🇬🇮' }
];

const megaCountries = [];

const nimotvCountries = [
    { name: 'Turkey', code: '+90', price: 39.31, countryId: 62, flag: '🇹🇷' },
    { name: 'Kyrgyzstan', code: '+996', price: 5.1, countryId: 11, flag: '🇰🇬' }
];

const caixaCountries = [
    { name: 'Germany', code: '+49', price: 24.02, countryId: 43, flag: '🇩🇪' },
    { name: 'Malaysia', code: '+60', price: 24.39, countryId: 7, flag: '🇲🇾' },
    { name: 'Gibraltar', code: '+350', price: 407.32, countryId: 201, flag: '🇬🇮' },
    { name: 'Ukraine', code: '+380', price: 82.63, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' }
];

const astropayCountries = [
    { name: 'Colombia', code: '+57', price: 75.35, countryId: 33, flag: '🇨🇴' },
    { name: 'Germany', code: '+49', price: 26.21, countryId: 43, flag: '🇩🇪' },
    { name: 'Chile', code: '+56', price: 40.04, countryId: 151, flag: '🇨🇱' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Venezuela', code: '+58', price: 65.88, countryId: 70, flag: '🇻🇪' },
    { name: 'Kazakhstan', code: '+7', price: 52.42, countryId: 2, flag: '🇰🇿' },
    { name: 'Ukraine', code: '+380', price: 83.72, countryId: 1, flag: '🇺🇦' },
    { name: 'Peru', code: '+51', price: 65.88, countryId: 65, flag: '🇵🇪' },
    { name: 'United Kingdom', code: '+44', price: 14.2, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 14.56, countryId: 48, flag: '🇳🇱' },
    { name: 'Malaysia', code: '+60', price: 18.56, countryId: 7, flag: '🇲🇾' },
    { name: 'Brazil', code: '+55', price: 5.1, countryId: 73, flag: '🇧🇷' }
];

const happnCountries = [
    { name: 'Armenia', code: '+374', price: 16.74, countryId: 148, flag: '🇦🇲' },
    { name: 'Barbados', code: '+1', price: 71.34, countryId: 118, flag: '🇧🇧' },
    { name: 'Belize', code: '+501', price: 71.34, countryId: 124, flag: '🇧🇿' },
    { name: 'Bolivia', code: '+591', price: 71.34, countryId: 92, flag: '🇧🇴' },
    { name: 'Brunei Darussalam', code: '+673', price: 61.52, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 61.52, countryId: 170, flag: '🇰🇾' },
    { name: 'Chile', code: '+56', price: 30.21, countryId: 151, flag: '🇨🇱' },
    { name: 'Comoros', code: '+269', price: 71.34, countryId: 133, flag: '🇰🇲' },
    { name: 'Costa Rica', code: '+506', price: 71.34, countryId: 93, flag: '🇨🇷' },
    { name: 'Djibouti', code: '+253', price: 6.92, countryId: 168, flag: '🇩🇯' },
    { name: 'Equatorial Guinea', code: '+240', price: 71.34, countryId: 167, flag: '🇬🇶' },
    { name: 'Estonia', code: '+372', price: 48.78, countryId: 34, flag: '🇪🇪' },
    { name: 'Finland', code: '+358', price: 65.88, countryId: 163, flag: '🇫🇮' },
    { name: 'French Guiana', code: '+594', price: 72.07, countryId: 162, flag: '🇬🇫' },
    { name: 'Gabon', code: '+241', price: 71.34, countryId: 154, flag: '🇬🇦' },
    { name: 'Georgia', code: '+995', price: 16.74, countryId: 128, flag: '🇬🇪' },
    { name: 'Grenada', code: '+1', price: 61.52, countryId: 127, flag: '🇬🇩' },
    { name: 'Guadeloupe', code: '+590', price: 71.34, countryId: 160, flag: '🇬🇵' },
    { name: 'Guatemala', code: '+502', price: 67.7, countryId: 94, flag: '🇬🇹' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Latvia', code: '+371', price: 28.76, countryId: 49, flag: '🇱🇻' },
    { name: 'Lebanon', code: '+961', price: 71.34, countryId: 153, flag: '🇱🇧' },
    { name: 'Liberia', code: '+231', price: 71.34, countryId: 135, flag: '🇱🇷' },
    { name: 'Lithuania', code: '+370', price: 48.78, countryId: 44, flag: '🇱🇹' },
    { name: 'Maldives', code: '+960', price: 71.34, countryId: 159, flag: '🇲🇻' },
    { name: 'Mauritius', code: '+230', price: 71.34, countryId: 157, flag: '🇲🇺' },
    { name: 'Monaco', code: '+377', price: 71.34, countryId: 144, flag: '🇲🇨' },
    { name: 'Netherlands', code: '+31', price: 4, countryId: 48, flag: '🇳🇱' },
    { name: 'Nicaragua', code: '+505', price: 71.34, countryId: 90, flag: '🇳🇮' },
    { name: 'Reunion', code: '+262', price: 71.34, countryId: 146, flag: '🇷🇪' },
    { name: 'Saint Lucia', code: '+1', price: 71.34, countryId: 164, flag: '🇱🇨' },
    { name: 'Saint Vincent', code: '+1', price: 72.44, countryId: 166, flag: '🇻🇨' },
    { name: 'Sierra Leone', code: '+232', price: 71.34, countryId: 115, flag: '🇸🇱' },
    { name: 'Slovakia', code: '+421', price: 71.34, countryId: 141, flag: '🇸🇰' },
    { name: 'Suriname', code: '+597', price: 67.7, countryId: 142, flag: '🇸🇷' },
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' },
    { name: 'Uruguay', code: '+598', price: 71.34, countryId: 156, flag: '🇺🇾' }
];

const mercariCountries = [];

const premiumoneCountries = [];

const inboxlvCountries = [];

const gofundmeCountries = [];

const hepsiburadacomCountries = [
    { name: 'Estonia', code: '+372', price: 121.94, countryId: 34, flag: '🇪🇪' },
    { name: 'Denmark', code: '+45', price: 139.78, countryId: 172, flag: '🇩🇰' },
    { name: 'Gibraltar', code: '+350', price: 12.74, countryId: 201, flag: '🇬🇮' },
    { name: 'Poland', code: '+48', price: 59.7, countryId: 15, flag: '🇵🇱' },
    { name: 'Netherlands', code: '+31', price: 12.74, countryId: 48, flag: '🇳🇱' },
    { name: 'Turkey', code: '+90', price: 35.67, countryId: 62, flag: '🇹🇷' }
];

const zupeeCountries = [
    { name: 'India', code: '+91', price: 19.66, countryId: 22, flag: '🇮🇳' },
    { name: 'Gibraltar', code: '+350', price: 549.64, countryId: 201, flag: '🇬🇮' }
];

const toslaCountries = [
    { name: 'Turkey', code: '+90', price: 248.61, countryId: 62, flag: '🇹🇷' },
    { name: 'Gibraltar', code: '+350', price: 439.71, countryId: 201, flag: '🇬🇮' }
];

const wiseCountries = [
    { name: 'USA Virtual', code: '+1', price: 1.46, countryId: 12, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 3.64, countryId: 16, flag: '🇬🇧' },
    { name: 'Poland', code: '+48', price: 110.66, countryId: 15, flag: '🇵🇱' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Netherlands', code: '+31', price: 36.04, countryId: 48, flag: '🇳🇱' },
    { name: 'India', code: '+91', price: 27.3, countryId: 22, flag: '🇮🇳' },
    { name: 'Ukraine', code: '+380', price: 72.07, countryId: 1, flag: '🇺🇦' },
    { name: 'France', code: '+33', price: 55.33, countryId: 78, flag: '🇫🇷' },
    { name: 'Mexico', code: '+52', price: 47.32, countryId: 54, flag: '🇲🇽' },
    { name: 'Germany', code: '+49', price: 187.46, countryId: 43, flag: '🇩🇪' },
    { name: 'Malaysia', code: '+60', price: 42.95, countryId: 7, flag: '🇲🇾' },
    { name: 'Philippines', code: '+63', price: 24.39, countryId: 4, flag: '🇵🇭' },
    { name: 'Estonia', code: '+372', price: 182.73, countryId: 34, flag: '🇪🇪' },
    { name: 'Singapore', code: '+65', price: 1257.62, countryId: 196, flag: '🇸🇬' },
    { name: 'Denmark', code: '+45', price: 243.15, countryId: 172, flag: '🇩🇰' },
    { name: 'Gibraltar', code: '+350', price: 847.76, countryId: 201, flag: '🇬🇮' }
];

const callappCountries = [
    { name: 'Slovakia', code: '+421', price: 78.26, countryId: 141, flag: '🇸🇰' },
    { name: 'Chile', code: '+56', price: 30.58, countryId: 151, flag: '🇨🇱' },
    { name: 'Sierra Leone', code: '+232', price: 56.78, countryId: 115, flag: '🇸🇱' },
    { name: 'Liberia', code: '+231', price: 61.15, countryId: 135, flag: '🇱🇷' },
    { name: 'Switzerland', code: '+41', price: 101.92, countryId: 173, flag: '🇨🇭' },
    { name: 'Gabon', code: '+241', price: 61.15, countryId: 154, flag: '🇬🇦' },
    { name: 'Monaco', code: '+377', price: 128.86, countryId: 144, flag: '🇲🇨' }
];

const faceitCountries = [];

const xiaomiCountries = [
    { name: 'Austria', code: '+43', price: 177.63, countryId: 50, flag: '🇦🇹' },
    { name: 'Ukraine', code: '+380', price: 2.18, countryId: 1, flag: '🇺🇦' },
    { name: 'Uzbekistan', code: '+998', price: 2.18, countryId: 40, flag: '🇺🇿' },
    { name: 'Kazakhstan', code: '+7', price: 2.18, countryId: 2, flag: '🇰🇿' },
    { name: 'Kyrgyzstan', code: '+996', price: 2.18, countryId: 11, flag: '🇰🇬' },
    { name: 'Bulgaria', code: '+359', price: 2.18, countryId: 83, flag: '🇧🇬' },
    { name: 'Laos', code: '+856', price: 22.93, countryId: 25, flag: '🇱🇦' },
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'Malaysia', code: '+60', price: 12.38, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Singapore', code: '+65', price: 139.78, countryId: 196, flag: '🇸🇬' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Gibraltar', code: '+350', price: 549.64, countryId: 201, flag: '🇬🇮' }
];

const yappyCountries = [];

const dream11Countries = [];

const iqosCountries = [
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Gibraltar', code: '+350', price: 152.15, countryId: 201, flag: '🇬🇮' }
];

const shellboxCountries = [];

const kucoinplayCountries = [];

const expressmoneyCountries = [];

const baiduCountries = [
    { name: 'Czech Republic', code: '+420', price: 2.18, countryId: 63, flag: '🇨🇿' },
    { name: 'Hungary', code: '+36', price: 28.76, countryId: 84, flag: '🇭🇺' },
    { name: 'New Zealand', code: '+64', price: 1.31, countryId: 67, flag: '🇳🇿' },
    { name: 'USA', code: '+1', price: 1.46, countryId: 187, flag: '🇺🇸' },
    { name: 'Kazakhstan', code: '+7', price: 0.22, countryId: 2, flag: '🇰🇿' },
    { name: 'Philippines', code: '+63', price: 2.18, countryId: 4, flag: '🇵🇭' },
    { name: 'Thailand', code: '+66', price: 16.74, countryId: 52, flag: '🇹🇭' },
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'Romania', code: '+40', price: 1.46, countryId: 32, flag: '🇷🇴' },
    { name: 'Sweden', code: '+46', price: 2.18, countryId: 46, flag: '🇸🇪' },
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'United Kingdom', code: '+44', price: 2.91, countryId: 16, flag: '🇬🇧' },
    { name: 'Hong Kong', code: '+852', price: 23.3, countryId: 14, flag: '🇭🇰' },
    { name: 'Germany', code: '+49', price: 8.74, countryId: 43, flag: '🇩🇪' },
    { name: 'Canada', code: '+1', price: 1.46, countryId: 36, flag: '🇨🇦' },
    { name: 'Vietnam', code: '+84', price: 2.18, countryId: 10, flag: '🇻🇳' },
    { name: 'Netherlands', code: '+31', price: 8.74, countryId: 48, flag: '🇳🇱' },
    { name: 'France', code: '+33', price: 12.74, countryId: 78, flag: '🇫🇷' },
    { name: 'Spain', code: '+34', price: 2.18, countryId: 56, flag: '🇪🇸' },
    { name: 'India', code: '+91', price: 16.74, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Mexico', code: '+52', price: 15.65, countryId: 54, flag: '🇲🇽' },
    { name: 'Brazil', code: '+55', price: 2.18, countryId: 73, flag: '🇧🇷' },
    { name: 'Malaysia', code: '+60', price: 2.18, countryId: 7, flag: '🇲🇾' },
    { name: 'Pakistan', code: '+92', price: 18.56, countryId: 66, flag: '🇵🇰' },
    { name: 'Bangladesh', code: '+880', price: 18.56, countryId: 60, flag: '🇧🇩' },
    { name: 'Ukraine', code: '+380', price: 0.22, countryId: 1, flag: '🇺🇦' },
    { name: 'Uzbekistan', code: '+998', price: 2.18, countryId: 40, flag: '🇺🇿' },
    { name: 'Swaziland', code: '+268', price: 60.42, countryId: 106, flag: '🇸🇿' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Myanmar', code: '+95', price: 16.74, countryId: 5, flag: '🇲🇲' },
    { name: 'Timor-Leste', code: '+670', price: 2.18, countryId: 91, flag: '🇹🇱' },
    { name: 'Kenya', code: '+254', price: 2.18, countryId: 8, flag: '🇰🇪' },
    { name: 'Venezuela', code: '+58', price: 1.67, countryId: 70, flag: '🇻🇪' },
    { name: 'Colombia', code: '+57', price: 2.18, countryId: 33, flag: '🇨🇴' },
    { name: 'Kyrgyzstan', code: '+996', price: 2.18, countryId: 11, flag: '🇰🇬' },
    { name: 'Israel', code: '', price: 2.18, countryId: 13, flag: '🇮🇱' },
    { name: 'Bulgaria', code: '+359', price: 2.18, countryId: 83, flag: '🇧🇬' },
    { name: 'Mauritius', code: '+230', price: 56.78, countryId: 157, flag: '🇲🇺' },
    { name: 'Turkmenistan', code: '+993', price: 54.6, countryId: 161, flag: '🇹🇲' },
    { name: 'Gabon', code: '+241', price: 2.18, countryId: 154, flag: '🇬🇦' },
    { name: 'Moldova', code: '+373', price: 16.74, countryId: 85, flag: '🇲🇩' },
    { name: 'Albania', code: '+355', price: 2.18, countryId: 155, flag: '🇦🇱' },
    { name: 'Australia', code: '', price: 23.3, countryId: 175, flag: '🇦🇺' },
    { name: 'Belize', code: '+501', price: 1.46, countryId: 124, flag: '🇧🇿' },
    { name: 'Brunei Darussalam', code: '+673', price: 56.78, countryId: 121, flag: '🇧🇳' },
    { name: 'Burkina Faso', code: '+226', price: 2.18, countryId: 152, flag: '🇧🇫' },
    { name: 'CAF', code: '+236', price: 56.78, countryId: 125, flag: '🇨🇫' },
    { name: 'Chile', code: '+56', price: 6.55, countryId: 151, flag: '🇨🇱' },
    { name: 'Comoros', code: '+269', price: 56.78, countryId: 133, flag: '🇰🇲' },
    { name: 'Cyprus', code: '+357', price: 12.38, countryId: 77, flag: '🇨🇾' },
    { name: 'Denmark', code: '+45', price: 2.18, countryId: 172, flag: '🇩🇰' },
    { name: 'Estonia', code: '+372', price: 2.18, countryId: 34, flag: '🇪🇪' },
    { name: 'Gibraltar', code: '+350', price: 224.95, countryId: 201, flag: '🇬🇮' },
    { name: 'Greece', code: '+30', price: 2.18, countryId: 129, flag: '🇬🇷' },
    { name: 'Grenada', code: '+1', price: 1.46, countryId: 127, flag: '🇬🇩' },
    { name: 'Guadeloupe', code: '+590', price: 30.58, countryId: 160, flag: '🇬🇵' },
    { name: 'Iceland', code: '+354', price: 78.26, countryId: 132, flag: '🇮🇸' },
    { name: 'Ireland', code: '+353', price: 2.18, countryId: 23, flag: '🇮🇪' },
    { name: 'Italy', code: '+39', price: 10.92, countryId: 86, flag: '🇮🇹' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Laos', code: '+856', price: 18.56, countryId: 25, flag: '🇱🇦' },
    { name: 'Lebanon', code: '+961', price: 2.18, countryId: 153, flag: '🇱🇧' },
    { name: 'Liberia', code: '+231', price: 1.46, countryId: 135, flag: '🇱🇷' },
    { name: 'Maldives', code: '+960', price: 51.69, countryId: 159, flag: '🇲🇻' },
    { name: 'Monaco', code: '+377', price: 128.86, countryId: 144, flag: '🇲🇨' },
    { name: 'Portugal', code: '+351', price: 2.18, countryId: 117, flag: '🇵🇹' },
    { name: 'Serbia', code: '+381', price: 18.56, countryId: 29, flag: '🇷🇸' },
    { name: 'Sierra Leone', code: '+232', price: 30.58, countryId: 115, flag: '🇸🇱' },
    { name: 'Singapore', code: '+65', price: 2.18, countryId: 196, flag: '🇸🇬' },
    { name: 'Slovakia', code: '+421', price: 78.26, countryId: 141, flag: '🇸🇰' },
    { name: 'Suriname', code: '+597', price: 47.32, countryId: 142, flag: '🇸🇷' },
    { name: 'Switzerland', code: '+41', price: 21.48, countryId: 173, flag: '🇨🇭' },
    { name: 'Uruguay', code: '+598', price: 54.96, countryId: 156, flag: '🇺🇾' }
];

const subitoCountries = [
    { name: 'Italy', code: '+39', price: 29.12, countryId: 86, flag: '🇮🇹' },
    { name: 'France', code: '+33', price: 89.91, countryId: 78, flag: '🇫🇷' },
    { name: 'Saudi Arabia', code: '+966', price: 29.12, countryId: 53, flag: '🇸🇦' },
    { name: 'Pakistan', code: '+92', price: 29.12, countryId: 66, flag: '🇵🇰' },
    { name: 'Turkey', code: '+90', price: 145.6, countryId: 62, flag: '🇹🇷' },
    { name: 'Myanmar', code: '+95', price: 29.12, countryId: 5, flag: '🇲🇲' },
    { name: 'Spain', code: '+34', price: 51.69, countryId: 56, flag: '🇪🇸' },
    { name: 'Bangladesh', code: '+880', price: 29.12, countryId: 60, flag: '🇧🇩' },
    { name: 'Philippines', code: '+63', price: 29.12, countryId: 4, flag: '🇵🇭' },
    { name: 'Latvia', code: '+371', price: 182.73, countryId: 49, flag: '🇱🇻' },
    { name: 'Germany', code: '+49', price: 20.02, countryId: 43, flag: '🇩🇪' },
    { name: 'Cambodia', code: '+855', price: 29.12, countryId: 24, flag: '🇰🇭' },
    { name: 'Austria', code: '+43', price: 112.11, countryId: 50, flag: '🇦🇹' },
    { name: 'Switzerland', code: '+41', price: 136.86, countryId: 173, flag: '🇨🇭' },
    { name: 'Poland', code: '+48', price: 136.86, countryId: 15, flag: '🇵🇱' },
    { name: 'Czech Republic', code: '+420', price: 107.38, countryId: 63, flag: '🇨🇿' },
    { name: 'Finland', code: '+358', price: 182.73, countryId: 163, flag: '🇫🇮' },
    { name: 'Cyprus', code: '+357', price: 121.94, countryId: 77, flag: '🇨🇾' },
    { name: 'Slovenia', code: '+386', price: 127.76, countryId: 59, flag: '🇸🇮' },
    { name: 'Netherlands', code: '+31', price: 8.37, countryId: 48, flag: '🇳🇱' },
    { name: 'USA', code: '+1', price: 107.02, countryId: 187, flag: '🇺🇸' },
    { name: 'Belgium', code: '+32', price: 120.48, countryId: 82, flag: '🇧🇪' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Hungary', code: '+36', price: 182.73, countryId: 84, flag: '🇭🇺' },
    { name: 'Ireland', code: '+353', price: 123.03, countryId: 23, flag: '🇮🇪' },
    { name: 'Estonia', code: '+372', price: 121.94, countryId: 34, flag: '🇪🇪' },
    { name: 'Sweden', code: '+46', price: 133.22, countryId: 46, flag: '🇸🇪' },
    { name: 'Greece', code: '+30', price: 121.94, countryId: 129, flag: '🇬🇷' },
    { name: 'Lithuania', code: '+370', price: 121.94, countryId: 44, flag: '🇱🇹' },
    { name: 'Slovakia', code: '+421', price: 182.73, countryId: 141, flag: '🇸🇰' },
    { name: 'Croatia', code: '+385', price: 93.18, countryId: 45, flag: '🇭🇷' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Gibraltar', code: '+350', price: 549.64, countryId: 201, flag: '🇬🇮' }
];

const lovelocalCountries = [];

const likeeCountries = [];

const chalkboardCountries = [];

const casinoplusCountries = [];

const kleinanzeigenCountries = [];

const rakutenCountries = [];

const gochatCountries = [
    { name: 'Algeria', code: '+213', price: 5.1, countryId: 58, flag: '🇩🇿' },
    { name: 'Angola', code: '+244', price: 48.78, countryId: 76, flag: '🇦🇴' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Austria', code: '+43', price: 48.78, countryId: 50, flag: '🇦🇹' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Canada', code: '+1', price: 42.95, countryId: 36, flag: '🇨🇦' },
    { name: 'Colombia', code: '+57', price: 4, countryId: 33, flag: '🇨🇴' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 48.78, countryId: 18, flag: '🇨🇩' },
    { name: 'Czech Republic', code: '+420', price: 5.1, countryId: 63, flag: '🇨🇿' },
    { name: 'Ecuador', code: '+593', price: 48.78, countryId: 105, flag: '🇪🇨' },
    { name: 'Egypt', code: '+20', price: 48.78, countryId: 21, flag: '🇪🇬' },
    { name: 'El Salvador', code: '+503', price: 48.78, countryId: 101, flag: '🇸🇻' },
    { name: 'Ethiopia', code: '+251', price: 48.78, countryId: 71, flag: '🇪🇹' },
    { name: 'France', code: '+33', price: 24.39, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 5.1, countryId: 43, flag: '🇩🇪' },
    { name: 'Ghana', code: '+233', price: 48.78, countryId: 38, flag: '🇬🇭' },
    { name: 'Haiti', code: '+509', price: 48.78, countryId: 26, flag: '🇭🇹' },
    { name: 'Honduras', code: '+504', price: 48.78, countryId: 88, flag: '🇭🇳' },
    { name: 'India', code: '+91', price: 48.78, countryId: 22, flag: '🇮🇳' },
    { name: 'Iran', code: '+98', price: 48.78, countryId: 57, flag: '🇮🇷' },
    { name: 'Italy', code: '+39', price: 36.4, countryId: 86, flag: '🇮🇹' },
    { name: 'Jordan', code: '+962', price: 48.78, countryId: 116, flag: '🇯🇴' },
    { name: 'Kazakhstan', code: '+7', price: 5.1, countryId: 2, flag: '🇰🇿' },
    { name: 'Kenya', code: '+254', price: 5.1, countryId: 8, flag: '🇰🇪' },
    { name: 'Kyrgyzstan', code: '+996', price: 48.78, countryId: 11, flag: '🇰🇬' },
    { name: 'Malawi', code: '+265', price: 48.78, countryId: 137, flag: '🇲🇼' },
    { name: 'Malaysia', code: '+60', price: 42.22, countryId: 7, flag: '🇲🇾' },
    { name: 'Mexico', code: '+52', price: 48.78, countryId: 54, flag: '🇲🇽' },
    { name: 'Myanmar', code: '+95', price: 48.78, countryId: 5, flag: '🇲🇲' },
    { name: 'Nepal', code: '+977', price: 48.78, countryId: 81, flag: '🇳🇵' },
    { name: 'Nigeria', code: '+234', price: 48.78, countryId: 19, flag: '🇳🇬' },
    { name: 'Pakistan', code: '+92', price: 48.78, countryId: 66, flag: '🇵🇰' },
    { name: 'Panama', code: '+507', price: 48.78, countryId: 112, flag: '🇵🇦' },
    { name: 'Paraguay', code: '+595', price: 48.78, countryId: 87, flag: '🇵🇾' },
    { name: 'Peru', code: '+51', price: 48.78, countryId: 65, flag: '🇵🇪' },
    { name: 'Philippines', code: '+63', price: 24.39, countryId: 4, flag: '🇵🇭' },
    { name: 'Romania', code: '+40', price: 5.1, countryId: 32, flag: '🇷🇴' },
    { name: 'Saudi Arabia', code: '+966', price: 1.46, countryId: 53, flag: '🇸🇦' },
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '+34', price: 29.85, countryId: 56, flag: '🇪🇸' },
    { name: 'Sri Lanka', code: '+94', price: 48.78, countryId: 64, flag: '🇱🇰' },
    { name: 'Tanzania', code: '+255', price: 48.78, countryId: 9, flag: '🇹🇿' },
    { name: 'Tunisia', code: '+216', price: 5.1, countryId: 89, flag: '🇹🇳' },
    { name: 'Turkey', code: '+90', price: 409.5, countryId: 62, flag: '🇹🇷' },
    { name: 'Uganda', code: '+256', price: 48.78, countryId: 75, flag: '🇺🇬' },
    { name: 'Ukraine', code: '+380', price: 4, countryId: 1, flag: '🇺🇦' },
    { name: 'Uzbekistan', code: '+998', price: 48.78, countryId: 40, flag: '🇺🇿' },
    { name: 'Venezuela', code: '+58', price: 48.78, countryId: 70, flag: '🇻🇪' },
    { name: 'Vietnam', code: '+84', price: 5.1, countryId: 10, flag: '🇻🇳' },
    { name: 'Zambia', code: '+260', price: 48.78, countryId: 147, flag: '🇿🇲' }
];

const smilesCountries = [
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Cambodia', code: '+855', price: 91.36, countryId: 24, flag: '🇰🇭' },
    { name: 'South Sudan', code: '+211', price: 2.18, countryId: 177, flag: '🇸🇸' },
    { name: 'Mauritius', code: '+230', price: 2.18, countryId: 157, flag: '🇲🇺' },
    { name: 'Trinidad and Tobago', code: '+1', price: 2.18, countryId: 104, flag: '🇹🇹' },
    { name: 'Burundi', code: '+257', price: 2.18, countryId: 119, flag: '🇧🇮' },
    { name: 'Malaysia', code: '+60', price: 91.36, countryId: 7, flag: '🇲🇾' },
    { name: 'Syria', code: '+963', price: 1.46, countryId: 1333, flag: '🇸🇾' },
    { name: 'Hungary', code: '+36', price: 91.36, countryId: 84, flag: '🇭🇺' },
    { name: 'Nigeria', code: '+234', price: 2.18, countryId: 19, flag: '🇳🇬' },
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'Togo', code: '+228', price: 2.18, countryId: 99, flag: '🇹🇬' },
    { name: 'Senegal', code: '+221', price: 2.18, countryId: 61, flag: '🇸🇳' },
    { name: 'Laos', code: '+856', price: 2.18, countryId: 25, flag: '🇱🇦' },
    { name: 'China', code: '+86', price: 91.36, countryId: 3, flag: '🇨🇳' },
    { name: 'Guinea-Bissau', code: '+245', price: 2.18, countryId: 130, flag: '🇬🇼' },
    { name: 'Maldives', code: '+960', price: 2.18, countryId: 159, flag: '🇲🇻' },
    { name: 'Portugal', code: '+351', price: 2.18, countryId: 117, flag: '🇵🇹' },
    { name: 'Bosnia and Herzegovina', code: '+387', price: 2.18, countryId: 108, flag: '🇧🇦' },
    { name: 'Somalia', code: '+252', price: 2.18, countryId: 149, flag: '🇸🇴' },
    { name: 'Dominican Republic', code: '+1', price: 2.18, countryId: 109, flag: '🇩🇴' },
    { name: 'Gambia', code: '+220', price: 2.18, countryId: 28, flag: '🇬🇲' },
    { name: 'Afghanistan', code: '+93', price: 2.18, countryId: 74, flag: '🇦🇫' },
    { name: 'Armenia', code: '+374', price: 2.18, countryId: 148, flag: '🇦🇲' },
    { name: 'Guyana', code: '+592', price: 2.18, countryId: 131, flag: '🇬🇾' },
    { name: 'Chad', code: '+235', price: 2.18, countryId: 42, flag: '🇹🇩' },
    { name: 'Switzerland', code: '+41', price: 68.43, countryId: 173, flag: '🇨🇭' },
    { name: 'Ireland', code: '+353', price: 2.18, countryId: 23, flag: '🇮🇪' },
    { name: 'Serbia', code: '+381', price: 2.18, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 2.18, countryId: 34, flag: '🇪🇪' },
    { name: 'Bahrain', code: '+973', price: 2.18, countryId: 145, flag: '🇧🇭' },
    { name: 'Guadeloupe', code: '+590', price: 2.18, countryId: 160, flag: '🇬🇵' },
    { name: 'Norway', code: '+47', price: 91.36, countryId: 174, flag: '🇳🇴' },
    { name: 'Italy', code: '+39', price: 22.93, countryId: 86, flag: '🇮🇹' },
    { name: 'Cyprus', code: '+357', price: 2.18, countryId: 77, flag: '🇨🇾' },
    { name: 'Luxembourg', code: '+352', price: 2.18, countryId: 165, flag: '🇱🇺' },
    { name: 'Suriname', code: '+597', price: 2.18, countryId: 142, flag: '🇸🇷' },
    { name: 'Guatemala', code: '+502', price: 2.18, countryId: 94, flag: '🇬🇹' },
    { name: 'Madagascar', code: '+261', price: 2.18, countryId: 17, flag: '🇲🇬' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Sweden', code: '+46', price: 2.18, countryId: 46, flag: '🇸🇪' },
    { name: 'Finland', code: '+358', price: 91.36, countryId: 163, flag: '🇫🇮' },
    { name: 'Montenegro', code: '+382', price: 2.18, countryId: 171, flag: '🇲🇪' },
    { name: 'Cuba', code: '+53', price: 2.18, countryId: 113, flag: '🇨🇺' },
    { name: 'Greece', code: '+30', price: 2.18, countryId: 129, flag: '🇬🇷' },
    { name: 'Chile', code: '+56', price: 25.48, countryId: 151, flag: '🇨🇱' },
    { name: 'Georgia', code: '+995', price: 2.18, countryId: 128, flag: '🇬🇪' },
    { name: 'Sierra Leone', code: '+232', price: 2.18, countryId: 115, flag: '🇸🇱' },
    { name: 'Bahamas', code: '+1', price: 2.18, countryId: 122, flag: '🇧🇸' },
    { name: 'Bolivia', code: '+591', price: 2.18, countryId: 92, flag: '🇧🇴' },
    { name: 'Grenada', code: '+1', price: 2.18, countryId: 127, flag: '🇬🇩' },
    { name: 'Latvia', code: '+371', price: 2.18, countryId: 49, flag: '🇱🇻' },
    { name: 'Tajikistan', code: '+992', price: 2.18, countryId: 143, flag: '🇹🇯' },
    { name: 'Brunei Darussalam', code: '+673', price: 2.18, countryId: 121, flag: '🇧🇳' },
    { name: 'Albania', code: '+355', price: 2.18, countryId: 155, flag: '🇦🇱' },
    { name: 'Slovenia', code: '+386', price: 2.18, countryId: 59, flag: '🇸🇮' },
    { name: 'Hong Kong', code: '+852', price: 91.36, countryId: 14, flag: '🇭🇰' },
    { name: 'Saint Kitts and Nevis', code: '+1', price: 2.18, countryId: 134, flag: '🇰🇳' },
    { name: 'Taiwan', code: '+886', price: 91.36, countryId: 55, flag: '🇹🇼' },
    { name: 'Lithuania', code: '+370', price: 2.18, countryId: 44, flag: '🇱🇹' },
    { name: 'CAF', code: '+236', price: 2.18, countryId: 125, flag: '🇨🇫' },
    { name: 'Liberia', code: '+231', price: 2.18, countryId: 135, flag: '🇱🇷' },
    { name: 'Japan', code: '+81', price: 78.26, countryId: 1001, flag: '🇯🇵' },
    { name: 'Guinea', code: '+224', price: 2.18, countryId: 68, flag: '🇬🇳' },
    { name: 'Aruba', code: '+297', price: 2.18, countryId: 179, flag: '🇦🇼' },
    { name: 'Singapore', code: '+65', price: 91.36, countryId: 196, flag: '🇸🇬' },
    { name: 'Slovakia', code: '+421', price: 2.18, countryId: 141, flag: '🇸🇰' },
    { name: 'Sao Tome and Principe', code: '+239', price: 2.18, countryId: 178, flag: '🇸🇹' },
    { name: 'Croatia', code: '+385', price: 2.18, countryId: 45, flag: '🇭🇷' },
    { name: 'Cape Verde', code: '+238', price: 2.18, countryId: 186, flag: '🇨🇻' },
    { name: 'Monaco', code: '+377', price: 91.36, countryId: 144, flag: '🇲🇨' },
    { name: 'Macedonia', code: '+389', price: 91.36, countryId: 183, flag: '🇲🇰' },
    { name: 'Belize', code: '+501', price: 2.18, countryId: 124, flag: '🇧🇿' },
    { name: 'New Zealand', code: '+64', price: 2.18, countryId: 67, flag: '🇳🇿' },
    { name: 'Mongolia', code: '+976', price: 2.18, countryId: 72, flag: '🇲🇳' },
    { name: 'Lebanon', code: '+961', price: 2.18, countryId: 153, flag: '🇱🇧' },
    { name: 'Denmark', code: '+45', price: 2.18, countryId: 172, flag: '🇩🇰' },
    { name: 'Seychelles', code: '+248', price: 2.18, countryId: 184, flag: '🇸🇨' },
    { name: 'Australia', code: '', price: 2.18, countryId: 175, flag: '🇦🇺' },
    { name: 'Macau', code: '+853', price: 2.18, countryId: 20, flag: '🇲🇴' },
    { name: 'Iceland', code: '+354', price: 2.18, countryId: 132, flag: '🇮🇸' },
    { name: 'Eritrea', code: '+291', price: 2.18, countryId: 176, flag: '🇪🇷' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Canada', code: '+1', price: 1.46, countryId: 36, flag: '🇨🇦' },
    { name: 'UAE', code: '+971', price: 42.22, countryId: 95, flag: '🇦🇪' },
    { name: 'Czech Republic', code: '+420', price: 24.75, countryId: 63, flag: '🇨🇿' },
    { name: 'Germany', code: '+49', price: 15.65, countryId: 43, flag: '🇩🇪' },
    { name: 'Philippines', code: '+63', price: 61.88, countryId: 4, flag: '🇵🇭' },
    { name: 'Saudi Arabia', code: '+966', price: 42.95, countryId: 53, flag: '🇸🇦' },
    { name: 'Romania', code: '+40', price: 38.58, countryId: 32, flag: '🇷🇴' },
    { name: 'Spain', code: '+34', price: 37.49, countryId: 56, flag: '🇪🇸' },
    { name: 'Austria', code: '+43', price: 56.78, countryId: 50, flag: '🇦🇹' },
    { name: 'USA', code: '+1', price: 43.68, countryId: 187, flag: '🇺🇸' },
    { name: 'South Africa', code: '+27', price: 2.18, countryId: 31, flag: '🇿🇦' },
    { name: 'India', code: '+91', price: 2.18, countryId: 22, flag: '🇮🇳' },
    { name: 'Pakistan', code: '+92', price: 91.36, countryId: 66, flag: '🇵🇰' },
    { name: 'Zambia', code: '+260', price: 2.18, countryId: 147, flag: '🇿🇲' },
    { name: 'Namibia', code: '+264', price: 2.18, countryId: 138, flag: '🇳🇦' },
    { name: 'Papua new gvineya', code: '+675', price: 2.18, countryId: 79, flag: '🇵🇬' },
    { name: 'Algeria', code: '+213', price: 2.18, countryId: 58, flag: '🇩🇿' },
    { name: 'Ethiopia', code: '+251', price: 2.18, countryId: 71, flag: '🇪🇹' },
    { name: 'Mozambique', code: '+258', price: 2.18, countryId: 80, flag: '🇲🇿' },
    { name: 'Angola', code: '+244', price: 2.18, countryId: 76, flag: '🇦🇴' },
    { name: 'Ukraine', code: '+380', price: 2.18, countryId: 1, flag: '🇺🇦' },
    { name: 'Egypt', code: '+20', price: 2.18, countryId: 21, flag: '🇪🇬' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Haiti', code: '+509', price: 2.18, countryId: 26, flag: '🇭🇹' },
    { name: 'Iran', code: '+98', price: 2.18, countryId: 57, flag: '🇮🇷' },
    { name: 'Peru', code: '+51', price: 2.18, countryId: 65, flag: '🇵🇪' },
    { name: 'Vietnam', code: '+84', price: 2.18, countryId: 10, flag: '🇻🇳' },
    { name: 'Zimbabwe', code: '+263', price: 2.18, countryId: 96, flag: '🇿🇼' },
    { name: 'Nepal', code: '+977', price: 2.18, countryId: 81, flag: '🇳🇵' },
    { name: 'Uzbekistan', code: '+998', price: 2.18, countryId: 40, flag: '🇺🇿' },
    { name: 'Swaziland', code: '+268', price: 2.18, countryId: 106, flag: '🇸🇿' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 2.18, countryId: 18, flag: '🇨🇩' },
    { name: 'France', code: '+33', price: 24.75, countryId: 78, flag: '🇫🇷' },
    { name: 'Botswana', code: '+267', price: 2.18, countryId: 123, flag: '🇧🇼' },
    { name: 'Mexico', code: '+52', price: 91.36, countryId: 54, flag: '🇲🇽' },
    { name: 'Tanzania', code: '+255', price: 2.18, countryId: 9, flag: '🇹🇿' },
    { name: 'Sri Lanka', code: '+94', price: 2.18, countryId: 64, flag: '🇱🇰' },
    { name: 'Honduras', code: '+504', price: 2.18, countryId: 88, flag: '🇭🇳' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Myanmar', code: '+95', price: 2.18, countryId: 5, flag: '🇲🇲' },
    { name: 'Tunisia', code: '+216', price: 2.18, countryId: 89, flag: '🇹🇳' },
    { name: 'Timor-Leste', code: '+670', price: 2.18, countryId: 91, flag: '🇹🇱' },
    { name: 'Lesotho', code: '+266', price: 2.18, countryId: 136, flag: '🇱🇸' },
    { name: 'Ecuador', code: '+593', price: 2.18, countryId: 105, flag: '🇪🇨' },
    { name: 'El Salvador', code: '+503', price: 2.18, countryId: 101, flag: '🇸🇻' },
    { name: 'Morocco', code: '+212', price: 2.18, countryId: 37, flag: '🇲🇦' },
    { name: 'Uganda', code: '+256', price: 2.18, countryId: 75, flag: '🇺🇬' },
    { name: 'Malawi', code: '+265', price: 2.18, countryId: 137, flag: '🇲🇼' },
    { name: 'Ghana', code: '+233', price: 2.18, countryId: 38, flag: '🇬🇭' },
    { name: 'Kenya', code: '+254', price: 2.18, countryId: 8, flag: '🇰🇪' },
    { name: 'Panama', code: '+507', price: 2.18, countryId: 112, flag: '🇵🇦' },
    { name: 'Jamaica', code: '+1', price: 2.18, countryId: 103, flag: '🇯🇲' },
    { name: 'Venezuela', code: '+58', price: 2.18, countryId: 70, flag: '🇻🇪' },
    { name: 'Kazakhstan', code: '+7', price: 2.18, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 2.18, countryId: 33, flag: '🇨🇴' },
    { name: 'Paraguay', code: '+595', price: 2.18, countryId: 87, flag: '🇵🇾' },
    { name: 'Turkey', code: '+90', price: 91.36, countryId: 62, flag: '🇹🇷' },
    { name: 'Kyrgyzstan', code: '+996', price: 2.18, countryId: 11, flag: '🇰🇬' },
    { name: 'Jordan', code: '+962', price: 2.18, countryId: 116, flag: '🇯🇴' },
    { name: 'Cameroon', code: '+237', price: 2.18, countryId: 41, flag: '🇨🇲' },
    { name: 'Israel', code: '', price: 2.18, countryId: 13, flag: '🇮🇱' },
    { name: 'Ivory Coast', code: '+225', price: 2.18, countryId: 27, flag: '🇨🇮' },
    { name: 'Bulgaria', code: '+359', price: 2.18, countryId: 83, flag: '🇧🇬' },
    { name: 'Libya', code: '+218', price: 2.18, countryId: 102, flag: '🇱🇾' },
    { name: 'Turkmenistan', code: '+993', price: 2.18, countryId: 161, flag: '🇹🇲' },
    { name: 'Azerbaijan', code: '+994', price: 2.18, countryId: 35, flag: '🇦🇿' },
    { name: 'Mali', code: '+223', price: 2.18, countryId: 69, flag: '🇲🇱' },
    { name: 'Rwanda', code: '+250', price: 2.18, countryId: 140, flag: '🇷🇼' },
    { name: 'Gabon', code: '+241', price: 2.18, countryId: 154, flag: '🇬🇦' },
    { name: 'Sudan', code: '+249', price: 91.36, countryId: 1010, flag: '🇸🇩' },
    { name: 'Nicaragua', code: '+505', price: 2.18, countryId: 90, flag: '🇳🇮' },
    { name: 'Moldova', code: '+373', price: 2.18, countryId: 85, flag: '🇲🇩' },
    { name: 'Thailand', code: '+66', price: 91.36, countryId: 52, flag: '🇹🇭' },
    { name: 'Benin', code: '+229', price: 2.18, countryId: 120, flag: '🇧🇯' },
    { name: 'Costa Rica', code: '+506', price: 2.18, countryId: 93, flag: '🇨🇷' },
    { name: 'Burkina Faso', code: '+226', price: 2.18, countryId: 152, flag: '🇧🇫' },
    { name: 'Qatar', code: '+974', price: 2.18, countryId: 111, flag: '🇶🇦' },
    { name: 'Belgium', code: '+32', price: 2.18, countryId: 82, flag: '🇧🇪' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Oman', code: '+968', price: 2.18, countryId: 107, flag: '🇴🇲' },
    { name: 'Congo', code: '+242', price: 2.18, countryId: 150, flag: '🇨🇬' },
    { name: 'Yemen', code: '+967', price: 2.18, countryId: 30, flag: '🇾🇪' },
    { name: 'Uruguay', code: '+598', price: 2.18, countryId: 156, flag: '🇺🇾' },
    { name: 'Iraq', code: '+964', price: 2.18, countryId: 47, flag: '🇮🇶' },
    { name: 'Niger', code: '+227', price: 2.18, countryId: 139, flag: '🇳🇪' },
    { name: 'Mauritania', code: '+222', price: 2.18, countryId: 114, flag: '🇲🇷' },
    { name: 'Kuwait', code: '+965', price: 2.18, countryId: 100, flag: '🇰🇼' }
];

const anyotherCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'USA', code: '+1', price: 5.1, countryId: 187, flag: '🇺🇸' },
    { name: 'Chile', code: '+56', price: 13.83, countryId: 151, flag: '🇨🇱' },
    { name: 'France', code: '+33', price: 43.68, countryId: 78, flag: '🇫🇷' },
    { name: 'Argentina', code: '+54', price: 42.95, countryId: 39, flag: '🇦🇷' },
    { name: 'United Kingdom', code: '+44', price: 6.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 4, countryId: 48, flag: '🇳🇱' },
    { name: 'Poland', code: '+48', price: 36.4, countryId: 15, flag: '🇵🇱' },
    { name: 'Portugal', code: '+351', price: 72.8, countryId: 117, flag: '🇵🇹' },
    { name: 'Ukraine', code: '+380', price: 72.8, countryId: 1, flag: '🇺🇦' },
    { name: 'Australia', code: '', price: 551.82, countryId: 175, flag: '🇦🇺' },
    { name: 'Kazakhstan', code: '+7', price: 228.23, countryId: 2, flag: '🇰🇿' },
    { name: 'Sweden', code: '+46', price: 108.84, countryId: 46, flag: '🇸🇪' },
    { name: 'Czech Republic', code: '+420', price: 391.3, countryId: 63, flag: '🇨🇿' },
    { name: 'Slovenia', code: '+386', price: 43.68, countryId: 59, flag: '🇸🇮' },
    { name: 'Estonia', code: '+372', price: 121.94, countryId: 34, flag: '🇪🇪' },
    { name: 'Kenya', code: '+254', price: 26.94, countryId: 8, flag: '🇰🇪' },
    { name: 'Vietnam', code: '+84', price: 72.07, countryId: 10, flag: '🇻🇳' },
    { name: 'Philippines', code: '+63', price: 1.46, countryId: 4, flag: '🇵🇭' },
    { name: 'Denmark', code: '+45', price: 110.66, countryId: 172, flag: '🇩🇰' },
    { name: 'Algeria', code: '+213', price: 91.36, countryId: 58, flag: '🇩🇿' },
    { name: 'Kyrgyzstan', code: '+996', price: 11.28, countryId: 11, flag: '🇰🇬' },
    { name: 'Laos', code: '+856', price: 27.3, countryId: 25, flag: '🇱🇦' },
    { name: 'Malaysia', code: '+60', price: 38.95, countryId: 7, flag: '🇲🇾' },
    { name: 'Cambodia', code: '+855', price: 121.94, countryId: 24, flag: '🇰🇭' },
    { name: 'Afghanistan', code: '+93', price: 142.69, countryId: 74, flag: '🇦🇫' },
    { name: 'Ireland', code: '+353', price: 494.31, countryId: 23, flag: '🇮🇪' },
    { name: 'Tajikistan', code: '+992', price: 18.56, countryId: 143, flag: '🇹🇯' },
    { name: 'Hong Kong', code: '+852', price: 439.71, countryId: 14, flag: '🇭🇰' },
    { name: 'Lithuania', code: '+370', price: 57.51, countryId: 44, flag: '🇱🇹' },
    { name: 'Japan', code: '+81', price: 3276, countryId: 1001, flag: '🇯🇵' }
];

const notifireCountries = [
    { name: 'Czech Republic', code: '+420', price: 15.65, countryId: 63, flag: '🇨🇿' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Estonia', code: '+372', price: 36.4, countryId: 34, flag: '🇪🇪' }
];

const privetmirCountries = [];

const yamiCountries = [];

const synottipCountries = [
    { name: 'United Kingdom', code: '+44', price: 48.78, countryId: 16, flag: '🇬🇧' },
    { name: 'Czech Republic', code: '+420', price: 92.46, countryId: 63, flag: '🇨🇿' }
];

const miraviaCountries = [
    { name: 'Spain', code: '+34', price: 27.66, countryId: 56, flag: '🇪🇸' },
    { name: 'Germany', code: '+49', price: 12.38, countryId: 43, flag: '🇩🇪' },
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'Poland', code: '+48', price: 26.21, countryId: 15, flag: '🇵🇱' },
    { name: 'Netherlands', code: '+31', price: 10.19, countryId: 48, flag: '🇳🇱' },
    { name: 'Estonia', code: '+372', price: 79.35, countryId: 34, flag: '🇪🇪' },
    { name: 'Denmark', code: '+45', price: 79.35, countryId: 172, flag: '🇩🇰' }
];

const walmartCountries = [
    { name: 'USA', code: '+1', price: 48.78, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 1.46, countryId: 12, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 2.18, countryId: 36, flag: '🇨🇦' }
];

const fortunaskCountries = [];

const freenowCountries = [
    { name: 'Colombia', code: '+57', price: 40.4, countryId: 33, flag: '🇨🇴' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Philippines', code: '+63', price: 15.29, countryId: 4, flag: '🇵🇭' },
    { name: 'Malaysia', code: '+60', price: 17.11, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Chile', code: '+56', price: 11.46, countryId: 151, flag: '🇨🇱' },
    { name: 'Lithuania', code: '+370', price: 2.18, countryId: 44, flag: '🇱🇹' },
    { name: 'Kosovo', code: '+383', price: 12.18, countryId: 1004, flag: '🇽🇰' }
];

const shpockCountries = [
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '+49', price: 36.04, countryId: 43, flag: '🇩🇪' },
    { name: 'Netherlands', code: '+31', price: 8.01, countryId: 48, flag: '🇳🇱' }
];

const motorkuxCountries = [];

const indodaxCountries = [];

const upworkCountries = [
    { name: 'United Kingdom', code: '+44', price: 2.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 1.46, countryId: 48, flag: '🇳🇱' },
    { name: 'USA Virtual', code: '+1', price: 1.46, countryId: 12, flag: '🇺🇸' },
    { name: 'Malaysia', code: '+60', price: 24.39, countryId: 7, flag: '🇲🇾' },
    { name: 'India', code: '+91', price: 22.93, countryId: 22, flag: '🇮🇳' },
    { name: 'Kenya', code: '+254', price: 2.18, countryId: 8, flag: '🇰🇪' },
    { name: 'Kazakhstan', code: '+7', price: 2.18, countryId: 2, flag: '🇰🇿' },
    { name: 'Paraguay', code: '+595', price: 2.18, countryId: 87, flag: '🇵🇾' },
    { name: 'Thailand', code: '+66', price: 17.11, countryId: 52, flag: '🇹🇭' },
    { name: 'Chile', code: '+56', price: 8.37, countryId: 151, flag: '🇨🇱' },
    { name: 'Lithuania', code: '+370', price: 2.18, countryId: 44, flag: '🇱🇹' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const beanfunCountries = [];

const claudeCountries = [
    { name: 'Japan', code: '+81', price: 730.18, countryId: 1001, flag: '🇯🇵' },
    { name: 'Gibraltar', code: '+350', price: 1609.61, countryId: 201, flag: '🇬🇮' },
    { name: 'Malaysia', code: '+60', price: 20.02, countryId: 7, flag: '🇲🇾' },
    { name: 'Ukraine', code: '+380', price: 8.37, countryId: 1, flag: '🇺🇦' },
    { name: 'France', code: '+33', price: 101.56, countryId: 78, flag: '🇫🇷' },
    { name: 'Denmark', code: '+45', price: 42.95, countryId: 172, flag: '🇩🇰' }
];

const emenuCountries = [];

const naimikzCountries = [];

const mycarkzCountries = [];

const aviatakzCountries = [];

const universalbeijingresortCountries = [];

const uzumCountries = [
    { name: 'Uzbekistan', code: '+998', price: 121.94, countryId: 40, flag: '🇺🇿' }
];

const cmbCountries = [
    { name: 'USA', code: '+1', price: 40.77, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 4.37, countryId: 12, flag: '🇺🇸' },
    { name: 'Netherlands', code: '+31', price: 10.19, countryId: 48, flag: '🇳🇱' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 42.95, countryId: 7, flag: '🇲🇾' }
];

const ipsosisayCountries = [
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' },
    { name: 'Ireland', code: '+353', price: 96.82, countryId: 23, flag: '🇮🇪' },
    { name: 'Poland', code: '+48', price: 3.28, countryId: 15, flag: '🇵🇱' },
    { name: 'Netherlands', code: '+31', price: 3.93, countryId: 48, flag: '🇳🇱' },
    { name: 'USA', code: '+1', price: 91, countryId: 187, flag: '🇺🇸' },
    { name: 'Ukraine', code: '+380', price: 82.63, countryId: 1, flag: '🇺🇦' },
    { name: 'France', code: '+33', price: 32.4, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 50.6, countryId: 43, flag: '🇩🇪' },
    { name: 'Canada', code: '+1', price: 25.48, countryId: 36, flag: '🇨🇦' },
    { name: 'Italy', code: '+39', price: 36.4, countryId: 86, flag: '🇮🇹' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const pinduoduoCountries = [
    { name: 'Malaysia', code: '+60', price: 2.18, countryId: 7, flag: '🇲🇾' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const bharatpeCountries = [
    { name: 'India', code: '+91', price: 20.02, countryId: 22, flag: '🇮🇳' }
];

const jiomartCountries = [];

const playerzpotCountries = [];

const tataneuCountries = [];

const winterloanCountries = [
    { name: 'India', code: '+91', price: 18.56, countryId: 22, flag: '🇮🇳' }
];

const collabactCountries = [];

const qwikcilverCountries = [];

const tatacliqpaletteCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const citymallCountries = [];

const a23Countries = [
    { name: 'India', code: '+91', price: 11.28, countryId: 22, flag: '🇮🇳' }
];

const poshvineCountries = [];

const marwadiCountries = [];

const frizzaCountries = [];

const zeptoCountries = [
    { name: 'India', code: '+91', price: 21.84, countryId: 22, flag: '🇮🇳' }
];

const rummycircleCountries = [
    { name: 'India', code: '+91', price: 19.66, countryId: 22, flag: '🇮🇳' }
];

const khatabookCountries = [];

const earneasyCountries = [];

const fitcreditCountries = [];

const bankkaroCountries = [
    { name: 'India', code: '+91', price: 34.22, countryId: 22, flag: '🇮🇳' }
];

const skcapitalCountries = [];

const roomsterCountries = [
    { name: 'Colombia', code: '+57', price: 17.11, countryId: 33, flag: '🇨🇴' },
    { name: 'India', code: '+91', price: 14.56, countryId: 22, flag: '🇮🇳' },
    { name: 'United Kingdom', code: '+44', price: 4, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 36.4, countryId: 7, flag: '🇲🇾' }
];

const servifyCountries = [];

const hdfcbankCountries = [];

const bajajfinservCountries = [
    { name: 'India', code: '+91', price: 33.12, countryId: 22, flag: '🇮🇳' }
];

const yonogamesCountries = [
    { name: 'India', code: '+91', price: 33.12, countryId: 22, flag: '🇮🇳' }
];

const angeloneCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'India', code: '+91', price: 18.56, countryId: 22, flag: '🇮🇳' }
];

const mockguruCountries = [];

const hingedatingCountries = [];

const kamateraCountries = [];

const tomatoCountries = [
    { name: 'Vietnam', code: '+84', price: 14.56, countryId: 10, flag: '🇻🇳' },
    { name: 'Indonesia', code: '+62', price: 9.83, countryId: 6, flag: '🇮🇩' }
];

const bearwwwCountries = [
    { name: 'France', code: '+33', price: 76.8, countryId: 78, flag: '🇫🇷' },
    { name: 'United Kingdom', code: '+44', price: 24.75, countryId: 16, flag: '🇬🇧' }
];

const anibisCountries = [
    { name: 'France', code: '+33', price: 3.64, countryId: 78, flag: '🇫🇷' }
];

const bunqCountries = [
    { name: 'Ukraine', code: '+380', price: 82.26, countryId: 1, flag: '🇺🇦' },
    { name: 'France', code: '+33', price: 65.16, countryId: 78, flag: '🇫🇷' },
    { name: 'United Kingdom', code: '+44', price: 4, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 18.56, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 5.46, countryId: 48, flag: '🇳🇱' }
];

const bebooCountries = [
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const namarsCountries = [
    { name: 'Netherlands', code: '+31', price: 24.75, countryId: 48, flag: '🇳🇱' },
    { name: 'Brazil', code: '+55', price: 18.56, countryId: 73, flag: '🇧🇷' },
    { name: 'Ukraine', code: '+380', price: 149.6, countryId: 1, flag: '🇺🇦' },
    { name: 'France', code: '+33', price: 94.28, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 37.86, countryId: 43, flag: '🇩🇪' },
    { name: 'Lithuania', code: '+370', price: 97.19, countryId: 44, flag: '🇱🇹' }
];

const radiumCountries = [];

const busyflyCountries = [];

const vfsglobalCountries = [
    { name: 'Poland', code: '+48', price: 48.03, countryId: 15, flag: '🇵🇱' },
    { name: 'India', code: '+91', price: 22.93, countryId: 22, flag: '🇮🇳' }
];

const broCountries = [];

const bitrueCountries = [
    { name: 'India', code: '+91', price: 31.3, countryId: 22, flag: '🇮🇳' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const kiaCountries = [];

const royalcaninCountries = [];

const ayabankCountries = [
    { name: 'Myanmar', code: '+95', price: 54.96, countryId: 5, flag: '🇲🇲' }
];

const neteaseCountries = [
    { name: 'Philippines', code: '+63', price: 12.74, countryId: 4, flag: '🇵🇭' },
    { name: 'Colombia', code: '+57', price: 21.18, countryId: 33, flag: '🇨🇴' },
    { name: 'Thailand', code: '+66', price: 37.49, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 30.58, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 21.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Chile', code: '+56', price: 2.18, countryId: 151, flag: '🇨🇱' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const rappiCountries = [
    { name: 'Colombia', code: '+57', price: 65.16, countryId: 33, flag: '🇨🇴' }
];

const cabifyCountries = [
    { name: 'Colombia', code: '+57', price: 41.86, countryId: 33, flag: '🇨🇴' }
];

const nequiCountries = [];

const ozanCountries = [
    { name: 'Turkey', code: '+90', price: 182.73, countryId: 62, flag: '🇹🇷' },
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' }
];

const fupsCountries = [
    { name: 'Turkey', code: '+90', price: 91.36, countryId: 62, flag: '🇹🇷' }
];

const playerauctionsCountries = [
    { name: 'Spain', code: '+34', price: 148.51, countryId: 56, flag: '🇪🇸' },
    { name: 'Netherlands', code: '+31', price: 9.83, countryId: 48, flag: '🇳🇱' },
    { name: 'Canada', code: '+1', price: 32.76, countryId: 36, flag: '🇨🇦' }
];

const chevronCountries = [];

const xxgameCountries = [
    { name: 'Thailand', code: '+66', price: 62.61, countryId: 52, flag: '🇹🇭' }
];

const alchemyCountries = [
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Thailand', code: '+66', price: 2.18, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' }
];

const boyaaCountries = [
    { name: 'Thailand', code: '+66', price: 10.18, countryId: 52, flag: '🇹🇭' },
    { name: 'Kosovo', code: '+383', price: 10.18, countryId: 1004, flag: '🇽🇰' }
];

const byteplusCountries = [
    { name: 'Chile', code: '+56', price: 8.74, countryId: 151, flag: '🇨🇱' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Thailand', code: '+66', price: 45.86, countryId: 52, flag: '🇹🇭' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const privyCountries = [
    { name: 'Thailand', code: '+66', price: 17.11, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Laos', code: '+856', price: 36.4, countryId: 25, flag: '🇱🇦' },
    { name: 'Malaysia', code: '+60', price: 18.56, countryId: 7, flag: '🇲🇾' }
];

const meituanCountries = [];

const pockitCountries = [];

const tiptappCountries = [];

const rocketreachCountries = [];

const taptapsendCountries = [
    { name: 'Estonia', code: '+372', price: 79.35, countryId: 34, flag: '🇪🇪' },
    { name: 'Czech Republic', code: '+420', price: 30.58, countryId: 63, flag: '🇨🇿' },
    { name: 'Latvia', code: '+371', price: 85.54, countryId: 49, flag: '🇱🇻' },
    { name: 'Croatia', code: '+385', price: 48.78, countryId: 45, flag: '🇭🇷' },
    { name: 'Denmark', code: '+45', price: 121.94, countryId: 172, flag: '🇩🇰' }
];

const foodoraCountries = [
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '+49', price: 5.1, countryId: 43, flag: '🇩🇪' },
    { name: 'Netherlands', code: '+31', price: 6.92, countryId: 48, flag: '🇳🇱' },
    { name: 'Japan', code: '+81', price: 1877.51, countryId: 1001, flag: '🇯🇵' },
    { name: 'Ukraine', code: '+380', price: 41.86, countryId: 1, flag: '🇺🇦' },
    { name: 'Malaysia', code: '+60', price: 30.58, countryId: 7, flag: '🇲🇾' },
    { name: 'Finland', code: '+358', price: 193.28, countryId: 163, flag: '🇫🇮' },
    { name: 'Denmark', code: '+45', price: 142.32, countryId: 172, flag: '🇩🇰' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const friendtechCountries = [];

const haleonCountries = [];

const airtimeCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const truthsocialCountries = [
    { name: 'Colombia', code: '+57', price: 2.18, countryId: 33, flag: '🇨🇴' },
    { name: 'Malaysia', code: '+60', price: 2.18, countryId: 7, flag: '🇲🇾' },
    { name: 'United Kingdom', code: '+44', price: 2.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Philippines', code: '+63', price: 2.18, countryId: 4, flag: '🇵🇭' },
    { name: 'Chile', code: '+56', price: 2.18, countryId: 151, flag: '🇨🇱' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const playojoCountries = [];

const jinjiangCountries = [
    { name: 'Eritrea', code: '+291', price: 2.18, countryId: 176, flag: '🇪🇷' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Iceland', code: '+354', price: 2.18, countryId: 132, flag: '🇮🇸' },
    { name: 'Macau', code: '+853', price: 2.18, countryId: 20, flag: '🇲🇴' },
    { name: 'Australia', code: '', price: 2.18, countryId: 175, flag: '🇦🇺' },
    { name: 'Seychelles', code: '+248', price: 2.18, countryId: 184, flag: '🇸🇨' },
    { name: 'Denmark', code: '+45', price: 2.18, countryId: 172, flag: '🇩🇰' },
    { name: 'Lebanon', code: '+961', price: 2.18, countryId: 153, flag: '🇱🇧' },
    { name: 'Mongolia', code: '+976', price: 2.18, countryId: 72, flag: '🇲🇳' },
    { name: 'New Zealand', code: '+64', price: 2.18, countryId: 67, flag: '🇳🇿' },
    { name: 'Macedonia', code: '+389', price: 63.34, countryId: 183, flag: '🇲🇰' },
    { name: 'Belize', code: '+501', price: 2.18, countryId: 124, flag: '🇧🇿' },
    { name: 'Monaco', code: '+377', price: 63.34, countryId: 144, flag: '🇲🇨' },
    { name: 'Croatia', code: '+385', price: 2.18, countryId: 45, flag: '🇭🇷' },
    { name: 'Cape Verde', code: '+238', price: 2.18, countryId: 186, flag: '🇨🇻' },
    { name: 'Fiji', code: '+679', price: 2.18, countryId: 189, flag: '🇫🇯' },
    { name: 'Slovakia', code: '+421', price: 2.18, countryId: 141, flag: '🇸🇰' },
    { name: 'Sao Tome and Principe', code: '+239', price: 2.18, countryId: 178, flag: '🇸🇹' },
    { name: 'Singapore', code: '+65', price: 50.23, countryId: 196, flag: '🇸🇬' },
    { name: 'Comoros', code: '+269', price: 2.18, countryId: 133, flag: '🇰🇲' },
    { name: 'Guinea', code: '+224', price: 0.22, countryId: 68, flag: '🇬🇳' },
    { name: 'Aruba', code: '+297', price: 0.22, countryId: 179, flag: '🇦🇼' },
    { name: 'Liberia', code: '+231', price: 2.18, countryId: 135, flag: '🇱🇷' },
    { name: 'Lithuania', code: '+370', price: 2.18, countryId: 44, flag: '🇱🇹' },
    { name: 'CAF', code: '+236', price: 2.18, countryId: 125, flag: '🇨🇫' },
    { name: 'Saint Kitts and Nevis', code: '+1', price: 2.18, countryId: 134, flag: '🇰🇳' },
    { name: 'Slovenia', code: '+386', price: 2.18, countryId: 59, flag: '🇸🇮' },
    { name: 'Albania', code: '+355', price: 2.18, countryId: 155, flag: '🇦🇱' },
    { name: 'Bahamas', code: '+1', price: 2.18, countryId: 122, flag: '🇧🇸' },
    { name: 'Bahrain', code: '+973', price: 2.18, countryId: 145, flag: '🇧🇭' },
    { name: 'Bolivia', code: '+591', price: 2.18, countryId: 92, flag: '🇧🇴' },
    { name: 'Bulgaria', code: '+359', price: 2.18, countryId: 83, flag: '🇧🇬' },
    { name: 'Cuba', code: '+53', price: 2.18, countryId: 113, flag: '🇨🇺' },
    { name: 'Cyprus', code: '+357', price: 2.18, countryId: 77, flag: '🇨🇾' },
    { name: 'Czech Republic', code: '+420', price: 2.18, countryId: 63, flag: '🇨🇿' },
    { name: 'Estonia', code: '+372', price: 2.18, countryId: 34, flag: '🇪🇪' },
    { name: 'Georgia', code: '+995', price: 2.18, countryId: 128, flag: '🇬🇪' },
    { name: 'Greece', code: '+30', price: 2.18, countryId: 129, flag: '🇬🇷' },
    { name: 'Grenada', code: '+1', price: 2.18, countryId: 127, flag: '🇬🇩' },
    { name: 'Guadeloupe', code: '+590', price: 2.18, countryId: 160, flag: '🇬🇵' },
    { name: 'Guatemala', code: '+502', price: 2.18, countryId: 94, flag: '🇬🇹' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Ireland', code: '+353', price: 2.18, countryId: 23, flag: '🇮🇪' },
    { name: 'Latvia', code: '+371', price: 2.18, countryId: 49, flag: '🇱🇻' },
    { name: 'Luxembourg', code: '+352', price: 2.18, countryId: 165, flag: '🇱🇺' },
    { name: 'Madagascar', code: '+261', price: 2.18, countryId: 17, flag: '🇲🇬' },
    { name: 'Montenegro', code: '+382', price: 2.18, countryId: 171, flag: '🇲🇪' },
    { name: 'Serbia', code: '+381', price: 2.18, countryId: 29, flag: '🇷🇸' },
    { name: 'Sierra Leone', code: '+232', price: 2.18, countryId: 115, flag: '🇸🇱' },
    { name: 'Suriname', code: '+597', price: 2.18, countryId: 142, flag: '🇸🇷' },
    { name: 'Sweden', code: '+46', price: 2.18, countryId: 46, flag: '🇸🇪' },
    { name: 'Tajikistan', code: '+992', price: 2.18, countryId: 143, flag: '🇹🇯' },
    { name: 'Switzerland', code: '+41', price: 63.34, countryId: 173, flag: '🇨🇭' },
    { name: 'Armenia', code: '+374', price: 2.18, countryId: 148, flag: '🇦🇲' },
    { name: 'Somalia', code: '+252', price: 2.18, countryId: 149, flag: '🇸🇴' },
    { name: 'Dominican Republic', code: '+1', price: 2.18, countryId: 109, flag: '🇩🇴' },
    { name: 'Portugal', code: '+351', price: 2.18, countryId: 117, flag: '🇵🇹' },
    { name: 'Maldives', code: '+960', price: 2.18, countryId: 159, flag: '🇲🇻' },
    { name: 'Guinea-Bissau', code: '+245', price: 2.18, countryId: 130, flag: '🇬🇼' },
    { name: 'China', code: '+86', price: 6.99, countryId: 3, flag: '🇨🇳' },
    { name: 'Kuwait', code: '+965', price: 2.18, countryId: 100, flag: '🇰🇼' },
    { name: 'Philippines', code: '+63', price: 0.22, countryId: 4, flag: '🇵🇭' },
    { name: 'South Sudan', code: '+211', price: 2.18, countryId: 177, flag: '🇸🇸' },
    { name: 'Mauritius', code: '+230', price: 2.18, countryId: 157, flag: '🇲🇺' },
    { name: 'UAE', code: '+971', price: 2.18, countryId: 95, flag: '🇦🇪' },
    { name: 'Trinidad and Tobago', code: '+1', price: 2.18, countryId: 104, flag: '🇹🇹' },
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Syria', code: '+963', price: 1.46, countryId: 1333, flag: '🇸🇾' },
    { name: 'Burundi', code: '+257', price: 0.29, countryId: 119, flag: '🇧🇮' },
    { name: 'Togo', code: '+228', price: 2.18, countryId: 99, flag: '🇹🇬' },
    { name: 'Niger', code: '+227', price: 2.18, countryId: 139, flag: '🇳🇪' },
    { name: 'Poland', code: '+48', price: 2.91, countryId: 15, flag: '🇵🇱' },
    { name: 'Laos', code: '+856', price: 0.22, countryId: 25, flag: '🇱🇦' },
    { name: 'Senegal', code: '+221', price: 2.18, countryId: 61, flag: '🇸🇳' },
    { name: 'Uruguay', code: '+598', price: 2.18, countryId: 156, flag: '🇺🇾' },
    { name: 'Iraq', code: '+964', price: 2.18, countryId: 47, flag: '🇮🇶' },
    { name: 'Yemen', code: '+967', price: 2.18, countryId: 30, flag: '🇾🇪' },
    { name: 'Oman', code: '+968', price: 2.18, countryId: 107, flag: '🇴🇲' },
    { name: 'Congo', code: '+242', price: 2.18, countryId: 150, flag: '🇨🇬' },
    { name: 'Belgium', code: '+32', price: 2.18, countryId: 82, flag: '🇧🇪' },
    { name: 'Costa Rica', code: '+506', price: 2.18, countryId: 93, flag: '🇨🇷' },
    { name: 'Burkina Faso', code: '+226', price: 2.18, countryId: 152, flag: '🇧🇫' },
    { name: 'Qatar', code: '+974', price: 2.18, countryId: 111, flag: '🇶🇦' },
    { name: 'Benin', code: '+229', price: 2.18, countryId: 120, flag: '🇧🇯' },
    { name: 'Nicaragua', code: '+505', price: 2.18, countryId: 90, flag: '🇳🇮' },
    { name: 'Moldova', code: '+373', price: 2.18, countryId: 85, flag: '🇲🇩' },
    { name: 'Gabon', code: '+241', price: 2.18, countryId: 154, flag: '🇬🇦' },
    { name: 'Sudan', code: '+249', price: 69.89, countryId: 1010, flag: '🇸🇩' },
    { name: 'Rwanda', code: '+250', price: 2.18, countryId: 140, flag: '🇷🇼' },
    { name: 'Mali', code: '+223', price: 2.18, countryId: 69, flag: '🇲🇱' },
    { name: 'Turkmenistan', code: '+993', price: 2.18, countryId: 161, flag: '🇹🇲' },
    { name: 'Azerbaijan', code: '+994', price: 2.18, countryId: 35, flag: '🇦🇿' },
    { name: 'Libya', code: '+218', price: 2.18, countryId: 102, flag: '🇱🇾' },
    { name: 'Belarus', code: '+375', price: 2.18, countryId: 51, flag: '🇧🇾' },
    { name: 'Israel', code: '', price: 2.18, countryId: 13, flag: '🇮🇱' },
    { name: 'Ivory Coast', code: '+225', price: 2.18, countryId: 27, flag: '🇨🇮' },
    { name: 'Cameroon', code: '+237', price: 2.18, countryId: 41, flag: '🇨🇲' },
    { name: 'Kyrgyzstan', code: '+996', price: 0.29, countryId: 11, flag: '🇰🇬' },
    { name: 'Jordan', code: '+962', price: 2.18, countryId: 116, flag: '🇯🇴' },
    { name: 'Paraguay', code: '+595', price: 2.91, countryId: 87, flag: '🇵🇾' },
    { name: 'Colombia', code: '+57', price: 2.18, countryId: 33, flag: '🇨🇴' },
    { name: 'Kazakhstan', code: '+7', price: 2.18, countryId: 2, flag: '🇰🇿' },
    { name: 'Venezuela', code: '+58', price: 2.18, countryId: 70, flag: '🇻🇪' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Botswana', code: '+267', price: 2.18, countryId: 123, flag: '🇧🇼' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 2.18, countryId: 18, flag: '🇨🇩' },
    { name: 'Ecuador', code: '+593', price: 2.18, countryId: 105, flag: '🇪🇨' },
    { name: 'El Salvador', code: '+503', price: 2.18, countryId: 101, flag: '🇸🇻' },
    { name: 'Ghana', code: '+233', price: 2.18, countryId: 38, flag: '🇬🇭' },
    { name: 'Honduras', code: '+504', price: 2.18, countryId: 88, flag: '🇭🇳' },
    { name: 'Jamaica', code: '+1', price: 2.18, countryId: 103, flag: '🇯🇲' },
    { name: 'Kenya', code: '+254', price: 2.18, countryId: 8, flag: '🇰🇪' },
    { name: 'Lesotho', code: '+266', price: 2.18, countryId: 136, flag: '🇱🇸' },
    { name: 'Malawi', code: '+265', price: 2.18, countryId: 137, flag: '🇲🇼' },
    { name: 'Morocco', code: '+212', price: 2.18, countryId: 37, flag: '🇲🇦' },
    { name: 'Nepal', code: '+977', price: 2.18, countryId: 81, flag: '🇳🇵' },
    { name: 'Panama', code: '+507', price: 2.18, countryId: 112, flag: '🇵🇦' },
    { name: 'Peru', code: '+51', price: 2.18, countryId: 65, flag: '🇵🇪' },
    { name: 'Sri Lanka', code: '+94', price: 2.18, countryId: 64, flag: '🇱🇰' },
    { name: 'Swaziland', code: '+268', price: 2.18, countryId: 106, flag: '🇸🇿' },
    { name: 'Tanzania', code: '+255', price: 2.18, countryId: 9, flag: '🇹🇿' },
    { name: 'Timor-Leste', code: '+670', price: 2.18, countryId: 91, flag: '🇹🇱' },
    { name: 'Tunisia', code: '+216', price: 2.18, countryId: 89, flag: '🇹🇳' },
    { name: 'Uganda', code: '+256', price: 2.18, countryId: 75, flag: '🇺🇬' },
    { name: 'Uzbekistan', code: '+998', price: 2.18, countryId: 40, flag: '🇺🇿' },
    { name: 'Zimbabwe', code: '+263', price: 2.18, countryId: 96, flag: '🇿🇼' },
    { name: 'Algeria', code: '+213', price: 2.18, countryId: 58, flag: '🇩🇿' },
    { name: 'Angola', code: '+244', price: 2.18, countryId: 76, flag: '🇦🇴' },
    { name: 'Austria', code: '+43', price: 35.67, countryId: 50, flag: '🇦🇹' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Cambodia', code: '+855', price: 2.91, countryId: 24, flag: '🇰🇭' },
    { name: 'Canada', code: '+1', price: 2.18, countryId: 36, flag: '🇨🇦' },
    { name: 'Egypt', code: '+20', price: 2.18, countryId: 21, flag: '🇪🇬' },
    { name: 'Ethiopia', code: '+251', price: 2.18, countryId: 71, flag: '🇪🇹' },
    { name: 'Finland', code: '+358', price: 35.67, countryId: 163, flag: '🇫🇮' },
    { name: 'Germany', code: '+49', price: 24.75, countryId: 43, flag: '🇩🇪' },
    { name: 'Haiti', code: '+509', price: 2.18, countryId: 26, flag: '🇭🇹' },
    { name: 'Hong Kong', code: '+852', price: 2.18, countryId: 14, flag: '🇭🇰' },
    { name: 'Hungary', code: '+36', price: 35.67, countryId: 84, flag: '🇭🇺' },
    { name: 'India', code: '+91', price: 2.91, countryId: 22, flag: '🇮🇳' },
    { name: 'Iran', code: '+98', price: 2.91, countryId: 57, flag: '🇮🇷' },
    { name: 'Japan', code: '+81', price: 35.67, countryId: 1001, flag: '🇯🇵' },
    { name: 'Malaysia', code: '+60', price: 2.18, countryId: 7, flag: '🇲🇾' },
    { name: 'Mexico', code: '+52', price: 35.67, countryId: 54, flag: '🇲🇽' },
    { name: 'Mozambique', code: '+258', price: 2.18, countryId: 80, flag: '🇲🇿' },
    { name: 'Namibia', code: '+264', price: 2.18, countryId: 138, flag: '🇳🇦' },
    { name: 'Nigeria', code: '+234', price: 35.67, countryId: 19, flag: '🇳🇬' },
    { name: 'Norway', code: '+47', price: 3.57, countryId: 174, flag: '🇳🇴' },
    { name: 'Pakistan', code: '+92', price: 35.67, countryId: 66, flag: '🇵🇰' },
    { name: 'Papua new gvineya', code: '+675', price: 2.18, countryId: 79, flag: '🇵🇬' },
    { name: 'Romania', code: '+40', price: 1.46, countryId: 32, flag: '🇷🇴' },
    { name: 'Saudi Arabia', code: '+966', price: 35.67, countryId: 53, flag: '🇸🇦' },
    { name: 'South Africa', code: '+27', price: 2.18, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '+34', price: 2.18, countryId: 56, flag: '🇪🇸' },
    { name: 'Taiwan', code: '+886', price: 35.67, countryId: 55, flag: '🇹🇼' },
    { name: 'Thailand', code: '+66', price: 2.18, countryId: 52, flag: '🇹🇭' },
    { name: 'Turkey', code: '+90', price: 35.67, countryId: 62, flag: '🇹🇷' },
    { name: 'USA', code: '+1', price: 35.67, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 3.64, countryId: 12, flag: '🇺🇸' },
    { name: 'Ukraine', code: '+380', price: 2.18, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Zambia', code: '+260', price: 2.18, countryId: 147, flag: '🇿🇲' }
];

const neocryptoCountries = [
    { name: 'USA', code: '+1', price: 87.36, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const tuulCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const klarnaCountries = [
    { name: 'Germany', code: '+49', price: 5.1, countryId: 43, flag: '🇩🇪' },
    { name: 'Netherlands', code: '+31', price: 12.38, countryId: 48, flag: '🇳🇱' },
    { name: 'USA', code: '+1', price: 121.58, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 4, countryId: 16, flag: '🇬🇧' }
];

const vimpayCountries = [
    { name: 'Germany', code: '+49', price: 80.08, countryId: 43, flag: '🇩🇪' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const grailedCountries = [];

const mtrmobileCountries = [];

const meituCountries = [];

const oneformaCountries = [
    { name: 'USA', code: '+1', price: 48.78, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 3.64, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 16.38, countryId: 48, flag: '🇳🇱' }
];

const abbottCountries = [
    { name: 'India', code: '+91', price: 11.28, countryId: 22, flag: '🇮🇳' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Italy', code: '+39', price: 187.1, countryId: 86, flag: '🇮🇹' }
];

const gmxCountries = [
    { name: 'Germany', code: '+49', price: 72.8, countryId: 43, flag: '🇩🇪' },
    { name: 'Netherlands', code: '+31', price: 2.55, countryId: 48, flag: '🇳🇱' },
    { name: 'Denmark', code: '+45', price: 6.55, countryId: 172, flag: '🇩🇰' },
    { name: 'Malaysia', code: '+60', price: 30.58, countryId: 7, flag: '🇲🇾' },
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'India', code: '+91', price: 4, countryId: 22, flag: '🇮🇳' },
    { name: 'Ukraine', code: '+380', price: 4, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 2.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Poland', code: '+48', price: 8.37, countryId: 15, flag: '🇵🇱' },
    { name: 'Estonia', code: '+372', price: 6.55, countryId: 34, flag: '🇪🇪' },
    { name: 'Croatia', code: '+385', price: 4, countryId: 45, flag: '🇭🇷' }
];

const webdeCountries = [
    { name: 'Germany', code: '+49', price: 54.96, countryId: 43, flag: '🇩🇪' }
];

const stratoCountries = [
    { name: 'Germany', code: '+49', price: 42.95, countryId: 43, flag: '🇩🇪' }
];

const oneandoneCountries = [
    { name: 'Germany', code: '+49', price: 50.96, countryId: 43, flag: '🇩🇪' }
];

const surveybellCountries = [
    { name: 'Germany', code: '+49', price: 41.86, countryId: 43, flag: '🇩🇪' }
];

const checkdomainCountries = [];

const arlensCountries = [
    { name: 'Malaysia', code: '+60', price: 18.56, countryId: 7, flag: '🇲🇾' }
];

const bonuslinkCountries = [
    { name: 'Malaysia', code: '+60', price: 24.02, countryId: 7, flag: '🇲🇾' }
];

const suntecCountries = [];

const gopayzCountries = [];

const tanotiCountries = [];

const maybankCountries = [];

const myboostCountries = [];

const meiqfashionCountries = [];

const fugeelahCountries = [];

const k11Countries = [];

const strivinginthelioncityCountries = [];

const marktplaatsCountries = [];

const primeopinionCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '+49', price: 53.14, countryId: 43, flag: '🇩🇪' },
    { name: 'Netherlands', code: '+31', price: 8.74, countryId: 48, flag: '🇳🇱' }
];

const arenaplusCountries = [
    { name: 'Philippines', code: '+63', price: 47.68, countryId: 4, flag: '🇵🇭' }
];

const willhabenCountries = [
    { name: 'Germany', code: '+49', price: 5.1, countryId: 43, flag: '🇩🇪' },
    { name: 'Estonia', code: '+372', price: 109.93, countryId: 34, flag: '🇪🇪' }
];

const openphoneCountries = [];

const seznamCountries = [
    { name: 'Czech Republic', code: '+420', price: 70.98, countryId: 63, flag: '🇨🇿' }
];

const packetaCountries = [];

const publi24Countries = [];

const betanoCountries = [
    { name: 'Japan', code: '+81', price: 1073.07, countryId: 1001, flag: '🇯🇵' },
    { name: 'Romania', code: '+40', price: 32.4, countryId: 32, flag: '🇷🇴' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const zasilkovnaCountries = [
    { name: 'Romania', code: '+40', price: 29.85, countryId: 32, flag: '🇷🇴' }
];

const bpjstkCountries = [
    { name: 'Kosovo', code: '+383', price: 32.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Indonesia', code: '+62', price: 13.55, countryId: 6, flag: '🇮🇩' }
];

const bcasyariahCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const cloudmanagerCountries = [
    { name: 'Chile', code: '+56', price: 11.46, countryId: 151, flag: '🇨🇱' },
    { name: 'Indonesia', code: '+62', price: 13.46, countryId: 6, flag: '🇮🇩' },
    { name: 'India', code: '+91', price: 22.93, countryId: 22, flag: '🇮🇳' },
    { name: 'United Kingdom', code: '+44', price: 15.1, countryId: 16, flag: '🇬🇧' }
];

const astrapayCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const redigameCountries = [];

const allofreshCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const onbukaCountries = [];

const godrejCountries = [];

const greywoodsCountries = [];

const theforkCountries = [
    { name: 'United Kingdom', code: '+44', price: 3.64, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '+49', price: 47.68, countryId: 43, flag: '🇩🇪' },
    { name: 'Indonesia', code: '+62', price: 2.55, countryId: 6, flag: '🇮🇩' }
];

const flipCountries = [];

const neonCountries = [];

const bundaCountries = [
    { name: 'Indonesia', code: '+62', price: 13.46, countryId: 6, flag: '🇮🇩' }
];

const astraotoshopCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const gamesofaCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Malaysia', code: '+60', price: 36.4, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 9.83, countryId: 48, flag: '🇳🇱' }
];

const flikCountries = [];

const jivapetaniCountries = [];

const ubisoftCountries = [
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Malaysia', code: '+60', price: 2.18, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 14.2, countryId: 48, flag: '🇳🇱' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const uangmeCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const pizzahutCountries = [];

const seedsCountries = [];

const afreecatvCountries = [
    { name: 'Malaysia', code: '+60', price: 45.86, countryId: 7, flag: '🇲🇾' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const tiptipCountries = [];

const schibstedCountries = [
    { name: 'Japan', code: '+81', price: 1073.07, countryId: 1001, flag: '🇯🇵' }
];

const feetfinderCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Estonia', code: '+372', price: 152.15, countryId: 34, flag: '🇪🇪' },
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' }
];

const luckylandslotsCountries = [];

const dakiCountries = [];

const baiheCountries = [
    { name: 'Hong Kong', code: '+852', price: 397.49, countryId: 14, flag: '🇭🇰' }
];

const thisfateCountries = [
    { name: 'Hong Kong', code: '+852', price: 461.19, countryId: 14, flag: '🇭🇰' }
];

const njuskaloCountries = [
    { name: 'Croatia', code: '+385', price: 98.64, countryId: 45, flag: '🇭🇷' }
];

const cocacolaCountries = [
    { name: 'USA', code: '+1', price: 23.3, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 26.21, countryId: 12, flag: '🇺🇸' }
];

const kachingCountries = [];

const couponscomCountries = [];

const sparkdriverCountries = [];

const tivCountries = [];

const razerCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 30.58, countryId: 7, flag: '🇲🇾' },
    { name: 'USA Virtual', code: '+1', price: 4.37, countryId: 12, flag: '🇺🇸' }
];

const zachbryanCountries = [
    { name: 'USA Virtual', code: '+1', price: 4.37, countryId: 12, flag: '🇺🇸' }
];

const smartypigCountries = [];

const fliffCountries = [];

const spacewebCountries = [];

const nlotoCountries = [];

const brevoCountries = [
    { name: 'USA', code: '+1', price: 82.99, countryId: 187, flag: '🇺🇸' },
    { name: 'Germany', code: '+49', price: 55.33, countryId: 43, flag: '🇩🇪' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const av100proCountries = [];

const ollisCountries = [];

const bankeraCountries = [
    { name: 'Spain', code: '+34', price: 143.78, countryId: 56, flag: '🇪🇸' },
    { name: 'Estonia', code: '+372', price: 152.15, countryId: 34, flag: '🇪🇪' }
];

const g2aCountries = [
    { name: 'USA', code: '+1', price: 110.66, countryId: 187, flag: '🇺🇸' }
];

const cupidmediaCountries = [];

const ipanelonlineCountries = [];

const fortumoCountries = [];

const waugCountries = [
    { name: 'Thailand', code: '+66', price: 45.86, countryId: 52, flag: '🇹🇭' }
];

const rebtelCountries = [
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'France', code: '+33', price: 22.93, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 6.92, countryId: 43, flag: '🇩🇪' },
    { name: 'USA', code: '+1', price: 54.96, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 2.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Italy', code: '+39', price: 22.57, countryId: 86, flag: '🇮🇹' },
    { name: 'Kenya', code: '+254', price: 27.66, countryId: 8, flag: '🇰🇪' },
    { name: 'Spain', code: '+34', price: 43.32, countryId: 56, flag: '🇪🇸' },
    { name: 'Czech Republic', code: '+420', price: 22.93, countryId: 63, flag: '🇨🇿' },
    { name: 'Canada', code: '+1', price: 8.37, countryId: 36, flag: '🇨🇦' },
    { name: 'Romania', code: '+40', price: 28.39, countryId: 32, flag: '🇷🇴' },
    { name: 'India', code: '+91', price: 29.12, countryId: 22, flag: '🇮🇳' },
    { name: 'Ethiopia', code: '+251', price: 29.12, countryId: 71, flag: '🇪🇹' },
    { name: 'Egypt', code: '+20', price: 29.12, countryId: 21, flag: '🇪🇬' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Vietnam', code: '+84', price: 21.84, countryId: 10, flag: '🇻🇳' },
    { name: 'Zimbabwe', code: '+263', price: 29.12, countryId: 96, flag: '🇿🇼' },
    { name: 'Nigeria', code: '+234', price: 29.12, countryId: 19, flag: '🇳🇬' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 29.12, countryId: 18, flag: '🇨🇩' },
    { name: 'Botswana', code: '+267', price: 29.12, countryId: 123, flag: '🇧🇼' },
    { name: 'Mexico', code: '+52', price: 29.12, countryId: 54, flag: '🇲🇽' },
    { name: 'Honduras', code: '+504', price: 29.12, countryId: 88, flag: '🇭🇳' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Tunisia', code: '+216', price: 29.12, countryId: 89, flag: '🇹🇳' },
    { name: 'Timor-Leste', code: '+670', price: 29.12, countryId: 91, flag: '🇹🇱' },
    { name: 'Uganda', code: '+256', price: 29.12, countryId: 75, flag: '🇺🇬' },
    { name: 'Venezuela', code: '+58', price: 30.58, countryId: 70, flag: '🇻🇪' },
    { name: 'Kazakhstan', code: '+7', price: 29.12, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 20.02, countryId: 33, flag: '🇨🇴' },
    { name: 'Paraguay', code: '+595', price: 29.12, countryId: 87, flag: '🇵🇾' },
    { name: 'Turkey', code: '+90', price: 29.12, countryId: 62, flag: '🇹🇷' },
    { name: 'Cameroon', code: '+237', price: 8.74, countryId: 41, flag: '🇨🇲' },
    { name: 'Belarus', code: '+375', price: 29.12, countryId: 51, flag: '🇧🇾' },
    { name: 'Bulgaria', code: '+359', price: 30.58, countryId: 83, flag: '🇧🇬' },
    { name: 'Moldova', code: '+373', price: 29.12, countryId: 85, flag: '🇲🇩' },
    { name: 'Saudi Arabia', code: '+966', price: 1.46, countryId: 53, flag: '🇸🇦' },
    { name: 'Thailand', code: '+66', price: 29.12, countryId: 52, flag: '🇹🇭' },
    { name: 'Burkina Faso', code: '+226', price: 29.12, countryId: 152, flag: '🇧🇫' },
    { name: 'Belgium', code: '+32', price: 22.93, countryId: 82, flag: '🇧🇪' },
    { name: 'Yemen', code: '+967', price: 20.38, countryId: 30, flag: '🇾🇪' },
    { name: 'Laos', code: '+856', price: 29.12, countryId: 25, flag: '🇱🇦' },
    { name: 'Poland', code: '+48', price: 21.84, countryId: 15, flag: '🇵🇱' },
    { name: 'Malaysia', code: '+60', price: 48.78, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 13.83, countryId: 48, flag: '🇳🇱' },
    { name: 'UAE', code: '+971', price: 29.12, countryId: 95, flag: '🇦🇪' },
    { name: 'Portugal', code: '+351', price: 29.12, countryId: 117, flag: '🇵🇹' },
    { name: 'Switzerland', code: '+41', price: 22.93, countryId: 173, flag: '🇨🇭' },
    { name: 'Ireland', code: '+353', price: 21.48, countryId: 23, flag: '🇮🇪' },
    { name: 'Estonia', code: '+372', price: 30.58, countryId: 34, flag: '🇪🇪' },
    { name: 'Sweden', code: '+46', price: 18.93, countryId: 46, flag: '🇸🇪' },
    { name: 'Greece', code: '+30', price: 28.76, countryId: 129, flag: '🇬🇷' },
    { name: 'Chile', code: '+56', price: 45.86, countryId: 151, flag: '🇨🇱' },
    { name: 'Sierra Leone', code: '+232', price: 27.66, countryId: 115, flag: '🇸🇱' },
    { name: 'Slovenia', code: '+386', price: 21.84, countryId: 59, flag: '🇸🇮' },
    { name: 'Liberia', code: '+231', price: 29.12, countryId: 135, flag: '🇱🇷' },
    { name: 'Singapore', code: '+65', price: 29.12, countryId: 196, flag: '🇸🇬' },
    { name: 'New Zealand', code: '+64', price: 30.58, countryId: 67, flag: '🇳🇿' },
    { name: 'Mongolia', code: '+976', price: 29.12, countryId: 72, flag: '🇲🇳' },
    { name: 'Denmark', code: '+45', price: 30.58, countryId: 172, flag: '🇩🇰' },
    { name: 'Australia', code: '', price: 30.21, countryId: 175, flag: '🇦🇺' },
    { name: 'USA Virtual', code: '+1', price: 22.93, countryId: 12, flag: '🇺🇸' }
];

const gener8Countries = [];

const gopuffCountries = [];

const feelsCountries = [];

const zuscoffeeCountries = [
    { name: 'Malaysia', code: '+60', price: 23.3, countryId: 7, flag: '🇲🇾' }
];

const zoogameCountries = [
    { name: 'Malaysia', code: '+60', price: 28.76, countryId: 7, flag: '🇲🇾' }
];

const coffeeteaCountries = [];

const moveitCountries = [];

const prakerjaCountries = [];

const ventenyCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const asiamilesCountries = [
    { name: 'Thailand', code: '+66', price: 45.86, countryId: 52, flag: '🇹🇭' }
];

const myvalueCountries = [];

const bokuCountries = [
    { name: 'Indonesia', code: '+62', price: 4.46, countryId: 6, flag: '🇮🇩' }
];

const getplusCountries = [];

const dayaautoCountries = [];

const sharepartyCountries = [];

const indobaCountries = [];

const kemnakerriCountries = [];

const allaccessCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const motionpayCountries = [];

const linkajaCountries = [];

const leroymerlinCountries = [];

const bookmyplayCountries = [
    { name: 'India', code: '+91', price: 36.4, countryId: 22, flag: '🇮🇳' }
];

const windsCountries = [
    { name: 'India', code: '+91', price: 36.4, countryId: 22, flag: '🇮🇳' }
];

const rydeCountries = [];

const herCountries = [];

const blankstreetCountries = [
    { name: 'United Kingdom', code: '+44', price: 11.83, countryId: 16, flag: '🇬🇧' }
];

const voiCountries = [
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'Germany', code: '+49', price: 53.87, countryId: 43, flag: '🇩🇪' },
    { name: 'Denmark', code: '+45', price: 146.33, countryId: 172, flag: '🇩🇰' }
];

const sonylivCountries = [];

const hanyaCountries = [];

const prenagenclubCountries = [];

const tiketcomCountries = [
    { name: 'USA', code: '+1', price: 42.22, countryId: 187, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 9.83, countryId: 36, flag: '🇨🇦' },
    { name: 'United Kingdom', code: '+44', price: 37.86, countryId: 16, flag: '🇬🇧' },
    { name: 'Netherlands', code: '+31', price: 19.66, countryId: 48, flag: '🇳🇱' },
    { name: 'Chile', code: '+56', price: 18.93, countryId: 151, flag: '🇨🇱' },
    { name: 'Portugal', code: '+351', price: 28.76, countryId: 117, flag: '🇵🇹' },
    { name: 'Poland', code: '+48', price: 8.37, countryId: 15, flag: '🇵🇱' },
    { name: 'Greece', code: '+30', price: 19.66, countryId: 129, flag: '🇬🇷' },
    { name: 'USA Virtual', code: '+1', price: 3.64, countryId: 12, flag: '🇺🇸' },
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' },
    { name: 'Austria', code: '+43', price: 131.77, countryId: 50, flag: '🇦🇹' },
    { name: 'Denmark', code: '+45', price: 48.78, countryId: 172, flag: '🇩🇰' },
    { name: 'Germany', code: '+49', price: 59.7, countryId: 43, flag: '🇩🇪' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Spain', code: '+34', price: 29.12, countryId: 56, flag: '🇪🇸' },
    { name: 'Finland', code: '+358', price: 49.5, countryId: 163, flag: '🇫🇮' },
    { name: 'Italy', code: '+39', price: 19.66, countryId: 86, flag: '🇮🇹' },
    { name: 'Romania', code: '+40', price: 19.66, countryId: 32, flag: '🇷🇴' },
    { name: 'Malaysia', code: '+60', price: 42.22, countryId: 7, flag: '🇲🇾' },
    { name: 'France', code: '+33', price: 19.66, countryId: 78, flag: '🇫🇷' },
    { name: 'Kenya', code: '+254', price: 24.02, countryId: 8, flag: '🇰🇪' },
    { name: 'Kazakhstan', code: '+7', price: 18.56, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 12.38, countryId: 33, flag: '🇨🇴' },
    { name: 'Belarus', code: '+375', price: 164.16, countryId: 51, flag: '🇧🇾' },
    { name: 'Bulgaria', code: '+359', price: 19.66, countryId: 83, flag: '🇧🇬' },
    { name: 'Azerbaijan', code: '+994', price: 33.12, countryId: 35, flag: '🇦🇿' },
    { name: 'Moldova', code: '+373', price: 18.2, countryId: 85, flag: '🇲🇩' },
    { name: 'Thailand', code: '+66', price: 56.78, countryId: 52, flag: '🇹🇭' },
    { name: 'China', code: '+86', price: 64.43, countryId: 3, flag: '🇨🇳' },
    { name: 'Armenia', code: '+374', price: 33.12, countryId: 148, flag: '🇦🇲' },
    { name: 'Ireland', code: '+353', price: 19.66, countryId: 23, flag: '🇮🇪' },
    { name: 'Serbia', code: '+381', price: 19.66, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 48.78, countryId: 34, flag: '🇪🇪' },
    { name: 'Czech Republic', code: '+420', price: 23.3, countryId: 63, flag: '🇨🇿' },
    { name: 'Georgia', code: '+995', price: 28.39, countryId: 128, flag: '🇬🇪' },
    { name: 'Latvia', code: '+371', price: 57.51, countryId: 49, flag: '🇱🇻' },
    { name: 'Slovenia', code: '+386', price: 33.85, countryId: 59, flag: '🇸🇮' },
    { name: 'Lithuania', code: '+370', price: 48.78, countryId: 44, flag: '🇱🇹' },
    { name: 'Japan', code: '+81', price: 747.93, countryId: 1001, flag: '🇯🇵' },
    { name: 'Croatia', code: '+385', price: 37.49, countryId: 45, flag: '🇭🇷' },
    { name: 'New Zealand', code: '+64', price: 199.47, countryId: 67, flag: '🇳🇿' },
    { name: 'Australia', code: '', price: 206.39, countryId: 175, flag: '🇦🇺' },
    { name: 'Gibraltar', code: '+350', price: 219.13, countryId: 201, flag: '🇬🇮' }
];

const easycashCountries = [];

const daganganCountries = [];

const dokuCountries = [];

const lottemartCountries = [];

const chakrarewardsCountries = [
    { name: 'Indonesia', code: '+62', price: 11.46, countryId: 6, flag: '🇮🇩' }
];

const xworldwalletCountries = [
    { name: 'USA Virtual', code: '+1', price: 37.3, countryId: 12, flag: '🇺🇸' }
];

const gomofyCountries = [];

const stockydodoCountries = [
    { name: 'India', code: '+91', price: 29.12, countryId: 22, flag: '🇮🇳' }
];

const meragaonCountries = [];

const gurmanikaCountries = [];

const dikidiCountries = [];

const lydiaCountries = [];

const muzzCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const ankamaCountries = [
    { name: 'Netherlands', code: '+31', price: 7.28, countryId: 48, flag: '🇳🇱' }
];

const profeeCountries = [];

const nice88Countries = [];

const paybisCountries = [
    { name: 'Romania', code: '+40', price: 21.84, countryId: 32, flag: '🇷🇴' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const lionparcelCountries = [];

const getresponseCountries = [];

const remotasksCountries = [
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 48.78, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 12.38, countryId: 48, flag: '🇳🇱' },
    { name: 'Canada', code: '+1', price: 53.87, countryId: 36, flag: '🇨🇦' }
];

const tierCountries = [
    { name: 'Colombia', code: '+57', price: 15.29, countryId: 33, flag: '🇨🇴' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 36.4, countryId: 7, flag: '🇲🇾' },
    { name: 'Netherlands', code: '+31', price: 12.38, countryId: 48, flag: '🇳🇱' }
];

const greggsCountries = [];

const womplyCountries = [
    { name: 'USA', code: '+1', price: 72.8, countryId: 187, flag: '🇺🇸' }
];

const pcipayCountries = [];

const battlestategamesCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.46, countryId: 16, flag: '🇬🇧' },
    { name: 'France', code: '+33', price: 4, countryId: 78, flag: '🇫🇷' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const ackoCountries = [
    { name: 'India', code: '+91', price: 36.4, countryId: 22, flag: '🇮🇳' }
];

const sbicardCountries = [];

const wooplusCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 224.22, countryId: 187, flag: '🇺🇸' }
];

const vercelCountries = [
    { name: 'United Kingdom', code: '+44', price: 4, countryId: 16, flag: '🇬🇧' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'USA', code: '+1', price: 46.59, countryId: 187, flag: '🇺🇸' }
];

const discoverhongkongCountries = [];

const smartCountries = [
    { name: 'Philippines', code: '+63', price: 38.58, countryId: 4, flag: '🇵🇭' }
];

const segariCountries = [];

const bcgameCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const vidaCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const nutriclubCountries = [];

const bebeclubCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' }
];

const punjabcitizenCountries = [];

const teamoruCountries = [];

const gordanCountries = [];

const mitidCountries = [];

const moneyviewCountries = [];

const sheinCountries = [
    { name: 'USA', code: '+1', price: 81.54, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 9.83, countryId: 16, flag: '🇬🇧' },
    { name: 'India', code: '+91', price: 27.3, countryId: 22, flag: '🇮🇳' },
    { name: 'Malaysia', code: '+60', price: 36.4, countryId: 7, flag: '🇲🇾' }
];

const supercellCountries = [
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Malaysia', code: '+60', price: 42.95, countryId: 7, flag: '🇲🇾' },
    { name: 'India', code: '+91', price: 24.02, countryId: 22, flag: '🇮🇳' },
    { name: 'Netherlands', code: '+31', price: 10.19, countryId: 48, flag: '🇳🇱' }
];

const varusCountries = [
    { name: 'Ukraine', code: '+380', price: 38.58, countryId: 1, flag: '🇺🇦' }
];

const coinfantasyCountries = [];

const pyyplCountries = [];

const migrosCountries = [];

const xboxCountries = [
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'Germany', code: '+49', price: 8.74, countryId: 43, flag: '🇩🇪' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' },
    { name: 'Ukraine', code: '+380', price: 2.18, countryId: 1, flag: '🇺🇦' },
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'Malaysia', code: '+60', price: 48.78, countryId: 7, flag: '🇲🇾' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' }
];

const yellowCountries = [];

const satuCountries = [];

const openbudjetCountries = [];

const sonolCountries = [];

const yudaCountries = [];

const googlemessengerCountries = [
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Austria', code: '+43', price: 242.79, countryId: 50, flag: '🇦🇹' },
    { name: 'Brazil', code: '+55', price: 28.76, countryId: 73, flag: '🇧🇷' },
    { name: 'South Africa', code: '+27', price: 2.18, countryId: 31, flag: '🇿🇦' },
    { name: 'India', code: '+91', price: 54.6, countryId: 22, flag: '🇮🇳' },
    { name: 'Pakistan', code: '+92', price: 182.73, countryId: 66, flag: '🇵🇰' },
    { name: 'Bangladesh', code: '+880', price: 182.73, countryId: 60, flag: '🇧🇩' },
    { name: 'Zambia', code: '+260', price: 182.73, countryId: 147, flag: '🇿🇲' },
    { name: 'Namibia', code: '+264', price: 182.73, countryId: 138, flag: '🇳🇦' },
    { name: 'Algeria', code: '+213', price: 182.73, countryId: 58, flag: '🇩🇿' },
    { name: 'Ethiopia', code: '+251', price: 182.73, countryId: 71, flag: '🇪🇹' },
    { name: 'Mozambique', code: '+258', price: 182.73, countryId: 80, flag: '🇲🇿' },
    { name: 'Angola', code: '+244', price: 182.73, countryId: 76, flag: '🇦🇴' },
    { name: 'Ukraine', code: '+380', price: 364, countryId: 1, flag: '🇺🇦' },
    { name: 'Egypt', code: '+20', price: 182.73, countryId: 21, flag: '🇪🇬' },
    { name: 'Haiti', code: '+509', price: 182.73, countryId: 26, flag: '🇭🇹' },
    { name: 'Iran', code: '+98', price: 182.73, countryId: 57, flag: '🇮🇷' },
    { name: 'Peru', code: '+51', price: 182.73, countryId: 65, flag: '🇵🇪' },
    { name: 'Vietnam', code: '+84', price: 57.51, countryId: 10, flag: '🇻🇳' },
    { name: 'Zimbabwe', code: '+263', price: 182.73, countryId: 96, flag: '🇿🇼' },
    { name: 'Nepal', code: '+977', price: 182.73, countryId: 81, flag: '🇳🇵' },
    { name: 'Uzbekistan', code: '+998', price: 182.73, countryId: 40, flag: '🇺🇿' },
    { name: 'Nigeria', code: '+234', price: 182.73, countryId: 19, flag: '🇳🇬' },
    { name: 'France', code: '+33', price: 273.36, countryId: 78, flag: '🇫🇷' },
    { name: 'Botswana', code: '+267', price: 182.73, countryId: 123, flag: '🇧🇼' },
    { name: 'Mexico', code: '+52', price: 182.73, countryId: 54, flag: '🇲🇽' },
    { name: 'Tanzania', code: '+255', price: 182.73, countryId: 9, flag: '🇹🇿' },
    { name: 'Sri Lanka', code: '+94', price: 182.73, countryId: 64, flag: '🇱🇰' },
    { name: 'Honduras', code: '+504', price: 182.73, countryId: 88, flag: '🇭🇳' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Myanmar', code: '+95', price: 182.73, countryId: 5, flag: '🇲🇲' },
    { name: 'Tunisia', code: '+216', price: 182.73, countryId: 89, flag: '🇹🇳' },
    { name: 'Lesotho', code: '+266', price: 182.73, countryId: 136, flag: '🇱🇸' },
    { name: 'Ecuador', code: '+593', price: 182.73, countryId: 105, flag: '🇪🇨' },
    { name: 'El Salvador', code: '+503', price: 182.73, countryId: 101, flag: '🇸🇻' },
    { name: 'Morocco', code: '+212', price: 364, countryId: 37, flag: '🇲🇦' },
    { name: 'Uganda', code: '+256', price: 182.73, countryId: 75, flag: '🇺🇬' },
    { name: 'Malawi', code: '+265', price: 182.73, countryId: 137, flag: '🇲🇼' },
    { name: 'Ghana', code: '+233', price: 182.73, countryId: 38, flag: '🇬🇭' },
    { name: 'Kenya', code: '+254', price: 182.73, countryId: 8, flag: '🇰🇪' },
    { name: 'Panama', code: '+507', price: 182.73, countryId: 112, flag: '🇵🇦' },
    { name: 'Jamaica', code: '+1', price: 182.73, countryId: 103, flag: '🇯🇲' },
    { name: 'Venezuela', code: '+58', price: 182.73, countryId: 70, flag: '🇻🇪' },
    { name: 'Kazakhstan', code: '+7', price: 364, countryId: 2, flag: '🇰🇿' },
    { name: 'Colombia', code: '+57', price: 140.14, countryId: 33, flag: '🇨🇴' },
    { name: 'Paraguay', code: '+595', price: 182.73, countryId: 87, flag: '🇵🇾' },
    { name: 'Turkey', code: '+90', price: 182.73, countryId: 62, flag: '🇹🇷' },
    { name: 'Kyrgyzstan', code: '+996', price: 182.73, countryId: 11, flag: '🇰🇬' },
    { name: 'Jordan', code: '+962', price: 182.73, countryId: 116, flag: '🇯🇴' },
    { name: 'Cameroon', code: '+237', price: 182.73, countryId: 41, flag: '🇨🇲' },
    { name: 'Israel', code: '', price: 658.11, countryId: 13, flag: '🇮🇱' },
    { name: 'Ivory Coast', code: '+225', price: 182.73, countryId: 27, flag: '🇨🇮' },
    { name: 'Belarus', code: '+375', price: 182.73, countryId: 51, flag: '🇧🇾' },
    { name: 'Bulgaria', code: '+359', price: 250.07, countryId: 83, flag: '🇧🇬' },
    { name: 'Mauritius', code: '+230', price: 182.73, countryId: 157, flag: '🇲🇺' },
    { name: 'Turkmenistan', code: '+993', price: 182.73, countryId: 161, flag: '🇹🇲' },
    { name: 'Azerbaijan', code: '+994', price: 182.73, countryId: 35, flag: '🇦🇿' },
    { name: 'Mali', code: '+223', price: 182.73, countryId: 69, flag: '🇲🇱' },
    { name: 'Rwanda', code: '+250', price: 182.73, countryId: 140, flag: '🇷🇼' },
    { name: 'Gabon', code: '+241', price: 182.73, countryId: 154, flag: '🇬🇦' },
    { name: 'Spain', code: '+34', price: 268.63, countryId: 56, flag: '🇪🇸' },
    { name: 'Nicaragua', code: '+505', price: 182.73, countryId: 90, flag: '🇳🇮' },
    { name: 'Moldova', code: '+373', price: 182.73, countryId: 85, flag: '🇲🇩' },
    { name: 'USA', code: '+1', price: 182.73, countryId: 187, flag: '🇺🇸' },
    { name: 'Saudi Arabia', code: '+966', price: 182.73, countryId: 53, flag: '🇸🇦' },
    { name: 'Belgium', code: '+32', price: 136.86, countryId: 82, flag: '🇧🇪' },
    { name: 'Benin', code: '+229', price: 182.73, countryId: 120, flag: '🇧🇯' },
    { name: 'Burkina Faso', code: '+226', price: 182.73, countryId: 152, flag: '🇧🇫' },
    { name: 'Costa Rica', code: '+506', price: 182.73, countryId: 93, flag: '🇨🇷' },
    { name: 'Germany', code: '+49', price: 364, countryId: 43, flag: '🇩🇪' },
    { name: 'Iraq', code: '+964', price: 182.73, countryId: 47, flag: '🇮🇶' },
    { name: 'Laos', code: '+856', price: 18.27, countryId: 25, flag: '🇱🇦' },
    { name: 'Oman', code: '+968', price: 182.73, countryId: 107, flag: '🇴🇲' },
    { name: 'Poland', code: '+48', price: 364, countryId: 15, flag: '🇵🇱' },
    { name: 'Qatar', code: '+974', price: 182.73, countryId: 111, flag: '🇶🇦' },
    { name: 'Reunion', code: '+262', price: 182.73, countryId: 146, flag: '🇷🇪' },
    { name: 'Senegal', code: '+221', price: 18.27, countryId: 61, flag: '🇸🇳' },
    { name: 'Thailand', code: '+66', price: 182.73, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 98.64, countryId: 16, flag: '🇬🇧' },
    { name: 'Uruguay', code: '+598', price: 182.73, countryId: 156, flag: '🇺🇾' },
    { name: 'Yemen', code: '+967', price: 182.73, countryId: 30, flag: '🇾🇪' },
    { name: 'Afghanistan', code: '+93', price: 182.73, countryId: 74, flag: '🇦🇫' },
    { name: 'Armenia', code: '+374', price: 182.73, countryId: 148, flag: '🇦🇲' },
    { name: 'Barbados', code: '+1', price: 182.73, countryId: 118, flag: '🇧🇧' },
    { name: 'Burundi', code: '+257', price: 182.73, countryId: 119, flag: '🇧🇮' },
    { name: 'Cambodia', code: '+855', price: 182.73, countryId: 24, flag: '🇰🇭' },
    { name: 'Chad', code: '+235', price: 182.73, countryId: 42, flag: '🇹🇩' },
    { name: 'Equatorial Guinea', code: '+240', price: 182.73, countryId: 167, flag: '🇬🇶' },
    { name: 'Gambia', code: '+220', price: 182.73, countryId: 28, flag: '🇬🇲' },
    { name: 'Guinea-Bissau', code: '+245', price: 182.73, countryId: 130, flag: '🇬🇼' },
    { name: 'Guyana', code: '+592', price: 182.73, countryId: 131, flag: '🇬🇾' },
    { name: 'Hungary', code: '+36', price: 182.73, countryId: 84, flag: '🇭🇺' },
    { name: 'Kuwait', code: '+965', price: 182.73, countryId: 100, flag: '🇰🇼' },
    { name: 'Malaysia', code: '+60', price: 182.73, countryId: 7, flag: '🇲🇾' },
    { name: 'Maldives', code: '+960', price: 182.73, countryId: 159, flag: '🇲🇻' },
    { name: 'Mauritania', code: '+222', price: 182.73, countryId: 114, flag: '🇲🇷' },
    { name: 'Netherlands', code: '+31', price: 82.26, countryId: 48, flag: '🇳🇱' },
    { name: 'Niger', code: '+227', price: 182.73, countryId: 139, flag: '🇳🇪' },
    { name: 'Philippines', code: '+63', price: 364, countryId: 4, flag: '🇵🇭' },
    { name: 'Portugal', code: '+351', price: 120.85, countryId: 117, flag: '🇵🇹' },
    { name: 'Somalia', code: '+252', price: 182.73, countryId: 149, flag: '🇸🇴' },
    { name: 'South Sudan', code: '+211', price: 182.73, countryId: 177, flag: '🇸🇸' },
    { name: 'Switzerland', code: '+41', price: 127.76, countryId: 173, flag: '🇨🇭' },
    { name: 'Togo', code: '+228', price: 182.73, countryId: 99, flag: '🇹🇬' },
    { name: 'Puerto Rico', code: '+1', price: 182.73, countryId: 97, flag: '🇵🇷' },
    { name: 'Ireland', code: '+353', price: 182.73, countryId: 23, flag: '🇮🇪' },
    { name: 'Serbia', code: '+381', price: 182.73, countryId: 29, flag: '🇷🇸' },
    { name: 'Estonia', code: '+372', price: 364, countryId: 34, flag: '🇪🇪' },
    { name: 'Bahrain', code: '+973', price: 182.73, countryId: 145, flag: '🇧🇭' },
    { name: 'Czech Republic', code: '+420', price: 364, countryId: 63, flag: '🇨🇿' },
    { name: 'Guadeloupe', code: '+590', price: 182.73, countryId: 160, flag: '🇬🇵' },
    { name: 'Norway', code: '+47', price: 182.73, countryId: 174, flag: '🇳🇴' },
    { name: 'Italy', code: '+39', price: 143.42, countryId: 86, flag: '🇮🇹' },
    { name: 'Cyprus', code: '+357', price: 364, countryId: 77, flag: '🇨🇾' },
    { name: 'Luxembourg', code: '+352', price: 182.73, countryId: 165, flag: '🇱🇺' },
    { name: 'Suriname', code: '+597', price: 182.73, countryId: 142, flag: '🇸🇷' },
    { name: 'Guatemala', code: '+502', price: 182.73, countryId: 94, flag: '🇬🇹' },
    { name: 'Madagascar', code: '+261', price: 182.73, countryId: 17, flag: '🇲🇬' },
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' },
    { name: 'Djibouti', code: '+253', price: 182.73, countryId: 168, flag: '🇩🇯' },
    { name: 'Finland', code: '+358', price: 182.73, countryId: 163, flag: '🇫🇮' },
    { name: 'French Guiana', code: '+594', price: 182.73, countryId: 162, flag: '🇬🇫' },
    { name: 'Saint Lucia', code: '+1', price: 182.73, countryId: 164, flag: '🇱🇨' },
    { name: 'Montenegro', code: '+382', price: 182.73, countryId: 171, flag: '🇲🇪' },
    { name: 'Canada', code: '+1', price: 47.68, countryId: 36, flag: '🇨🇦' },
    { name: 'Cuba', code: '+53', price: 182.73, countryId: 113, flag: '🇨🇺' },
    { name: 'Greece', code: '+30', price: 364, countryId: 129, flag: '🇬🇷' },
    { name: 'Chile', code: '+56', price: 48.78, countryId: 151, flag: '🇨🇱' },
    { name: 'Albania', code: '+355', price: 182.73, countryId: 155, flag: '🇦🇱' },
    { name: 'Slovenia', code: '+386', price: 364, countryId: 59, flag: '🇸🇮' },
    { name: 'Hong Kong', code: '+852', price: 182.73, countryId: 14, flag: '🇭🇰' },
    { name: 'Taiwan', code: '+886', price: 182.73, countryId: 55, flag: '🇹🇼' },
    { name: 'Lithuania', code: '+370', price: 182.73, countryId: 44, flag: '🇱🇹' },
    { name: 'Liberia', code: '+231', price: 182.73, countryId: 135, flag: '🇱🇷' },
    { name: 'Guinea', code: '+224', price: 182.73, countryId: 68, flag: '🇬🇳' },
    { name: 'Aruba', code: '+297', price: 182.73, countryId: 179, flag: '🇦🇼' },
    { name: 'Comoros', code: '+269', price: 182.73, countryId: 133, flag: '🇰🇲' },
    { name: 'Singapore', code: '+65', price: 182.73, countryId: 196, flag: '🇸🇬' },
    { name: 'Slovakia', code: '+421', price: 182.73, countryId: 141, flag: '🇸🇰' },
    { name: 'Sao Tome and Principe', code: '+239', price: 182.73, countryId: 178, flag: '🇸🇹' },
    { name: 'Fiji', code: '+679', price: 182.73, countryId: 189, flag: '🇫🇯' },
    { name: 'Croatia', code: '+385', price: 364, countryId: 45, flag: '🇭🇷' },
    { name: 'Cape Verde', code: '+238', price: 182.73, countryId: 186, flag: '🇨🇻' },
    { name: 'Monaco', code: '+377', price: 182.73, countryId: 144, flag: '🇲🇨' },
    { name: 'Macedonia', code: '+389', price: 182.73, countryId: 183, flag: '🇲🇰' },
    { name: 'Belize', code: '+501', price: 182.73, countryId: 124, flag: '🇧🇿' },
    { name: 'New Caledonia', code: '+687', price: 182.73, countryId: 185, flag: '🇳🇨' },
    { name: 'New Zealand', code: '+64', price: 182.73, countryId: 67, flag: '🇳🇿' },
    { name: 'Mongolia', code: '+976', price: 182.73, countryId: 72, flag: '🇲🇳' },
    { name: 'Lebanon', code: '+961', price: 182.73, countryId: 153, flag: '🇱🇧' },
    { name: 'Denmark', code: '+45', price: 182.73, countryId: 172, flag: '🇩🇰' },
    { name: 'Georgia', code: '+995', price: 315.59, countryId: 128, flag: '🇬🇪' },
    { name: 'Sierra Leone', code: '+232', price: 182.73, countryId: 115, flag: '🇸🇱' },
    { name: 'Bahamas', code: '+1', price: 182.73, countryId: 122, flag: '🇧🇸' },
    { name: 'Bolivia', code: '+591', price: 182.73, countryId: 92, flag: '🇧🇴' },
    { name: 'Grenada', code: '+1', price: 182.73, countryId: 127, flag: '🇬🇩' },
    { name: 'Latvia', code: '+371', price: 182.73, countryId: 49, flag: '🇱🇻' },
    { name: 'Tajikistan', code: '+992', price: 182.73, countryId: 143, flag: '🇹🇯' },
    { name: 'Brunei Darussalam', code: '+673', price: 182.73, countryId: 121, flag: '🇧🇳' },
    { name: 'Cayman Islands', code: '+1', price: 182.73, countryId: 170, flag: '🇰🇾' },
    { name: 'Australia', code: '', price: 182.73, countryId: 175, flag: '🇦🇺' },
    { name: 'Seychelles', code: '+248', price: 182.73, countryId: 184, flag: '🇸🇨' },
    { name: 'Montserrat', code: '+1', price: 182.73, countryId: 180, flag: '🇲🇸' },
    { name: 'Dominica', code: '+1', price: 182.73, countryId: 126, flag: '🇩🇲' },
    { name: 'Iceland', code: '+354', price: 182.73, countryId: 132, flag: '🇮🇸' },
    { name: 'Eritrea', code: '+291', price: 18.27, countryId: 176, flag: '🇪🇷' },
    { name: 'Gibraltar', code: '+350', price: 18.27, countryId: 201, flag: '🇬🇮' }
];

const fastwinCountries = [];

const mediaexpressCountries = [];

const getsbetCountries = [
    { name: 'Romania', code: '+40', price: 28.76, countryId: 32, flag: '🇷🇴' }
];

const bingoplusCountries = [
    { name: 'Philippines', code: '+63', price: 26.94, countryId: 4, flag: '🇵🇭' }
];

const branchCountries = [
    { name: 'USA', code: '+1', price: 72.8, countryId: 187, flag: '🇺🇸' }
];

const pokercircleCountries = [];

const radquestCountries = [
    { name: 'Colombia', code: '+57', price: 42.95, countryId: 33, flag: '🇨🇴' },
    { name: 'USA', code: '+1', price: 483.03, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 45.86, countryId: 16, flag: '🇬🇧' },
    { name: 'Chile', code: '+56', price: 1.46, countryId: 151, flag: '🇨🇱' }
];

const hicardCountries = [];

const ludoplusCountries = [];

const confirmtktCountries = [];

const matchcomCountries = [];

const verasightCountries = [
    { name: 'USA', code: '+1', price: 72.8, countryId: 187, flag: '🇺🇸' }
];

const goagamesCountries = [];

const betininCountries = [];

const tealiveCountries = [];

const busqoCountries = [
    { name: 'Colombia', code: '+57', price: 24.75, countryId: 33, flag: '🇨🇴' }
];

const nuumruCountries = [];

const metauaCountries = [];

const narendramodiCountries = [];

const namaskarCountries = [];

const tajrummyCountries = [];

const happypancakeCountries = [];

const keetaCountries = [];

const hdfcegroCountries = [];

const tomorocoffeeCountries = [];

const fivesurveysCountries = [];

const benjaminCountries = [
    { name: 'USA', code: '+1', price: 109.2, countryId: 187, flag: '🇺🇸' }
];

const dingCountries = [];

const theasianparentCountries = [];

const tunestudioCountries = [
    { name: 'South Africa', code: '+27', price: 1.46, countryId: 31, flag: '🇿🇦' },
    { name: 'Colombia', code: '+57', price: 4.37, countryId: 33, flag: '🇨🇴' },
    { name: 'United Kingdom', code: '+44', price: 7.28, countryId: 16, flag: '🇬🇧' },
    { name: 'Indonesia', code: '+62', price: 7.28, countryId: 6, flag: '🇮🇩' }
];

const talabatCountries = [];

const hpgasCountries = [];

const lolooCountries = [];

const olxkzCountries = [];

const olxuaCountries = [];

const olxplCountries = [];

const talkatoneCountries = [];

const etsyCountries = [
    { name: 'Spain', code: '+34', price: 181.64, countryId: 56, flag: '🇪🇸' },
    { name: 'South Africa', code: '+27', price: 24.39, countryId: 31, flag: '🇿🇦' },
    { name: 'Brazil', code: '+55', price: 2.18, countryId: 73, flag: '🇧🇷' },
    { name: 'USA', code: '+1', price: 92.46, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 182, countryId: 16, flag: '🇬🇧' },
    { name: 'Poland', code: '+48', price: 242.79, countryId: 15, flag: '🇵🇱' },
    { name: 'Portugal', code: '+351', price: 242.79, countryId: 117, flag: '🇵🇹' },
    { name: 'Romania', code: '+40', price: 72.8, countryId: 32, flag: '🇷🇴' }
];

const olxroCountries = [];

const olxbgCountries = [];

const olxptCountries = [];

const githubCountries = [];

const olxuzCountries = [];

const streamlabsCountries = [];

const unstopCountries = [];

const stanCountries = [];

const swarailCountries = [];

const magicpinCountries = [];

const fiftyoneexchCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const truemoneyCountries = [
    { name: 'Cambodia', code: '+855', price: 48.78, countryId: 24, flag: '🇰🇭' }
];

const innopayCountries = [];

const hypermartCountries = [];

const vision11Countries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const saathiCountries = [];

const capitaloneCountries = [
    { name: 'USA', code: '+1', price: 34.22, countryId: 187, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 32.4, countryId: 36, flag: '🇨🇦' },
    { name: 'United Kingdom', code: '+44', price: 15.1, countryId: 16, flag: '🇬🇧' }
];

const bingo101Countries = [
    { name: 'India', code: '+91', price: 30.58, countryId: 22, flag: '🇮🇳' }
];

const efsaneCountries = [
    { name: 'Turkey', code: '+90', price: 900.07, countryId: 62, flag: '🇹🇷' },
    { name: 'United Kingdom', code: '+44', price: 15.1, countryId: 16, flag: '🇬🇧' }
];

const rapidoCountries = [];

const sixerCountries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const omnicardCountries = [];

const shopsyCountries = [];

const collegepulseCountries = [];

const creditkarmaCountries = [];

const gaintplayCountries = [
    { name: 'USA', code: '+1', price: 68.07, countryId: 187, flag: '🇺🇸' }
];

const trapcallCountries = [
    { name: 'USA', code: '+1', price: 92.46, countryId: 187, flag: '🇺🇸' }
];

const kudosCountries = [];

const resyCountries = [];

const blastbucksCountries = [
    { name: 'USA', code: '+1', price: 188.55, countryId: 187, flag: '🇺🇸' }
];

const timewallCountries = [
    { name: 'USA', code: '+1', price: 92.46, countryId: 187, flag: '🇺🇸' }
];

const sidelineCountries = [];

const junoCountries = [];

const chaseCountries = [];

const dutchbrosCountries = [];

const centurylinkCountries = [];

const threefunCountries = [
    { name: 'USA', code: '+1', price: 68, countryId: 187, flag: '🇺🇸' }
];

const ibottaCountries = [];

const acimaCountries = [
    { name: 'USA', code: '+1', price: 238.06, countryId: 187, flag: '🇺🇸' }
];

const aspirationCountries = [
    { name: 'USA', code: '+1', price: 383.66, countryId: 187, flag: '🇺🇸' }
];

const ring4Countries = [
    { name: 'USA', code: '+1', price: 68.07, countryId: 187, flag: '🇺🇸' }
];

const taimiCountries = [];

const pelagoCountries = [
    { name: 'USA', code: '+1', price: 238.06, countryId: 187, flag: '🇺🇸' }
];

const tumblrCountries = [];

const audibleCountries = [];

const rapidapiCountries = [];

const serpapiCountries = [];

const bosslikeCountries = [];

const fmcpayCountries = [];

const rummyyesCountries = [];

const wallapopCountries = [];

const mmliveCountries = [];

const redditCountries = [
    { name: 'USA', code: '+1', price: 169.99, countryId: 187, flag: '🇺🇸' }
];

const winclashCountries = [
    { name: 'India', code: '+91', price: 30.58, countryId: 22, flag: '🇮🇳' }
];

const outlierCountries = [];

const courtyardCountries = [];

const turbotenantCountries = [
    { name: 'USA', code: '+1', price: 92.46, countryId: 187, flag: '🇺🇸' }
];

const bridgemoneyCountries = [
    { name: 'USA', code: '+1', price: 238.06, countryId: 187, flag: '🇺🇸' }
];

const zillowCountries = [
    { name: 'USA', code: '+1', price: 52.42, countryId: 187, flag: '🇺🇸' }
];

const seatgeekCountries = [
    { name: 'USA', code: '+1', price: 48.78, countryId: 187, flag: '🇺🇸' }
];

const daveCountries = [];

const getholdingsCountries = [
    { name: 'USA', code: '+1', price: 450.63, countryId: 187, flag: '🇺🇸' }
];

const rednotexiaohongshuCountries = [];

const docusignCountries = [
    { name: 'Latvia', code: '+371', price: 30.58, countryId: 49, flag: '🇱🇻' },
    { name: 'Indonesia', code: '+62', price: 11.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Chile', code: '+56', price: 22.57, countryId: 151, flag: '🇨🇱' },
    { name: 'Romania', code: '+40', price: 15.29, countryId: 32, flag: '🇷🇴' },
    { name: 'Argentina', code: '+54', price: 11.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Spain', code: '+34', price: 18.2, countryId: 56, flag: '🇪🇸' },
    { name: 'Philippines', code: '+63', price: 12.83, countryId: 4, flag: '🇵🇭' },
    { name: 'USA', code: '+1', price: 29.85, countryId: 187, flag: '🇺🇸' },
    { name: 'Netherlands', code: '+31', price: 19.83, countryId: 48, flag: '🇳🇱' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'United Kingdom', code: '+44', price: 5.1, countryId: 16, flag: '🇬🇧' }
];

const qponCountries = [];

const starexchCountries = [
    { name: 'India', code: '+91', price: 48.78, countryId: 22, flag: '🇮🇳' }
];

const playkaro247Countries = [];

const spinwinnerCountries = [];

const atlasearthCountries = [
    { name: 'Chile', code: '+56', price: 22.93, countryId: 151, flag: '🇨🇱' },
    { name: 'Netherlands', code: '+31', price: 7.28, countryId: 48, flag: '🇳🇱' },
    { name: 'United Kingdom', code: '+44', price: 2.55, countryId: 16, flag: '🇬🇧' },
    { name: 'Colombia', code: '+57', price: 17.47, countryId: 33, flag: '🇨🇴' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Philippines', code: '+63', price: 17.47, countryId: 4, flag: '🇵🇭' }
];

const instamatchCountries = [];

const ludo11Countries = [];

const truemedsCountries = [];

const nykaaCountries = [];

const rozrummyCountries = [];

const paisabazaarCountries = [];

const huionepayCountries = [
    { name: 'Cambodia', code: '+855', price: 79.35, countryId: 24, flag: '🇰🇭' },
    { name: 'Thailand', code: '+66', price: 60.8, countryId: 52, flag: '🇹🇭' },
    { name: 'United Kingdom', code: '+44', price: 14.56, countryId: 16, flag: '🇬🇧' }
];

const skillsCountries = [];

const cursorCountries = [];

const awsCountries = [
    { name: 'USA', code: '+1', price: 21.84, countryId: 187, flag: '🇺🇸' }
];

const goldsbetCountries = [];

const cricbuzzCountries = [];

const royaljeetCountries = [];

const quokaCountries = [];

const fivehundredpxCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const bigbasketCountries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const googlechatCountries = [
    { name: 'Algeria', code: '+213', price: 5.1, countryId: 58, flag: '🇩🇿' },
    { name: 'Angola', code: '+244', price: 48.78, countryId: 76, flag: '🇦🇴' },
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Australia', code: '', price: 145.6, countryId: 175, flag: '🇦🇺' },
    { name: 'Austria', code: '+43', price: 76.44, countryId: 50, flag: '🇦🇹' },
    { name: 'Brazil', code: '+55', price: 48.78, countryId: 73, flag: '🇧🇷' },
    { name: 'Cameroon', code: '+237', price: 54.96, countryId: 41, flag: '🇨🇲' },
    { name: 'Canada', code: '+1', price: 54.6, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '+56', price: 24.75, countryId: 151, flag: '🇨🇱' },
    { name: 'Colombia', code: '+57', price: 5.1, countryId: 33, flag: '🇨🇴' },
    { name: 'Congo (Dem. Republic)', code: '+243', price: 48.78, countryId: 18, flag: '🇨🇩' },
    { name: 'Czech Republic', code: '+420', price: 92.46, countryId: 63, flag: '🇨🇿' },
    { name: 'Estonia', code: '+372', price: 455, countryId: 34, flag: '🇪🇪' },
    { name: 'France', code: '+33', price: 79.17, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 66.59, countryId: 43, flag: '🇩🇪' },
    { name: 'Greece', code: '+30', price: 82.63, countryId: 129, flag: '🇬🇷' },
    { name: 'Hong Kong', code: '+852', price: 38.58, countryId: 14, flag: '🇭🇰' },
    { name: 'India', code: '+91', price: 72.8, countryId: 22, flag: '🇮🇳' },
    { name: 'Indonesia', code: '+62', price: 2.18, countryId: 6, flag: '🇮🇩' },
    { name: 'Israel', code: '', price: 658.11, countryId: 13, flag: '🇮🇱' },
    { name: 'Italy', code: '+39', price: 82.63, countryId: 86, flag: '🇮🇹' },
    { name: 'Japan', code: '+81', price: 534.8, countryId: 1001, flag: '🇯🇵' },
    { name: 'Laos', code: '+856', price: 121.94, countryId: 25, flag: '🇱🇦' },
    { name: 'Latvia', code: '+371', price: 1241.97, countryId: 49, flag: '🇱🇻' },
    { name: 'Liberia', code: '+231', price: 115.75, countryId: 135, flag: '🇱🇷' },
    { name: 'Malaysia', code: '+60', price: 32.76, countryId: 7, flag: '🇲🇾' },
    { name: 'Moldova', code: '+373', price: 145.6, countryId: 85, flag: '🇲🇩' },
    { name: 'Netherlands', code: '+31', price: 63.34, countryId: 48, flag: '🇳🇱' },
    { name: 'Philippines', code: '+63', price: 52.78, countryId: 4, flag: '🇵🇭' },
    { name: 'Portugal', code: '+351', price: 73.89, countryId: 117, flag: '🇵🇹' },
    { name: 'Romania', code: '+40', price: 5.1, countryId: 32, flag: '🇷🇴' },
    { name: 'Sierra Leone', code: '+232', price: 73.89, countryId: 115, flag: '🇸🇱' },
    { name: 'Slovenia', code: '+386', price: 54.96, countryId: 59, flag: '🇸🇮' },
    { name: 'South Africa', code: '+27', price: 18.56, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '+34', price: 31.3, countryId: 56, flag: '🇪🇸' },
    { name: 'Sweden', code: '+46', price: 72.8, countryId: 46, flag: '🇸🇪' },
    { name: 'Thailand', code: '+66', price: 88.09, countryId: 52, flag: '🇹🇭' },
    { name: 'Ukraine', code: '+380', price: 39.31, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 4.88, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 341.43, countryId: 187, flag: '🇺🇸' },
    { name: 'Vietnam', code: '+84', price: 27.66, countryId: 10, flag: '🇻🇳' }
];

const winmatchCountries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const chipotleCountries = [
    { name: 'USA Virtual', code: '+1', price: 19.65, countryId: 12, flag: '🇺🇸' },
    { name: 'USA', code: '+1', price: 39.66, countryId: 187, flag: '🇺🇸' },
    { name: 'Canada', code: '+1', price: 22.93, countryId: 36, flag: '🇨🇦' }
];

const wellsfargoCountries = [
    { name: 'USA', code: '+1', price: 737.1, countryId: 187, flag: '🇺🇸' }
];

const govinda365Countries = [];

const woohooCountries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const firstgamesCountries = [];

const kickcashCountries = [];

const aadharCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const shriramoneCountries = [];

const pokemonCountries = [];

const naukriCountries = [];

const okwinCountries = [];

const sharechatCountries = [];

const dreammoneyCountries = [];

const konvyCountries = [];

const milanunciosCountries = [];

const kliqCountries = [
    { name: 'Argentina', code: '+54', price: 1.46, countryId: 39, flag: '🇦🇷' },
    { name: 'Brazil', code: '+55', price: 6.92, countryId: 73, flag: '🇧🇷' },
    { name: 'Cameroon', code: '+237', price: 52.42, countryId: 41, flag: '🇨🇲' },
    { name: 'Canada', code: '+1', price: 54.96, countryId: 36, flag: '🇨🇦' },
    { name: 'Chile', code: '+56', price: 72.8, countryId: 151, flag: '🇨🇱' },
    { name: 'Colombia', code: '+57', price: 44.77, countryId: 33, flag: '🇨🇴' },
    { name: 'France', code: '+33', price: 54.96, countryId: 78, flag: '🇫🇷' },
    { name: 'Italy', code: '+39', price: 54.96, countryId: 86, flag: '🇮🇹' },
    { name: 'Malaysia', code: '+60', price: 72.8, countryId: 7, flag: '🇲🇾' },
    { name: 'Morocco', code: '+212', price: 54.96, countryId: 37, flag: '🇲🇦' },
    { name: 'Netherlands', code: '+31', price: 14.56, countryId: 48, flag: '🇳🇱' },
    { name: 'Philippines', code: '+63', price: 54.96, countryId: 4, flag: '🇵🇭' },
    { name: 'South Africa', code: '+27', price: 11.28, countryId: 31, flag: '🇿🇦' },
    { name: 'Spain', code: '+34', price: 49.14, countryId: 56, flag: '🇪🇸' },
    { name: 'United Kingdom', code: '+44', price: 33.12, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 51.69, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 54.96, countryId: 12, flag: '🇺🇸' }
];

const jiagu360Countries = [];

const whatnotCountries = [
    { name: 'Netherlands', code: '+31', price: 20.02, countryId: 48, flag: '🇳🇱' }
];

const atisuCountries = [
    { name: 'Kazakhstan', code: '+7', price: 38.95, countryId: 2, flag: '🇰🇿' },
    { name: 'Ukraine', code: '+380', price: 29.12, countryId: 1, flag: '🇺🇦' }
];

const creditmantriCountries = [];

const credCountries = [];

const qqliveCountries = [];

const clubggCountries = [
    { name: 'Austria', code: '+43', price: 50.96, countryId: 50, flag: '🇦🇹' },
    { name: 'Brazil', code: '+55', price: 1.46, countryId: 73, flag: '🇧🇷' },
    { name: 'Chile', code: '+56', price: 2.18, countryId: 151, flag: '🇨🇱' },
    { name: 'Croatia', code: '+385', price: 2.18, countryId: 45, flag: '🇭🇷' },
    { name: 'Cyprus', code: '+357', price: 2.18, countryId: 77, flag: '🇨🇾' },
    { name: 'Czech Republic', code: '+420', price: 16.74, countryId: 63, flag: '🇨🇿' },
    { name: 'Denmark', code: '+45', price: 2.18, countryId: 172, flag: '🇩🇰' },
    { name: 'Ecuador', code: '+593', price: 2.18, countryId: 105, flag: '🇪🇨' },
    { name: 'Estonia', code: '+372', price: 2.18, countryId: 34, flag: '🇪🇪' },
    { name: 'France', code: '+33', price: 16.38, countryId: 78, flag: '🇫🇷' },
    { name: 'Germany', code: '+49', price: 18.93, countryId: 43, flag: '🇩🇪' },
    { name: 'Gibraltar', code: '+350', price: 847.76, countryId: 201, flag: '🇬🇮' },
    { name: 'Greece', code: '+30', price: 2.18, countryId: 129, flag: '🇬🇷' },
    { name: 'Hong Kong', code: '+852', price: 2.18, countryId: 14, flag: '🇭🇰' },
    { name: 'Indonesia', code: '+62', price: 1.46, countryId: 6, flag: '🇮🇩' },
    { name: 'Ireland', code: '+353', price: 2.18, countryId: 23, flag: '🇮🇪' },
    { name: 'Italy', code: '+39', price: 47.32, countryId: 86, flag: '🇮🇹' },
    { name: 'Japan', code: '+81', price: 1073.07, countryId: 1001, flag: '🇯🇵' },
    { name: 'Kazakhstan', code: '+7', price: 2.18, countryId: 2, flag: '🇰🇿' },
    { name: 'Kenya', code: '+254', price: 2.18, countryId: 8, flag: '🇰🇪' },
    { name: 'Kosovo', code: '+383', price: 2.18, countryId: 1004, flag: '🇽🇰' },
    { name: 'Kyrgyzstan', code: '+996', price: 6.92, countryId: 11, flag: '🇰🇬' },
    { name: 'Latvia', code: '+371', price: 2.18, countryId: 49, flag: '🇱🇻' },
    { name: 'Lithuania', code: '+370', price: 121.58, countryId: 44, flag: '🇱🇹' },
    { name: 'Malaysia', code: '+60', price: 35.67, countryId: 7, flag: '🇲🇾' },
    { name: 'Mexico', code: '+52', price: 16.74, countryId: 54, flag: '🇲🇽' },
    { name: 'Moldova', code: '+373', price: 2.18, countryId: 85, flag: '🇲🇩' },
    { name: 'Myanmar', code: '+95', price: 35.67, countryId: 5, flag: '🇲🇲' },
    { name: 'Netherlands', code: '+31', price: 2.18, countryId: 48, flag: '🇳🇱' },
    { name: 'Philippines', code: '+63', price: 17.47, countryId: 4, flag: '🇵🇭' },
    { name: 'Poland', code: '+48', price: 2.18, countryId: 15, flag: '🇵🇱' },
    { name: 'Portugal', code: '+351', price: 2.18, countryId: 117, flag: '🇵🇹' },
    { name: 'Romania', code: '+40', price: 1.46, countryId: 32, flag: '🇷🇴' },
    { name: 'Singapore', code: '+65', price: 2.18, countryId: 196, flag: '🇸🇬' },
    { name: 'Slovenia', code: '+386', price: 12.18, countryId: 59, flag: '🇸🇮' },
    { name: 'Spain', code: '+34', price: 12.18, countryId: 56, flag: '🇪🇸' },
    { name: 'Sweden', code: '+46', price: 6.55, countryId: 46, flag: '🇸🇪' },
    { name: 'Tajikistan', code: '+992', price: 6.92, countryId: 143, flag: '🇹🇯' },
    { name: 'Thailand', code: '+66', price: 13.28, countryId: 52, flag: '🇹🇭' },
    { name: 'Ukraine', code: '+380', price: 11.71, countryId: 1, flag: '🇺🇦' },
    { name: 'United Kingdom', code: '+44', price: 2.18, countryId: 16, flag: '🇬🇧' },
    { name: 'USA', code: '+1', price: 67.34, countryId: 187, flag: '🇺🇸' },
    { name: 'USA Virtual', code: '+1', price: 3.64, countryId: 12, flag: '🇺🇸' },
    { name: 'Vietnam', code: '+84', price: 35.67, countryId: 10, flag: '🇻🇳' }
];

const polloaiCountries = [];

const tolunaCountries = [];

const kickCountries = [];

const founditCountries = [];

const bigcashCountries = [
    { name: 'India', code: '+91', price: 36.4, countryId: 22, flag: '🇮🇳' },
    { name: 'Brazil', code: '+55', price: 6.55, countryId: 73, flag: '🇧🇷' }
];

const ez777Countries = [];

const fdjparionssportCountries = [];

const eniliveCountries = [];

const nexonCountries = [];

const rangliveCountries = [];

const beuteaCountries = [
    { name: 'Malaysia', code: '+60', price: 11.65, countryId: 7, flag: '🇲🇾' }
];

const indiapollsCountries = [];

const adityabirlaCountries = [
    { name: 'India', code: '+91', price: 24.39, countryId: 22, flag: '🇮🇳' }
];

const heypiggyCountries = [];

const neosurfCountries = [
    { name: 'Portugal', code: '+351', price: 242.79, countryId: 117, flag: '🇵🇹' },
    { name: 'Ireland', code: '+353', price: 161.62, countryId: 23, flag: '🇮🇪' },
    { name: 'Italy', code: '+39', price: 160.89, countryId: 86, flag: '🇮🇹' },
    { name: 'Austria', code: '+43', price: 182, countryId: 50, flag: '🇦🇹' },
    { name: 'France', code: '+33', price: 113.57, countryId: 78, flag: '🇫🇷' },
    { name: 'Spain', code: '+34', price: 96.1, countryId: 56, flag: '🇪🇸' },
    { name: 'Netherlands', code: '+31', price: 1.46, countryId: 48, flag: '🇳🇱' },
    { name: 'Canada', code: '+1', price: 109.2, countryId: 36, flag: '🇨🇦' },
    { name: 'Greece', code: '+30', price: 242.79, countryId: 129, flag: '🇬🇷' }
];

const tuttiCountries = [
    { name: 'Switzerland', code: '+41', price: 424.79, countryId: 173, flag: '🇨🇭' }
];

const kreditoCountries = [];

const sponlineCountries = [
    { name: 'Hong Kong', code: '+852', price: 36.04, countryId: 14, flag: '🇭🇰' }
];

const letgoCountries = [];

const ideeopinioniCountries = [];

const naturaavonCountries = [];

const poeCountries = [];

const guviCountries = [];

const quicktvCountries = [];

const kolotibabloCountries = [];

const mackolikCountries = [];

const zenmuxCountries = [];

const jalwagameCountries = [];

const exnessCountries = [];

const tatamotorsCountries = [];

const research360Countries = [];

const ludowinnerCountries = [];

const mbmbetCountries = [];

const longchauCountries = [];

const timitCountries = [
    { name: 'Italy', code: '+39', price: 135.04, countryId: 86, flag: '🇮🇹' }
];

const wambaCountries = [];

const adobeCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const dahadahaCountries = [];

const guzmanygomezCountries = [];

const swagbucksCountries = [
    { name: 'USA', code: '+1', price: 27.3, countryId: 187, flag: '🇺🇸' },
    { name: 'United Kingdom', code: '+44', price: 27.3, countryId: 16, flag: '🇬🇧' }
];

const ricardoCountries = [
    { name: 'Switzerland', code: '+41', price: 658.11, countryId: 173, flag: '🇨🇭' }
];

const ashleymadisonCountries = [
    { name: 'USA', code: '+1', price: 97.19, countryId: 187, flag: '🇺🇸' }
];

const fiftyonegameCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const storytvCountries = [
    { name: 'India', code: '+91', price: 34.22, countryId: 22, flag: '🇮🇳' }
];

const ourtimeCountries = [];

const nielsenCountries = [];

const telnyxCountries = [];

const grokCountries = [];

const winmateCountries = [];

const tonlineCountries = [
    { name: 'Germany', code: '+49', price: 255.16, countryId: 43, flag: '🇩🇪' }
];

const dotandkeyCountries = [];

const thedermacoCountries = [];

const predikCountries = [];

const brevistayCountries = [];

const australiapostCountries = [];

const cheqCountries = [];

const rupiyoCountries = [
    { name: 'Indonesia', code: '+62', price: 100, countryId: 6, flag: '🇮🇩' }
];

const digitaloceanCountries = [];

const fdaCountries = [];

const playtimeCountries = [];

const betflagCountries = [
    { name: 'Italy', code: '+39', price: 455, countryId: 86, flag: '🇮🇹' }
];

const sisalCountries = [
    { name: 'Italy', code: '+39', price: 401.49, countryId: 86, flag: '🇮🇹' }
];

const lottomaticaCountries = [];

const goldbetCountries = [];

const netwinCountries = [
    { name: 'Italy', code: '+39', price: 319.96, countryId: 86, flag: '🇮🇹' }
];

const snaiCountries = [
    { name: 'Italy', code: '+39', price: 388.02, countryId: 86, flag: '🇮🇹' }
];

const eurobetCountries = [
    { name: 'Italy', code: '+39', price: 322.87, countryId: 86, flag: '🇮🇹' }
];

const extraServiceCountryArraysByServiceType = {
    "mercado": mercadoCountries,
    "uklon": uklonCountries,
    "rediffmail": rediffmailCountries,
    "prom": promCountries,
    "uwin": uwinCountries,
    "bereal": berealCountries,
    "dotz": dotzCountries,
    "redbus": redbusCountries,
    "pocket52": pocket52Countries,
    "gemgala": gemgalaCountries,
    "irancell": irancellCountries,
    "bazos": bazosCountries,
    "supers": supersCountries,
    "dosi": dosiCountries,
    "monobankindia": monobankindiaCountries,
    "alfa": alfaCountries,
    "tradeup": tradeupCountries,
    "adani": adaniCountries,
    "marketguru": marketguruCountries,
    "g2g": g2gCountries,
    "ys4fun": ys4funCountries,
    "mixmart": mixmartCountries,
    "gcash": gcashCountries,
    "lazypay": lazypayCountries,
    "citybase": citybaseCountries,
    "ruten": rutenCountries,
    "crefisamais": crefisamaisCountries,
    "haraj": harajCountries,
    "perfluence": perfluenceCountries,
    "wondermart": wondermartCountries,
    "glovo": glovoCountries,
    "uu163": uu163Countries,
    "galaxywin": galaxywinCountries,
    "iti": itiCountries,
    "probo": proboCountries,
    "alfagift": alfagiftCountries,
    "ininal": ininalCountries,
    "quipp": quippCountries,
    "twilio": twilioCountries,
    "hqtrivia": hqtriviaCountries,
    "lyka": lykaCountries,
    "doordash": doordashCountries,
    "celebe": celebeCountries,
    "taikang": taikangCountries,
    "99app": ninetynineappCountries,
    "hopi": hopiCountries,
    "mocospace": mocospaceCountries,
    "iqiyi": iqiyiCountries,
    "zomato": zomatoCountries,
    "trendyol": trendyolCountries,
    "ticketmaster": ticketmasterCountries,
    "qoo10": qoo10Countries,
    "fullrent": fullrentCountries,
    "dewupoison": dewupoisonCountries,
    "1xbet": onexbetCountries,
    "my11circle": my11circleCountries,
    "ximalaya": ximalayaCountries,
    "airtel": airtelCountries,
    "huya": huyaCountries,
    "douyu": douyuCountries,
    "olacabs": olacabsCountries,
    "dominospizza": dominospizzaCountries,
    "winzogame": winzogameCountries,
    "tenchat": tenchatCountries,
    "switips": switipsCountries,
    "youstar": youstarCountries,
    "ifood": ifoodCountries,
    "deliveryclub": deliveryclubCountries,
    "coursehero": courseheroCountries,
    "trip": tripCountries,
    "mega": megaCountries,
    "nimotv": nimotvCountries,
    "caixa": caixaCountries,
    "astropay": astropayCountries,
    "happn": happnCountries,
    "mercari": mercariCountries,
    "premiumone": premiumoneCountries,
    "inboxlv": inboxlvCountries,
    "gofundme": gofundmeCountries,
    "hepsiburadacom": hepsiburadacomCountries,
    "zupee": zupeeCountries,
    "tosla": toslaCountries,
    "wise": wiseCountries,
    "callapp": callappCountries,
    "faceit": faceitCountries,
    "xiaomi": xiaomiCountries,
    "yappy": yappyCountries,
    "dream11": dream11Countries,
    "iqos": iqosCountries,
    "shellbox": shellboxCountries,
    "kucoinplay": kucoinplayCountries,
    "expressmoney": expressmoneyCountries,
    "baidu": baiduCountries,
    "subito": subitoCountries,
    "lovelocal": lovelocalCountries,
    "likee": likeeCountries,
    "chalkboard": chalkboardCountries,
    "casinoplus": casinoplusCountries,
    "kleinanzeigen": kleinanzeigenCountries,
    "rakuten": rakutenCountries,
    "gochat": gochatCountries,
    "smiles": smilesCountries,
    "anyother": anyotherCountries,
    "notifire": notifireCountries,
    "privetmir": privetmirCountries,
    "yami": yamiCountries,
    "synottip": synottipCountries,
    "miravia": miraviaCountries,
    "walmart": walmartCountries,
    "fortunask": fortunaskCountries,
    "freenow": freenowCountries,
    "shpock": shpockCountries,
    "motorkux": motorkuxCountries,
    "indodax": indodaxCountries,
    "upwork": upworkCountries,
    "beanfun": beanfunCountries,
    "claude": claudeCountries,
    "emenu": emenuCountries,
    "naimikz": naimikzCountries,
    "mycarkz": mycarkzCountries,
    "aviatakz": aviatakzCountries,
    "universalbeijingresort": universalbeijingresortCountries,
    "uzum": uzumCountries,
    "cmb": cmbCountries,
    "ipsosisay": ipsosisayCountries,
    "pinduoduo": pinduoduoCountries,
    "bharatpe": bharatpeCountries,
    "jiomart": jiomartCountries,
    "playerzpot": playerzpotCountries,
    "tataneu": tataneuCountries,
    "winterloan": winterloanCountries,
    "collabact": collabactCountries,
    "qwikcilver": qwikcilverCountries,
    "tatacliqpalette": tatacliqpaletteCountries,
    "citymall": citymallCountries,
    "a23": a23Countries,
    "poshvine": poshvineCountries,
    "marwadi": marwadiCountries,
    "frizza": frizzaCountries,
    "zepto": zeptoCountries,
    "rummycircle": rummycircleCountries,
    "khatabook": khatabookCountries,
    "earneasy": earneasyCountries,
    "fitcredit": fitcreditCountries,
    "bankkaro": bankkaroCountries,
    "skcapital": skcapitalCountries,
    "roomster": roomsterCountries,
    "servify": servifyCountries,
    "hdfcbank": hdfcbankCountries,
    "bajajfinserv": bajajfinservCountries,
    "yonogames": yonogamesCountries,
    "angelone": angeloneCountries,
    "mockguru": mockguruCountries,
    "hingedating": hingedatingCountries,
    "kamatera": kamateraCountries,
    "tomato": tomatoCountries,
    "bearwww": bearwwwCountries,
    "anibis": anibisCountries,
    "bunq": bunqCountries,
    "beboo": bebooCountries,
    "namars": namarsCountries,
    "radium": radiumCountries,
    "busyfly": busyflyCountries,
    "vfsglobal": vfsglobalCountries,
    "bro": broCountries,
    "bitrue": bitrueCountries,
    "kia": kiaCountries,
    "royalcanin": royalcaninCountries,
    "ayabank": ayabankCountries,
    "netease": neteaseCountries,
    "rappi": rappiCountries,
    "cabify": cabifyCountries,
    "nequi": nequiCountries,
    "ozan": ozanCountries,
    "fups": fupsCountries,
    "playerauctions": playerauctionsCountries,
    "chevron": chevronCountries,
    "xxgame": xxgameCountries,
    "alchemy": alchemyCountries,
    "boyaa": boyaaCountries,
    "byteplus": byteplusCountries,
    "privy": privyCountries,
    "meituan": meituanCountries,
    "pockit": pockitCountries,
    "tiptapp": tiptappCountries,
    "rocketreach": rocketreachCountries,
    "taptapsend": taptapsendCountries,
    "foodora": foodoraCountries,
    "friendtech": friendtechCountries,
    "haleon": haleonCountries,
    "airtime": airtimeCountries,
    "truthsocial": truthsocialCountries,
    "playojo": playojoCountries,
    "jinjiang": jinjiangCountries,
    "neocrypto": neocryptoCountries,
    "tuul": tuulCountries,
    "klarna": klarnaCountries,
    "vimpay": vimpayCountries,
    "grailed": grailedCountries,
    "mtrmobile": mtrmobileCountries,
    "meitu": meituCountries,
    "oneforma": oneformaCountries,
    "abbott": abbottCountries,
    "gmx": gmxCountries,
    "webde": webdeCountries,
    "strato": stratoCountries,
    "1and1": oneandoneCountries,
    "surveybell": surveybellCountries,
    "checkdomain": checkdomainCountries,
    "arlens": arlensCountries,
    "bonuslink": bonuslinkCountries,
    "suntec": suntecCountries,
    "gopayz": gopayzCountries,
    "tanoti": tanotiCountries,
    "maybank": maybankCountries,
    "myboost": myboostCountries,
    "meiqfashion": meiqfashionCountries,
    "fugeelah": fugeelahCountries,
    "k11": k11Countries,
    "strivinginthelioncity": strivinginthelioncityCountries,
    "marktplaats": marktplaatsCountries,
    "primeopinion": primeopinionCountries,
    "arenaplus": arenaplusCountries,
    "willhaben": willhabenCountries,
    "openphone": openphoneCountries,
    "seznam": seznamCountries,
    "packeta": packetaCountries,
    "publi24": publi24Countries,
    "betano": betanoCountries,
    "zasilkovna": zasilkovnaCountries,
    "bpjstk": bpjstkCountries,
    "bcasyariah": bcasyariahCountries,
    "cloudmanager": cloudmanagerCountries,
    "astrapay": astrapayCountries,
    "redigame": redigameCountries,
    "allofresh": allofreshCountries,
    "onbuka": onbukaCountries,
    "godrej": godrejCountries,
    "greywoods": greywoodsCountries,
    "thefork": theforkCountries,
    "flip": flipCountries,
    "neon": neonCountries,
    "bunda": bundaCountries,
    "astraotoshop": astraotoshopCountries,
    "gamesofa": gamesofaCountries,
    "flik": flikCountries,
    "jivapetani": jivapetaniCountries,
    "ubisoft": ubisoftCountries,
    "uangme": uangmeCountries,
    "pizzahut": pizzahutCountries,
    "seeds": seedsCountries,
    "afreecatv": afreecatvCountries,
    "tiptip": tiptipCountries,
    "schibsted": schibstedCountries,
    "feetfinder": feetfinderCountries,
    "luckylandslots": luckylandslotsCountries,
    "daki": dakiCountries,
    "baihe": baiheCountries,
    "thisfate": thisfateCountries,
    "njuskalo": njuskaloCountries,
    "cocacola": cocacolaCountries,
    "kaching": kachingCountries,
    "couponscom": couponscomCountries,
    "sparkdriver": sparkdriverCountries,
    "tiv": tivCountries,
    "razer": razerCountries,
    "zachbryan": zachbryanCountries,
    "smartypig": smartypigCountries,
    "fliff": fliffCountries,
    "spaceweb": spacewebCountries,
    "nloto": nlotoCountries,
    "brevo": brevoCountries,
    "av100pro": av100proCountries,
    "ollis": ollisCountries,
    "bankera": bankeraCountries,
    "g2a": g2aCountries,
    "cupidmedia": cupidmediaCountries,
    "ipanelonline": ipanelonlineCountries,
    "fortumo": fortumoCountries,
    "waug": waugCountries,
    "rebtel": rebtelCountries,
    "gener8": gener8Countries,
    "gopuff": gopuffCountries,
    "feels": feelsCountries,
    "zuscoffee": zuscoffeeCountries,
    "zoogame": zoogameCountries,
    "coffeetea": coffeeteaCountries,
    "moveit": moveitCountries,
    "prakerja": prakerjaCountries,
    "venteny": ventenyCountries,
    "asiamiles": asiamilesCountries,
    "myvalue": myvalueCountries,
    "boku": bokuCountries,
    "getplus": getplusCountries,
    "dayaauto": dayaautoCountries,
    "shareparty": sharepartyCountries,
    "indoba": indobaCountries,
    "kemnakerri": kemnakerriCountries,
    "allaccess": allaccessCountries,
    "motionpay": motionpayCountries,
    "linkaja": linkajaCountries,
    "leroymerlin": leroymerlinCountries,
    "bookmyplay": bookmyplayCountries,
    "winds": windsCountries,
    "ryde": rydeCountries,
    "her": herCountries,
    "blankstreet": blankstreetCountries,
    "voi": voiCountries,
    "sonyliv": sonylivCountries,
    "hanya": hanyaCountries,
    "prenagenclub": prenagenclubCountries,
    "tiketcom": tiketcomCountries,
    "easycash": easycashCountries,
    "dagangan": daganganCountries,
    "doku": dokuCountries,
    "lottemart": lottemartCountries,
    "chakrarewards": chakrarewardsCountries,
    "xworldwallet": xworldwalletCountries,
    "gomofy": gomofyCountries,
    "stockydodo": stockydodoCountries,
    "meragaon": meragaonCountries,
    "gurmanika": gurmanikaCountries,
    "dikidi": dikidiCountries,
    "lydia": lydiaCountries,
    "muzz": muzzCountries,
    "ankama": ankamaCountries,
    "profee": profeeCountries,
    "nice88": nice88Countries,
    "paybis": paybisCountries,
    "lionparcel": lionparcelCountries,
    "getresponse": getresponseCountries,
    "remotasks": remotasksCountries,
    "tier": tierCountries,
    "greggs": greggsCountries,
    "womply": womplyCountries,
    "pcipay": pcipayCountries,
    "battlestategames": battlestategamesCountries,
    "acko": ackoCountries,
    "sbicard": sbicardCountries,
    "wooplus": wooplusCountries,
    "vercel": vercelCountries,
    "discoverhongkong": discoverhongkongCountries,
    "smart": smartCountries,
    "segari": segariCountries,
    "bcgame": bcgameCountries,
    "vida": vidaCountries,
    "nutriclub": nutriclubCountries,
    "bebeclub": bebeclubCountries,
    "punjabcitizen": punjabcitizenCountries,
    "teamoru": teamoruCountries,
    "gordan": gordanCountries,
    "mitid": mitidCountries,
    "moneyview": moneyviewCountries,
    "shein": sheinCountries,
    "supercell": supercellCountries,
    "varus": varusCountries,
    "coinfantasy": coinfantasyCountries,
    "pyypl": pyyplCountries,
    "migros": migrosCountries,
    "xbox": xboxCountries,
    "yellow": yellowCountries,
    "satu": satuCountries,
    "openbudjet": openbudjetCountries,
    "sonol": sonolCountries,
    "yuda": yudaCountries,
    "googlemessenger": googlemessengerCountries,
    "fastwin": fastwinCountries,
    "mediaexpress": mediaexpressCountries,
    "getsbet": getsbetCountries,
    "bingoplus": bingoplusCountries,
    "branch": branchCountries,
    "pokercircle": pokercircleCountries,
    "radquest": radquestCountries,
    "hicard": hicardCountries,
    "ludoplus": ludoplusCountries,
    "confirmtkt": confirmtktCountries,
    "matchcom": matchcomCountries,
    "verasight": verasightCountries,
    "goagames": goagamesCountries,
    "betinin": betininCountries,
    "tealive": tealiveCountries,
    "busqo": busqoCountries,
    "nuumru": nuumruCountries,
    "metaua": metauaCountries,
    "narendramodi": narendramodiCountries,
    "namaskar": namaskarCountries,
    "tajrummy": tajrummyCountries,
    "happypancake": happypancakeCountries,
    "keeta": keetaCountries,
    "hdfcegro": hdfcegroCountries,
    "tomorocoffee": tomorocoffeeCountries,
    "fivesurveys": fivesurveysCountries,
    "benjamin": benjaminCountries,
    "ding": dingCountries,
    "theasianparent": theasianparentCountries,
    "tunestudio": tunestudioCountries,
    "talabat": talabatCountries,
    "hpgas": hpgasCountries,
    "loloo": lolooCountries,
    "olxkz": olxkzCountries,
    "olxua": olxuaCountries,
    "olxpl": olxplCountries,
    "talkatone": talkatoneCountries,
    "etsy": etsyCountries,
    "olxro": olxroCountries,
    "olxbg": olxbgCountries,
    "olxpt": olxptCountries,
    "github": githubCountries,
    "olxuz": olxuzCountries,
    "streamlabs": streamlabsCountries,
    "unstop": unstopCountries,
    "stan": stanCountries,
    "swarail": swarailCountries,
    "magicpin": magicpinCountries,
    "51exch": fiftyoneexchCountries,
    "truemoney": truemoneyCountries,
    "innopay": innopayCountries,
    "hypermart": hypermartCountries,
    "vision11": vision11Countries,
    "saathi": saathiCountries,
    "capitalone": capitaloneCountries,
    "bingo101": bingo101Countries,
    "efsane": efsaneCountries,
    "rapido": rapidoCountries,
    "sixer": sixerCountries,
    "omnicard": omnicardCountries,
    "shopsy": shopsyCountries,
    "collegepulse": collegepulseCountries,
    "creditkarma": creditkarmaCountries,
    "gaintplay": gaintplayCountries,
    "trapcall": trapcallCountries,
    "kudos": kudosCountries,
    "resy": resyCountries,
    "blastbucks": blastbucksCountries,
    "timewall": timewallCountries,
    "sideline": sidelineCountries,
    "juno": junoCountries,
    "chase": chaseCountries,
    "dutchbros": dutchbrosCountries,
    "centurylink": centurylinkCountries,
    "3fun": threefunCountries,
    "ibotta": ibottaCountries,
    "acima": acimaCountries,
    "aspiration": aspirationCountries,
    "ring4": ring4Countries,
    "taimi": taimiCountries,
    "pelago": pelagoCountries,
    "tumblr": tumblrCountries,
    "audible": audibleCountries,
    "rapidapi": rapidapiCountries,
    "serpapi": serpapiCountries,
    "bosslike": bosslikeCountries,
    "fmcpay": fmcpayCountries,
    "rummyyes": rummyyesCountries,
    "wallapop": wallapopCountries,
    "mmlive": mmliveCountries,
    "reddit": redditCountries,
    "winclash": winclashCountries,
    "outlier": outlierCountries,
    "courtyard": courtyardCountries,
    "turbotenant": turbotenantCountries,
    "bridgemoney": bridgemoneyCountries,
    "zillow": zillowCountries,
    "seatgeek": seatgeekCountries,
    "dave": daveCountries,
    "getholdings": getholdingsCountries,
    "rednotexiaohongshu": rednotexiaohongshuCountries,
    "docusign": docusignCountries,
    "qpon": qponCountries,
    "starexch": starexchCountries,
    "playkaro247": playkaro247Countries,
    "spinwinner": spinwinnerCountries,
    "atlasearth": atlasearthCountries,
    "instamatch": instamatchCountries,
    "ludo11": ludo11Countries,
    "truemeds": truemedsCountries,
    "nykaa": nykaaCountries,
    "rozrummy": rozrummyCountries,
    "paisabazaar": paisabazaarCountries,
    "huionepay": huionepayCountries,
    "skills": skillsCountries,
    "cursor": cursorCountries,
    "aws": awsCountries,
    "goldsbet": goldsbetCountries,
    "cricbuzz": cricbuzzCountries,
    "royaljeet": royaljeetCountries,
    "quoka": quokaCountries,
    "500px": fivehundredpxCountries,
    "bigbasket": bigbasketCountries,
    "googlechat": googlechatCountries,
    "winmatch": winmatchCountries,
    "chipotle": chipotleCountries,
    "wellsfargo": wellsfargoCountries,
    "govinda365": govinda365Countries,
    "woohoo": woohooCountries,
    "firstgames": firstgamesCountries,
    "kickcash": kickcashCountries,
    "aadhar": aadharCountries,
    "shriramone": shriramoneCountries,
    "pokemon": pokemonCountries,
    "naukri": naukriCountries,
    "okwin": okwinCountries,
    "sharechat": sharechatCountries,
    "dreammoney": dreammoneyCountries,
    "konvy": konvyCountries,
    "milanuncios": milanunciosCountries,
    "kliq": kliqCountries,
    "jiagu360": jiagu360Countries,
    "whatnot": whatnotCountries,
    "atisu": atisuCountries,
    "creditmantri": creditmantriCountries,
    "cred": credCountries,
    "qqlive": qqliveCountries,
    "clubgg": clubggCountries,
    "polloai": polloaiCountries,
    "toluna": tolunaCountries,
    "kick": kickCountries,
    "foundit": founditCountries,
    "bigcash": bigcashCountries,
    "ez777": ez777Countries,
    "fdjparionssport": fdjparionssportCountries,
    "enilive": eniliveCountries,
    "nexon": nexonCountries,
    "ranglive": rangliveCountries,
    "beutea": beuteaCountries,
    "indiapolls": indiapollsCountries,
    "adityabirla": adityabirlaCountries,
    "heypiggy": heypiggyCountries,
    "neosurf": neosurfCountries,
    "tutti": tuttiCountries,
    "kredito": kreditoCountries,
    "sponline": sponlineCountries,
    "letgo": letgoCountries,
    "ideeopinioni": ideeopinioniCountries,
    "naturaavon": naturaavonCountries,
    "poe": poeCountries,
    "guvi": guviCountries,
    "quicktv": quicktvCountries,
    "kolotibablo": kolotibabloCountries,
    "mackolik": mackolikCountries,
    "zenmux": zenmuxCountries,
    "jalwagame": jalwagameCountries,
    "exness": exnessCountries,
    "tatamotors": tatamotorsCountries,
    "research360": research360Countries,
    "ludowinner": ludowinnerCountries,
    "mbmbet": mbmbetCountries,
    "longchau": longchauCountries,
    "timit": timitCountries,
    "wamba": wambaCountries,
    "adobe": adobeCountries,
    "dahadaha": dahadahaCountries,
    "guzmanygomez": guzmanygomezCountries,
    "swagbucks": swagbucksCountries,
    "ricardo": ricardoCountries,
    "ashleymadison": ashleymadisonCountries,
    "51game": fiftyonegameCountries,
    "storytv": storytvCountries,
    "ourtime": ourtimeCountries,
    "nielsen": nielsenCountries,
    "telnyx": telnyxCountries,
    "grok": grokCountries,
    "winmate": winmateCountries,
    "tonline": tonlineCountries,
    "dotandkey": dotandkeyCountries,
    "thedermaco": thedermacoCountries,
    "predik": predikCountries,
    "brevistay": brevistayCountries,
    "australiapost": australiapostCountries,
    "cheq": cheqCountries,
    "rupiyo": rupiyoCountries,
    "digitalocean": digitaloceanCountries,
    "fda": fdaCountries,
    "playtime": playtimeCountries,
    "betflag": betflagCountries,
    "sisal": sisalCountries,
    "lottomatica": lottomaticaCountries,
    "goldbet": goldbetCountries,
    "netwin": netwinCountries,
    "snai": snaiCountries,
    "eurobet": eurobetCountries,
};

const serviceCatalog = {
    whatsapp: {
        serviceType: 'whatsapp',
        serviceName: 'WhatsApp Number',
        serviceCode: SMSBOWER_WA_SERVICE,
        countries: whatsappCountries
    },
    facebook: {
        serviceType: 'facebook',
        serviceName: 'Facebook Number',
        serviceCode: SMSBOWER_FB_SERVICE,
        countries: facebookCountries
    },
    instagram: {
        serviceType: 'instagram',
        serviceName: 'Instagram Number',
        serviceCode: SMSBOWER_IG_SERVICE,
        countries: instagramCountries
    },
    snapchat: {
        serviceType: 'snapchat',
        serviceName: 'Snapchat Number',
        serviceCode: SMSBOWER_SNAPCHAT_SERVICE,
        countries: snapchatCountries
    },
    tiktok: {
        serviceType: 'tiktok',
        serviceName: 'TikTok Number',
        serviceCode: SMSBOWER_TIKTOK_SERVICE,
        countries: tiktokCountries
    },
    imo: {
        serviceType: 'imo',
        serviceName: 'Imo Messenger Number',
        serviceCode: SMSBOWER_IMO_SERVICE,
        countries: imoCountries
    },
    tinder: {
        serviceType: 'tinder',
        serviceName: 'Tinder Number',
        serviceCode: SMSBOWER_TINDER_SERVICE,
        countries: tinderCountries
    },
    twitter: {
        serviceType: 'twitter',
        serviceName: 'Twitter / X Number',
        serviceCode: SMSBOWER_TWITTER_SERVICE,
        countries: twitterCountries
    },
    amazon: {
        serviceType: 'amazon',
        serviceName: 'Amazon Number',
        serviceCode: SMSBOWER_AMAZON_SERVICE,
        countries: amazonCountries
    },
    alibaba: {
        serviceType: 'alibaba',
        serviceName: 'Alibaba Number',
        serviceCode: SMSBOWER_ALIBABA_SERVICE,
        countries: alibabaCountries
    },
    careem: {
        serviceType: 'careem',
        serviceName: 'Careem Number',
        serviceCode: SMSBOWER_CAREEM_SERVICE,
        countries: careemCountries
    },
    spotify: {
        serviceType: 'spotify',
        serviceName: 'Spotify Number',
        serviceCode: SMSBOWER_SPOTIFY_SERVICE,
        countries: spotifyCountries
    },
    openai: {
        serviceType: 'openai',
        serviceName: 'OpenAI / ChatGPT Number',
        serviceCode: SMSBOWER_OPENAI_SERVICE,
        countries: openaiCountries
    },
    paypal: {
        serviceType: 'paypal',
        serviceName: 'PayPal Number',
        serviceCode: SMSBOWER_PAYPAL_SERVICE,
        countries: paypalCountries
    },
    aliexpress: {
        serviceType: 'aliexpress',
        serviceName: 'AliExpress Number',
        serviceCode: SMSBOWER_ALIEXPRESS_SERVICE,
        countries: aliexpressCountries
    },
    wechat: {
        serviceType: 'wechat',
        serviceName: 'WeChat Number',
        serviceCode: SMSBOWER_WECHAT_SERVICE,
        countries: wechatCountries
    },
    viber: {
        serviceType: 'viber',
        serviceName: 'Viber Number',
        serviceCode: SMSBOWER_VIBER_SERVICE,
        countries: viberCountries
    },
    uber: {
        serviceType: 'uber',
        serviceName: 'Uber Number',
        serviceCode: SMSBOWER_UBER_SERVICE,
        countries: uberCountries
    },
    microsoft: {
        serviceType: 'microsoft',
        serviceName: 'Microsoft Number',
        serviceCode: SMSBOWER_MICROSOFT_SERVICE,
        countries: microsoftCountries
    },
    signal: {
        serviceType: 'signal',
        serviceName: 'Signal Number',
        serviceCode: SMSBOWER_SIGNAL_SERVICE,
        countries: signalCountries
    },
    easypay: {
        serviceType: 'easypay',
        serviceName: 'Easypay Number',
        serviceCode: SMSBOWER_EASYPAY_SERVICE,
        countries: easypayCountries
    },
    google: {
        serviceType: 'google',
        serviceName: 'Google / Gmail / YouTube Number',
        serviceCode: SMSBOWER_GOOGLE_SERVICE,
        countries: googleCountries
    }
};

function normalizeServiceLookup(value) {
    return String(value || '')
        .toLowerCase()
        .normalize('NFKD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
}

function createServiceTypeFromLabel(label, code = '') {
    const normalizedLabel = normalizeServiceLookup(label).replace(/\s+/g, '');
    if (normalizedLabel) return normalizedLabel;
    return String(code || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '')
        .trim();
}

function getServiceCatalogLabel(serviceConfig) {
    return String(serviceConfig?.serviceName || serviceConfig?.serviceType || '')
        .replace(/\s+number$/i, '')
        .trim();
}

function parseExtraServicesFromCatalogText(rawText, catalog) {
    const tokens = String(rawText || '')
        .split(/\r?\n/g)
        .map((line) => line.trim())
        .filter(Boolean);
    const seenLabels = new Set(Object.values(catalog).map((serviceConfig) => normalizeServiceLookup(getServiceCatalogLabel(serviceConfig))).filter(Boolean));
    const seenServiceTypes = new Set(Object.keys(catalog));
    const extras = [];

    for (let index = 0; index < tokens.length - 1; index += 1) {
        const code = tokens[index];
        const label = tokens[index + 1];
        if (!code || !label) continue;

        const looksLikeCode = !/\s/.test(code) && code.length <= 8;
        if (!looksLikeCode) continue;

        const normalizedLabel = normalizeServiceLookup(label);
        const serviceType = createServiceTypeFromLabel(label, code);
        const hasDuplicate = !normalizedLabel || !serviceType || seenLabels.has(normalizedLabel) || seenServiceTypes.has(serviceType);

        if (!hasDuplicate) {
            seenLabels.add(normalizedLabel);
            seenServiceTypes.add(serviceType);
            extras.push({ code, label, serviceType });
        }

        if (tokens[index + 2] === label) {
            index += 2;
        }
    }

    return extras;
}

const EXTRA_SERVICE_COUNTRY_FILES_DIR = path.join(__dirname, 'public', 'NUMBER ADDING IN SERVER JS');
const WHATSAPP_COUNTRY_FILE_PATH = path.join(__dirname, 'public', 'whatsapp.txt');
const EXTRA_SERVICE_COUNTRY_NAME_ALIASES = {
    'united states': 'usa',
    'united states of america': 'usa',
    'viet nam': 'vietnam',
    'lao peoples': 'laos',
    'lao people s': 'laos',
    'lao peoples democratic republic': 'laos',
    'lao people s democratic republic': 'laos',
    'cote d ivoire': 'ivory coast',
    'argentinas': 'argentina'
};

function normalizeCountryNameForFileLookup(value) {
    return normalizeServiceLookup(value).replace(/\s+/g, ' ').trim();
}

function sanitizeCountryNameFromServiceFile(value, serviceLabel = '') {
    let cleaned = String(value || '')
        .replace(/\*/g, '')
        .replace(/\s*\((?:[^)]*)\)\s*$/i, '')
        .trim();
    const escapedLabel = String(serviceLabel || '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (escapedLabel) {
        cleaned = cleaned.replace(new RegExp(`^${escapedLabel}\\s+`, 'i'), '').trim();
    }
    cleaned = cleaned.replace(/[^\p{L}\p{N}]+$/gu, '').trim();
    return cleaned;
}

function buildCountryReferenceLookup(catalog) {
    const byName = new Map();
    const addCountryReference = (country) => {
        const countryId = Number(country?.countryId);
        if (!Number.isFinite(countryId) || countryId <= 0) return;
        const reference = {
            name: String(country?.name || '').trim(),
            code: String(country?.code || '').trim(),
            countryId,
            flag: String(country?.flag || '').trim()
        };
        const directKey = normalizeCountryNameForFileLookup(reference.name);
        if (directKey && !byName.has(directKey)) {
            byName.set(directKey, reference);
        }
        getCountryCodeLookupKeys(country).forEach((aliasName) => {
            const aliasKey = normalizeCountryNameForFileLookup(aliasName);
            if (aliasKey && !byName.has(aliasKey)) {
                byName.set(aliasKey, reference);
            }
        });
    };

    Object.values(catalog).forEach((serviceConfig) => {
        const countries = Array.isArray(serviceConfig?.countries) ? serviceConfig.countries : [];
        countries.forEach(addCountryReference);
    });

    return { byName };
}

function resolveCountryReferenceFromLookup(countryName, lookup) {
    const normalizedName = normalizeCountryNameForFileLookup(countryName);
    if (!normalizedName) return null;
    if (lookup.byName.has(normalizedName)) {
        return lookup.byName.get(normalizedName) || null;
    }
    const aliasTarget = EXTRA_SERVICE_COUNTRY_NAME_ALIASES[normalizedName];
    if (aliasTarget) {
        const aliasKey = normalizeCountryNameForFileLookup(aliasTarget);
        if (lookup.byName.has(aliasKey)) {
            return lookup.byName.get(aliasKey) || null;
        }
    }
    return null;
}

function parseCountriesFromServiceText(rawText, lookup, serviceLabel = '') {
    const countries = [];
    const seenCountryIds = new Set();
    const unmatchedCountries = [];
    String(rawText || '')
        .split(/\r?\n/g)
        .map((line) => line.replace(/\*/g, '').trim())
        .filter(Boolean)
        .forEach((line) => {
            const match = line.match(/^(.*?)\s*(?:\W+\s*)?([0-9]+(?:\.[0-9]+)?)\s*PKR\b/i);
            if (!match) return;
            const rawCountryName = sanitizeCountryNameFromServiceFile(match[1], serviceLabel);
            const price = Number(match[2]);
            if (!rawCountryName || !Number.isFinite(price)) return;
            const reference = resolveCountryReferenceFromLookup(rawCountryName, lookup);
            if (!reference) {
                if (!unmatchedCountries.includes(rawCountryName)) unmatchedCountries.push(rawCountryName);
                return;
            }
            const countryIdKey = String(reference.countryId);
            if (seenCountryIds.has(countryIdKey)) return;
            seenCountryIds.add(countryIdKey);
            countries.push({
                name: reference.name,
                code: reference.code,
                price: Number(price.toFixed(2)),
                countryId: reference.countryId,
                flag: reference.flag
            });
        });
    return {
        countries,
        unmatchedCountries,
        parsedLineCount: countries.length + unmatchedCountries.length
    };
}

function extendWhatsappCountriesFromFile(catalog) {
    const whatsappService = catalog?.whatsapp;
    const existingCountries = Array.isArray(whatsappService?.countries) ? whatsappService.countries : [];
    if (!existingCountries.length) return;
    try {
        const rawText = fs.readFileSync(WHATSAPP_COUNTRY_FILE_PATH, 'utf8');
        const lookup = buildCountryReferenceLookup(catalog);
        const parsed = parseCountriesFromServiceText(rawText, lookup, 'whatsapp');
        const existingCountryIds = new Set(existingCountries.map((country) => String(country?.countryId ?? '').trim()).filter(Boolean));
        const lowOtpCountries = parsed.countries
            .filter((country) => !existingCountryIds.has(String(country?.countryId ?? '').trim()))
            .map((country) => ({
                ...country,
                code: country.code || (normalizeCountryNameForFileLookup(country.name) === 'australia' ? '+61' : ''),
                otpQuality: {
                    label: 'Low OTP',
                    defaultLabel: 'Low OTP',
                    successRate: 0,
                    totalOrders: 0,
                    successfulOrders: 0,
                    completedOrders: 0,
                    hasData: false,
                    hasEnoughData: false,
                    minimumCompletedOrders: 3
                }
            }));
        if (!lowOtpCountries.length) return;
        const usaIndex = existingCountries.findIndex((country) => String(country?.name || '').trim().toLowerCase() === 'usa' && Number(country?.countryId) === 187);
        whatsappService.countries = usaIndex >= 0
            ? [
                ...existingCountries.slice(0, usaIndex + 1),
                ...lowOtpCountries,
                ...existingCountries.slice(usaIndex + 1)
            ]
            : [...existingCountries, ...lowOtpCountries];
    } catch {
    }
}

function buildExtraServiceCountryArraysFromFiles(catalog) {
    const arraysByServiceType = { ...extraServiceCountryArraysByServiceType };
    let fileNames = [];
    try {
        fileNames = fs.readdirSync(EXTRA_SERVICE_COUNTRY_FILES_DIR)
            .filter((fileName) => /\.txt$/i.test(fileName))
            .sort((left, right) => left.localeCompare(right));
    } catch {
        return arraysByServiceType;
    }

    const lookup = buildCountryReferenceLookup(catalog);
    const bestCandidatesByServiceType = new Map();
    fileNames.forEach((fileName) => {
        const serviceLabel = fileName.replace(/\.txt$/i, '').trim();
        const serviceType = createServiceTypeFromLabel(serviceLabel);
        if (!serviceType) return;
        try {
            const rawText = fs.readFileSync(path.join(EXTRA_SERVICE_COUNTRY_FILES_DIR, fileName), 'utf8');
            const parsed = parseCountriesFromServiceText(rawText, lookup, serviceLabel);
            const currentBest = bestCandidatesByServiceType.get(serviceType);
            if (!currentBest
                || parsed.countries.length > currentBest.countries.length
                || (parsed.countries.length === currentBest.countries.length && parsed.parsedLineCount > currentBest.parsedLineCount)) {
                bestCandidatesByServiceType.set(serviceType, parsed);
            }
        } catch {
        }
    });

    bestCandidatesByServiceType.forEach((parsed, serviceType) => {
        arraysByServiceType[serviceType] = parsed.countries;
    });

    return arraysByServiceType;
}

function extendServiceCatalogWithExtraServices(catalog) {
    const catalogFilePath = path.join(__dirname, 'public', 'All Social Media Platform.txt');
    try {
        const rawText = fs.readFileSync(catalogFilePath, 'utf8');
        const extraServices = parseExtraServicesFromCatalogText(rawText, catalog);
        const extraCountryArraysByServiceType = buildExtraServiceCountryArraysFromFiles(catalog);
        extraServices.forEach((service) => {
            const countries = extraCountryArraysByServiceType[service.serviceType];
            if (!countries) return;
            catalog[service.serviceType] = {
                serviceType: service.serviceType,
                serviceName: `${service.label} Number`,
                serviceCode: service.code,
                countries
            };
        });
    } catch {
    }
}


const COUNTRY_CODE_NAME_ALIASES = {
    'usa virtual': ['usa', 'united states', 'united states of america'],
    uae: ['united arab emirates'],
    macedonia: ['north macedonia'],
    'north macedonia': ['macedonia'],
    'papua new gvineya': ['papua new guinea'],
    'cote d`ivoire ivory coast': ['ivory coast'],
    'cote d ivoire ivory coast': ['ivory coast'],
    'congo (dem. republic)': ['dr congo', 'democratic republic of the congo'],
    'congo dem. republic': ['dr congo', 'democratic republic of the congo'],
    'brunei darussalam': ['brunei']
};

function normalizeCountryNameForLookup(value) {
    return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function normalizeCountryDialCode(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const digits = raw.replace(/[^\d]/g, '');
    if (!digits) return '';
    return `+${digits}`;
}

function getCountryCodeLookupKeys(country) {
    const normalizedName = normalizeCountryNameForLookup(country?.name);
    if (!normalizedName) return [];
    const aliases = COUNTRY_CODE_NAME_ALIASES[normalizedName];
    const aliasList = Array.isArray(aliases)
        ? aliases
        : aliases
            ? [aliases]
            : [];
    return [normalizedName, ...aliasList.map((entry) => normalizeCountryNameForLookup(entry))]
        .filter(Boolean);
}

function buildCountryCodeLookup(catalog) {
    const byCountryId = new Map();
    const byCountryName = new Map();

    Object.values(catalog).forEach((serviceConfig) => {
        const countries = Array.isArray(serviceConfig?.countries) ? serviceConfig.countries : [];
        countries.forEach((country) => {
            const dialCode = normalizeCountryDialCode(country?.code);
            if (!dialCode) return;

            const countryIdKey = String(country?.countryId ?? '').trim();
            if (countryIdKey && !byCountryId.has(countryIdKey)) {
                byCountryId.set(countryIdKey, dialCode);
            }

            getCountryCodeLookupKeys(country).forEach((key) => {
                if (!byCountryName.has(key)) {
                    byCountryName.set(key, dialCode);
                }
            });
        });
    });

    return { byCountryId, byCountryName };
}

function resolveCountryDialCode(country, lookup) {
    const directCode = normalizeCountryDialCode(country?.code);
    if (directCode) return directCode;

    const countryIdKey = String(country?.countryId ?? '').trim();
    if (countryIdKey && lookup.byCountryId.has(countryIdKey)) {
        return lookup.byCountryId.get(countryIdKey) || '';
    }

    for (const key of getCountryCodeLookupKeys(country)) {
        if (lookup.byCountryName.has(key)) {
            return lookup.byCountryName.get(key) || '';
        }
    }

    return '';
}

function hydrateServiceCountryCodes(catalog) {
    const lookup = buildCountryCodeLookup(catalog);

    Object.values(catalog).forEach((serviceConfig) => {
        if (!Array.isArray(serviceConfig?.countries)) return;
        serviceConfig.countries = serviceConfig.countries.map((country) => {
            const resolvedCode = resolveCountryDialCode(country, lookup);
            if (!resolvedCode || resolvedCode === String(country?.code || '').trim()) {
                return country;
            }

            const updatedCountry = { ...country, code: resolvedCode };
            const countryIdKey = String(updatedCountry?.countryId ?? '').trim();
            if (countryIdKey && !lookup.byCountryId.has(countryIdKey)) {
                lookup.byCountryId.set(countryIdKey, resolvedCode);
            }
            getCountryCodeLookupKeys(updatedCountry).forEach((key) => {
                if (!lookup.byCountryName.has(key)) {
                    lookup.byCountryName.set(key, resolvedCode);
                }
            });
            return updatedCountry;
        });
    });
}

extendServiceCatalogWithExtraServices(serviceCatalog);
extendWhatsappCountriesFromFile(serviceCatalog);
hydrateServiceCountryCodes(serviceCatalog);

function getServiceConfig(serviceType) {
    return serviceCatalog[String(serviceType || '').trim().toLowerCase()] || null;
}

function sortCountriesByPrice(countries) {
    const list = Array.isArray(countries) ? [...countries] : [];
    return list.sort((left, right) => {
        const leftPrice = Number(left?.price ?? Number.POSITIVE_INFINITY);
        const rightPrice = Number(right?.price ?? Number.POSITIVE_INFINITY);
        if (leftPrice !== rightPrice) return leftPrice - rightPrice;
        return String(left?.name || '').localeCompare(String(right?.name || ''));
    });
}

function getDefaultCountryOtpQuality(seed = {}) {
    const defaultLabel = String(seed?.defaultLabel || seed?.label || 'Good OTP').trim() || 'Good OTP';
    const minimumCompletedOrders = Number(seed?.minimumCompletedOrders || 20);
    return {
        label: defaultLabel,
        defaultLabel,
        successRate: 0,
        totalOrders: 0,
        successfulOrders: 0,
        completedOrders: 0,
        hasData: false,
        hasEnoughData: false,
        minimumCompletedOrders: Number.isFinite(minimumCompletedOrders) && minimumCompletedOrders > 0 ? minimumCompletedOrders : 20
    };
}

function getCountryOtpQualityLabel(successRate, completedOrders, minimumCompletedOrders = 20, defaultLabel = 'Good OTP') {
    if (Number(completedOrders || 0) < Number(minimumCompletedOrders || 20)) return defaultLabel;
    if (successRate >= 0.85) return 'Excellent OTP';
    if (successRate >= 0.65) return 'Good OTP';
    if (successRate >= 0.4) return 'Average OTP';
    return 'Low OTP';
}

async function getCountryOtpPerformanceMap(serviceType) {
    const normalizedServiceType = String(serviceType || '').trim().toLowerCase();
    if (!normalizedServiceType) return new Map();
    const rows = await queryAll(`
        SELECT
            country_id,
            LOWER(TRIM(COALESCE(country, ''))) AS country_name_key,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(status, order_status, 'pending')) IN ('completed', 'cancelled', 'expired', 'expired_refunded')
            )::int AS total_orders,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(status, order_status, 'pending')) = 'completed'
            )::int AS successful_orders
        FROM orders
        WHERE LOWER(COALESCE(service_type, '')) = $1
        GROUP BY country_id, LOWER(TRIM(COALESCE(country, '')))
    `, [normalizedServiceType]);
    const performanceMap = new Map();
    rows.forEach((row) => {
        const totalOrders = Number(row.total_orders || 0);
        const successfulOrders = Number(row.successful_orders || 0);
        const completedOrders = successfulOrders;
        const successRate = totalOrders > 0 ? successfulOrders / totalOrders : 0;
        const otpQuality = {
            label: getCountryOtpQualityLabel(successRate, completedOrders),
            successRate,
            totalOrders,
            successfulOrders,
            completedOrders,
            hasData: totalOrders > 0,
            hasEnoughData: completedOrders >= 20
        };
        const countryIdKey = String(row.country_id ?? '').trim();
        const countryNameKey = String(row.country_name_key || '').trim();
        if (countryIdKey) performanceMap.set(`id:${countryIdKey}`, otpQuality);
        if (countryNameKey) performanceMap.set(`name:${countryNameKey}`, otpQuality);
    });
    return performanceMap;
}

async function decorateCountriesWithOtpQuality(serviceType, countries) {
    const normalizedServiceType = String(serviceType || '').trim().toLowerCase();
    const baseCountries = normalizedServiceType === 'whatsapp'
        ? (Array.isArray(countries) ? [...countries] : [])
        : sortCountriesByPrice(countries);
    let performanceMap = new Map();
    try {
        performanceMap = await getCountryOtpPerformanceMap(serviceType);
    } catch (err) {
        console.error(`Country OTP quality lookup failed for ${String(serviceType || 'unknown')}: ${formatSafeError(err, 'Unknown country OTP quality error')}`);
    }
    return baseCountries.map((country) => {
        const countryIdKey = String(country?.countryId ?? '').trim();
        const countryNameKey = String(country?.name || '').trim().toLowerCase();
        const seededOtpQuality = country?.otpQuality && typeof country.otpQuality === 'object'
            ? country.otpQuality
            : null;
        const defaultOtpQuality = getDefaultCountryOtpQuality(seededOtpQuality || undefined);
        const performanceOtpQuality = (countryIdKey && performanceMap.get(`id:${countryIdKey}`))
            || (countryNameKey && performanceMap.get(`name:${countryNameKey}`))
            || null;
        const otpQuality = performanceOtpQuality
            ? {
                ...defaultOtpQuality,
                ...performanceOtpQuality,
                label: getCountryOtpQualityLabel(
                    performanceOtpQuality.successRate,
                    performanceOtpQuality.completedOrders,
                    defaultOtpQuality.minimumCompletedOrders,
                    defaultOtpQuality.defaultLabel
                ),
                hasEnoughData: Number(performanceOtpQuality.completedOrders || 0) >= defaultOtpQuality.minimumCompletedOrders
            }
            : defaultOtpQuality;
        return {
            ...country,
            otpQuality: { ...otpQuality }
        };
    });
}

function parseV1NumberResponse(text) {
    const raw = String(text || '').trim();
    if (raw.startsWith('ACCESS_NUMBER:')) {
        const parts = raw.split(':');
        if (parts.length >= 3) {
            return {
                success: true,
                activationId: parts[1],
                phoneNumber: parts[2].startsWith('+') ? parts[2] : `+${parts[2]}`
            };
        }
    }
    return { success: false, error: raw || 'No number available' };
}

function parseNumberResponse(data) {
    if (typeof data === 'string') {
        const trimmed = data.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                return parseNumberResponse(JSON.parse(trimmed));
            } catch {
                return parseV1NumberResponse(trimmed);
            }
        }
        return parseV1NumberResponse(trimmed);
    }
    if (data && typeof data === 'object') {
        if (data.activationId && data.phoneNumber) {
            return {
                success: true,
                activationId: String(data.activationId),
                phoneNumber: String(data.phoneNumber).startsWith('+')
                    ? String(data.phoneNumber)
                    : `+${String(data.phoneNumber)}`
            };
        }
    }
    return { success: false, error: 'No number available' };
}

function extractProvidersRecursive(node, bucket = [], seen = new Set()) {
    if (!node || typeof node !== 'object') return bucket;
    if (
        Object.prototype.hasOwnProperty.call(node, 'provider_id') &&
        Object.prototype.hasOwnProperty.call(node, 'price')
    ) {
        const providerId = Number(node.provider_id);
        const providerPrice = Number(node.price);
        if (!Number.isNaN(providerId) && !Number.isNaN(providerPrice)) {
            const key = `${providerId}:${providerPrice}`;
            if (!seen.has(key)) {
                seen.add(key);
                bucket.push({
                    provider_id: providerId,
                    price: providerPrice,
                    count: node.count
                });
            }
        }
    }
    for (const value of Object.values(node)) {
        if (value && typeof value === 'object') {
            extractProvidersRecursive(value, bucket, seen);
        }
    }
    return bucket;
}

async function fetchProviderTiers(countryId, serviceCode = 'wa') {
    const url = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=getPricesV3&service=${serviceCode}&country=${countryId}`;
    const response = await axios.get(url, { timeout: 15000 });
    const data = response.data;
    let providers = [];
    if (data && typeof data === 'object') {
        const countryNode =
            data[String(countryId)] ??
            data[countryId] ??
            (Object.keys(data).length === 1 ? Object.values(data)[0] : null);
        const serviceNode =
            countryNode?.[serviceCode] ??
            (countryNode && Object.keys(countryNode).length === 1 ? Object.values(countryNode)[0] : null);
        providers = extractProvidersRecursive(serviceNode || data);
    }
    providers = providers
        .filter((p) => Number.isFinite(p.provider_id) && Number.isFinite(p.price))
        .sort((a, b) => a.price - b.price);
    return providers;
}

async function buyNumberFromProvider(countryId, provider, serviceCode = 'wa') {
    const url =
        `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}` +
        `&action=getNumberV2` +
        `&service=${serviceCode}` +
        `&country=${countryId}` +
        `&maxPrice=${provider.price}` +
        `&providerIds=${provider.provider_id}`;
    try {
        const response = await axios.get(url, { timeout: 15000 });
        const parsed = parseNumberResponse(response.data);
        if (parsed.success) {
            return {
                ...parsed,
                provider_id: provider.provider_id,
                provider_price: provider.price
            };
        }
        return { success: false, error: parsed.error || 'No number from provider' };
    } catch (err) {
        return { success: false, error: err.message };
    }
}

async function buyNumberByTierStrategy(countryId, clientMaxUsd, serviceCode = 'wa') {
    try {
        const providers = await fetchProviderTiers(countryId, serviceCode);
        const affordableProviders = providers
            .filter((p) => p.price <= clientMaxUsd + 0.000001)
            .slice(0, 5);
        if (!affordableProviders.length) {
            return {
                success: false,
                strategy: 'provider_unavailable',
                error: 'No provider tiers available in your price range'
            };
        }
        for (const provider of affordableProviders) {
            const startedAt = Date.now();
            let lastError = 'No number from provider';
            while (Date.now() - startedAt < 15000) {
                const result = await buyNumberFromProvider(countryId, provider, serviceCode);
                if (result.success) {
                    return {
                        success: true,
                        activationId: result.activationId,
                        phoneNumber: result.phoneNumber,
                        strategy: 'provider',
                        provider_id: result.provider_id,
                        provider_price: result.provider_price
                    };
                }
                lastError = result.error || lastError;
                const elapsed = Date.now() - startedAt;
                const remaining = 15000 - elapsed;
                if (remaining <= 0) break;
                await waitMs(Math.min(5000, remaining));
            }
        }
        return {
            success: false,
            strategy: 'provider_exhausted',
            error: 'No number found in lowest 5 price tiers'
        };
    } catch (err) {
        return {
            success: false,
            strategy: 'provider_unavailable',
            error: err.message
        };
    }
}

async function buyNumberWithRetry(countryId, baseUsdPrice, maxAttempts = 3, serviceCode = 'wa') {
    const priceSteps = [];
    for (let i = 0; i < maxAttempts; i++) {
        priceSteps.push((baseUsdPrice * (1 + i * 0.05)).toFixed(3));
    }
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const maxPriceUSD = priceSteps[attempt - 1];
        try {
            const url = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=getNumber&service=${serviceCode}&country=${countryId}&maxPrice=${maxPriceUSD}`;
            const response = await axios.get(url, { timeout: 15000 });
            const parsed = parseNumberResponse(response.data);
            if (parsed.success) {
                return {
                    success: true,
                    activationId: parsed.activationId,
                    phoneNumber: parsed.phoneNumber,
                    strategy: 'fallback'
                };
            }
            if (attempt < maxAttempts) {
                await waitMs(8000);
            }
        } catch (err) {
            if (attempt === maxAttempts) {
                return { success: false, error: err.message };
            }
            await waitMs(8000);
        }
    }
    return { success: false, error: 'No number available after all attempts' };
}

async function getBestAvailableNumber(countryId, clientMaxUsd, serviceCode = 'wa') {
    let result = await buyNumberByTierStrategy(countryId, clientMaxUsd, serviceCode);
    if (!result.success && result.strategy === 'provider_unavailable') {
        result = await buyNumberWithRetry(countryId, clientMaxUsd, 3, serviceCode);
    }
    return result;
}

async function checkSmsStatus(activationId) {
    try {
        const url = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=getStatus&id=${activationId}`;
        const response = await axios.get(url, { timeout: 15000 });
        const resText = String(response.data || '').trim();
        if (resText.startsWith('STATUS_OK:')) {
            return { success: true, code: resText.split(':')[1] };
        }
        if (resText === 'STATUS_WAIT_CODE') {
            return { success: true, waiting: true };
        }
        return { success: false, raw: resText };
    } catch (err) {
        return { success: false, error: err.message };
    }
}

function ensureAuth(req, res, next) {
    if (!req.session.userId) return res.status(401).send('Login required');
    next();
}

async function ensureAdmin(req, res, next) {
    try {
        if (!req.session.userId) return res.status(401).send('Login required');
        const user = await findUserById(req.session.userId);
        if (!isAdminUser(user)) return res.status(403).send('Admin only');
        req.user = user;
        next();
    } catch {
        res.status(500).send('Server error');
    }
}

const authRoutes = createAuthRouter
    ? createAuthRouter({
        passport,
        queryOne,
        queryRun,
        hashPassword,
        randomPassword,
        sanitizeEmail,
        updateUserLastLogin,
        updateUserLoginAttempts,
        googleClientId: GOOGLE_CLIENT_ID,
        googleClientSecret: GOOGLE_CLIENT_SECRET,
        googleCallbackUrl: GOOGLE_CALLBACK_URL
    })
    : express.Router();

if (!createAuthRouter) {
    console.error('Authentication routes are disabled because the auth module could not be loaded.');
    authRoutes.use((_req, res) => {
        res.status(503).send('Authentication service is temporarily unavailable');
    });
}

app.use('/auth', authRoutes);

app.get('/admin', ensureAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/countries', async (req, res) => {
    try {
        res.json(await decorateCountriesWithOtpQuality('whatsapp', serviceCatalog.whatsapp.countries));
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/facebook/countries', async (req, res) => {
    try {
        res.json(await decorateCountriesWithOtpQuality('facebook', serviceCatalog.facebook.countries));
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/services/:service/countries', async (req, res) => {
    const serviceConfig = getServiceConfig(req.params.service);
    if (!serviceConfig) return res.status(404).send('Service not found');
    try {
        res.json(await decorateCountriesWithOtpQuality(serviceConfig.serviceType || req.params.service, serviceConfig.countries));
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/auth/google', (req, res) => {
    return res.redirect('/auth/google');
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        if (!isMailConfigured()) {
            return res.status(503).send('Password reset email is not configured');
        }
        const email = sanitizeEmail(req.body.email);
        if (!validateEmail(email)) return res.status(400).send('Valid email is required');
        const user = await findUser(email);
        if (user) {
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_TTL_MS).toISOString();
            await savePasswordResetToken(user.id, hashToken(token), expiresAt);
            await sendPasswordResetEmail(user, token);
        }
        res.json({ success: true, message: 'If an account exists for that email, a reset link has been sent.' });
    } catch (err) {
        res.status(500).send(formatSafeError(err, 'Could not send password reset email'));
    }
});

app.get('/api/admin/users', ensureAdmin, async (req, res) => {
    try {
        const users = await getAdminUsers();
        res.json(users);
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/admin/balance-adjustments', ensureAdmin, async (req, res) => {
    try {
        const adjustments = await getAllBalanceAdjustments();
        res.json(adjustments);
    } catch {
        res.status(500).send('Server error');
    }
});

app.post('/api/admin/users/:userId/adjust-balance', ensureAdmin, async (req, res) => {
    try {
        const targetUserId = Number(req.params.userId);
        const amount = Number(req.body.amount);
        const reason = String(req.body.reason || '').trim();

        if (!Number.isFinite(targetUserId) || targetUserId <= 0) {
            return res.status(400).send('Invalid user id');
        }
        if (!Number.isFinite(amount) || amount === 0) {
            return res.status(400).send('Amount must be a non-zero number');
        }
        if (!reason) {
            return res.status(400).send('Reason is required');
        }

        const updatedUser = await applyAdminBalanceAdjustment({
            userId: targetUserId,
            adminId: req.user.id,
            amount,
            reason
        });

        res.json({
            success: true,
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                name: updatedUser.name,
                balance: updatedUser.balance
            }
        });
    } catch (err) {
        res.status(400).send(formatSafeError(err, 'Balance adjustment failed'));
    }
});

app.get('/api/admin/users/:userId/history', ensureAdmin, async (req, res) => {
    try {
        const targetUserId = Number(req.params.userId);
        if (!Number.isFinite(targetUserId) || targetUserId <= 0) {
            return res.status(400).send('Invalid user id');
        }
        const history = await getUserCombinedHistory(targetUserId);
        res.json(history);
    } catch {
        res.status(500).send('Server error');
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const token = String(req.body.token || '').trim();
        const newPassword = req.body.newPassword;
        if (!token) return res.status(400).send('Reset token is required');
        if (!validatePassword(newPassword)) {
            return res.status(400).send('New password must be at least 6 characters');
        }
        const user = await findUserByResetToken(token);
        if (!user) return res.status(400).send('Reset link is invalid or expired');
        await updateUserPassword(user.id, newPassword);
        await clearPasswordResetToken(user.id);
        await updateUserLoginAttempts(user.id, 0);
        await queryRun('UPDATE users SET is_active = TRUE WHERE id = $1', [user.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).send(formatSafeError(err, 'Could not reset password'));
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const email = sanitizeEmail(req.body.email);
        const password = req.body.password;
        if (!name) return res.status(400).send('Name is required');
        if (!validateEmail(email)) return res.status(400).send('Valid email is required');
        if (!validatePassword(password)) return res.status(400).send('Password must be at least 6 characters');
        const existing = await findUser(email);
        if (existing) return res.status(400).send('Email already exists');
        await createUser(name, email, password);
        res.json({ success: true });
    } catch (err) {
        res.status(500).send(formatSafeError(err));
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const email = sanitizeEmail(req.body.email);
        const password = req.body.password;
        if (!validateEmail(email)) return res.status(400).send('Valid email is required');
        if (typeof password !== 'string' || !password) return res.status(400).send('Password is required');
        const user = await findUser(email);
        if (!user) {
            return res.status(401).send('Invalid credentials');
        }
        if (!user.is_active) {
            return res.status(401).send('Account blocked');
        }
        const passwordCheck = await verifyPassword(password, user.password);
        if (!passwordCheck.valid) {
            const newAttempts = Number(user.login_attempts || 0) + 1;
            await updateUserLoginAttempts(user.id, newAttempts);
            if (newAttempts >= 5) {
                await queryRun('UPDATE users SET is_active = FALSE WHERE id = $1', [user.id]);
            }
            return res.status(401).send('Invalid credentials');
        }
        if (passwordCheck.needsUpgrade) {
            const upgradedHash = await hashPassword(password);
            await updateUserPasswordHash(user.id, upgradedHash);
        }
        await updateUserLoginAttempts(user.id, 0);
        await updateUserLastLogin(user.id);
        req.session.regenerate((regenErr) => {
            if (regenErr) {
                console.error('Session regenerate error:', regenErr);
                return res.status(500).send('Login failed');
            }
            req.session.userId = user.id;
            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('Session save error:', saveErr);
                    return res.status(500).send('Login failed');
                }
                return res.json({ success: true });
            });
        });
    } catch (err) {
        console.error('Login route error:', err);
        res.status(500).send(formatSafeError(err));
    }
});

app.post('/api/change-password', ensureAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (typeof currentPassword !== 'string' || !currentPassword) {
            return res.status(400).send('Current password is required');
        }
        if (!validatePassword(newPassword)) {
            return res.status(400).send('New password must be at least 6 characters');
        }
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(404).send('User not found');
        const passwordCheck = await verifyPassword(currentPassword, user.password);
        if (!passwordCheck.valid) {
            return res.status(400).send('Current password is incorrect');
        }
        await updateUserPassword(user.id, newPassword);
        res.send('OK');
    } catch (err) {
        res.status(500).send(formatSafeError(err));
    }
});

app.get('/api/me', ensureAuth, async (req, res) => {
    try {
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            balance: user.balance,
            role: user.role,
            isAdmin: isAdminUser(user),
            referralCode: user.referralCode,
            maskedPassword: '********'
        });
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            res.clearCookie('mrf.sid');
            res.send('OK');
        });
    });
});

app.post('/api/order', ensureAuth, async (req, res) => {
    const client = await pool.connect();
    let activationToRelease = null;
    try {
        const { countryName, countryId, service } = req.body;
        const idempotencyKey = String(req.body.idempotencyKey || '').trim();
        if (!idempotencyKey || idempotencyKey.length < 8) {
            return res.status(400).send('Idempotency key is required');
        }
        const serviceConfig = getServiceConfig(service || 'whatsapp');
        if (!serviceConfig) return res.status(400).send('Invalid service selected');
        const countryObj = serviceConfig.countries.find((c) => c.name === countryName && Number(c.countryId) === Number(countryId));
        if (!countryObj) return res.status(400).send('Invalid country selected');
        const existingQuickMatch = await queryOne(
            'SELECT id, phone_number FROM orders WHERE user_id = $1 AND idempotency_key = $2 ORDER BY id DESC LIMIT 1',
            [req.session.userId, idempotencyKey]
        );
        if (existingQuickMatch) {
            return res.json({ id: existingQuickMatch.id, number: existingQuickMatch.phone_number, duplicate: true });
        }
        const orderPrice = Number(countryObj.price || 0);
        if (orderPrice <= 0) {
            return res.status(400).send('Price not configured for selected service');
        }

        const clientMaxUsd = pkrToUsd(orderPrice);
        const result = await getBestAvailableNumber(countryObj.countryId, clientMaxUsd, serviceConfig.serviceCode);
        if (!result.success) {
            return res.status(500).send('Number not available yet, please try again later');
        }
        activationToRelease = result.activationId || null;

        const providerCostPKR = Number((Number(result.provider_price || 0) * 280).toFixed(2));
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 25 * 60 * 1000).toISOString();
        const cancelAvailableAt = new Date(now.getTime() + 17 * 1000).toISOString();

        await client.query('BEGIN');
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
        const user = userRes.rows[0];
        if (!user) {
            await client.query('ROLLBACK');
            return res.status(401).send('User not found');
        }

        const existingByIdempotency = await client.query(
            'SELECT id, phone_number FROM orders WHERE user_id = $1 AND idempotency_key = $2 ORDER BY id DESC LIMIT 1',
            [user.id, idempotencyKey]
        );
        if (existingByIdempotency.rowCount > 0) {
            await client.query('COMMIT');
            activationToRelease = result.activationId || null;
            return res.json({
                id: existingByIdempotency.rows[0].id,
                number: existingByIdempotency.rows[0].phone_number,
                duplicate: true
            });
        }

        const activeOrdersCountRes = await client.query(
            `
                SELECT COUNT(*)::int AS total
                FROM orders
                WHERE user_id = $1
                  AND COALESCE(status, order_status, 'pending') IN ('pending', 'active')
            `,
            [user.id]
        );
        const activeOrdersCount = Number(activeOrdersCountRes.rows[0]?.total || 0);
        if (activeOrdersCount >= 10) {
            await client.query('ROLLBACK');
            return res.status(409).send('You can only have 10 active orders at a time. Complete or cancel one first.');
        }

        const deductionRes = await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance',
            [orderPrice, user.id]
        );
        if (deductionRes.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(400).send('Insufficient balance. Please add funds.');
        }

        const inserted = await client.query(`
            INSERT INTO orders (
                user_id, user_email, service_type, service_name, country, country_code, country_id, price, provider_cost_pkr,
                payment_method, order_status, status, phone_number, activation_id,
                expires_at, cancel_available_at, last_purchase_at, idempotency_key, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
            RETURNING id
        `, [
            user.id,
            user.email,
            serviceConfig.serviceType,
            serviceConfig.serviceName,
            countryName,
            countryObj.code,
            countryObj.countryId,
            orderPrice,
            providerCostPKR,
            'balance',
            'pending',
            'pending',
            result.phoneNumber,
            result.activationId,
            expiresAt,
            cancelAvailableAt,
            now.toISOString(),
            idempotencyKey,
            now.toISOString()
        ]);
        await client.query(
            'INSERT INTO transactions (user_id, user_email, amount, type, status, description) VALUES ($1, $2, $3, $4, $5, $6)',
            [user.id, user.email, orderPrice, 'deduction', 'approved', `${serviceConfig.serviceName} • ${countryName}`]
        );
        await client.query('COMMIT');
        activationToRelease = null;
        res.json({ id: inserted.rows[0].id, number: result.phoneNumber });
    } catch (err) {
        try {
            await client.query('ROLLBACK');
        } catch {
        }
        if (err && err.code === '23505') {
            const dedupedOrder = await queryOne(
                'SELECT id, phone_number FROM orders WHERE user_id = $1 AND idempotency_key = $2 ORDER BY id DESC LIMIT 1',
                [req.session.userId, String(req.body.idempotencyKey || '').trim()]
            );
            if (dedupedOrder) {
                return res.json({ id: dedupedOrder.id, number: dedupedOrder.phone_number, duplicate: true });
            }
        }
        res.status(500).send(formatSafeError(err, 'Order failed. Please try again.'));
    } finally {
        if (activationToRelease) {
            await updateProviderActivationStatus(activationToRelease, 8);
        }
        client.release();
    }
});

app.get('/api/orders/:orderId', ensureAuth, async (req, res) => {
    try {
        let order = await getOrderById(Number(req.params.orderId));
        if (!order) return res.status(404).send('Order not found');
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        if (order.user_id !== user.id && !isAdminUser(user)) {
            return res.status(403).send('Unauthorized');
        }
        if (String(order.status || order.order_status || '').toLowerCase() === 'pending' && !order.otp_received && order.expires_at && new Date() >= new Date(order.expires_at)) {
            await expireOrderAndRefund(order.id);
            order = await getOrderById(order.id);
        }
        res.json(order);
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/orders', ensureAuth, async (req, res) => {
    try {
        await reconcileExpiredOrdersForUser(req.session.userId);
        const userOrders = await getOrdersByUser(req.session.userId);
        res.json(userOrders);
    } catch {
        res.status(500).send('Server error');
    }
});

app.post('/api/orders/:orderId/cancel', ensureAuth, async (req, res) => {
    const client = await pool.connect();
    try {
        const orderId = Number(req.params.orderId);
        await client.query('BEGIN');
        const orderRes = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [orderId]);
        const order = orderRes.rows[0];
        if (!order) {
            await client.query('ROLLBACK');
            return res.status(404).send('Order not found');
        }
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [req.session.userId]);
        const user = userRes.rows[0];
        if (!user || order.user_id !== user.id) {
            await client.query('ROLLBACK');
            return res.status(403).send('Unauthorized');
        }
        if (String(order.status || order.order_status || '').toLowerCase() !== 'pending') {
            await client.query('ROLLBACK');
            return res.status(400).send('Cannot cancel now');
        }
        if (order.otp_received) {
            await client.query('ROLLBACK');
            return res.status(400).send('OTP already received, cannot cancel');
        }
        const now = new Date();
        const expiry = order.expires_at ? new Date(order.expires_at) : null;
        if (expiry && now >= expiry && !order.otp_received && String(order.status || order.order_status || '').toLowerCase() === 'pending') {
            await client.query('ROLLBACK');
            const expireResult = await expireOrderAndRefund(order.id);
            return res.send(expireResult.message || EXPIRED_REFUND_MESSAGE);
        }
        const cancelAvailable = new Date(order.cancel_available_at);
        if (now < cancelAvailable) {
            await client.query('ROLLBACK');
            return res.status(400).send(`Please wait ${Math.ceil((cancelAvailable - now) / 1000)} seconds before cancelling.`);
        }
        try {
            const cancelUrl = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=setStatus&id=${order.activation_id}&status=8`;
            await axios.get(cancelUrl, { timeout: 15000 });
        } catch {}
        await client.query('UPDATE users SET balance = $1 WHERE id = $2', [
            Number(user.balance || 0) + Number(order.price || 0),
            user.id
        ]);
        await client.query('UPDATE orders SET order_status = $1, status = $2 WHERE id = $3', ['cancelled', 'cancelled', order.id]);
        await client.query('COMMIT');
        res.send('OK');
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).send(formatSafeError(err, 'Cancel failed'));
    } finally {
        client.release();
    }
});

app.post('/api/orders/:orderId/complete', ensureAuth, async (req, res) => {
    try {
        const order = await getOrderById(Number(req.params.orderId));
        if (!order) return res.status(404).send('Order not found');
        const user = await findUserById(req.session.userId);
        if (!user || order.user_id !== user.id) return res.status(403).send('Unauthorized');
        if (!order.otp_received) return res.status(400).send('Cannot complete without OTP');
        try {
            const completeUrl = `${SMSBOWER_URL}?api_key=${SMSBOWER_API_KEY}&action=setStatus&id=${order.activation_id}&status=6`;
            await axios.get(completeUrl, { timeout: 15000 });
        } catch {}
        await updateOrder(order.id, {
            order_status: 'completed',
            status: 'completed',
            completed_at: new Date().toISOString()
        });
        res.send('OK');
    } catch (err) {
        res.status(500).send(formatSafeError(err, 'Complete failed'));
    }
});

app.post('/api/orders/:orderId/expire', ensureAuth, async (req, res) => {
    try {
        const order = await getOrderById(Number(req.params.orderId));
        if (!order) return res.status(404).send('Order not found');
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        if (order.user_id !== user.id && !isAdminUser(user)) {
            return res.status(403).send('Unauthorized');
        }
        const expireResult = await expireOrderAndRefund(order.id);
        res.json({
            expired: expireResult.expired,
            refunded: expireResult.refunded,
            message: expireResult.expired ? expireResult.message : 'Order is still active.',
            order: expireResult.order
        });
    } catch (err) {
        res.status(500).send(formatSafeError(err, 'Expire failed'));
    }
});

app.get('/api/orders/:orderId/otp', ensureAuth, async (req, res) => {
    try {
        const order = await getOrderById(Number(req.params.orderId));
        if (!order) return res.status(404).send('Order not found');
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        if (order.user_id !== user.id && !isAdminUser(user)) {
            return res.status(403).send('Unauthorized');
        }
        if (String(order.status || order.order_status || '').toLowerCase() === 'expired') {
            return res.json({ received: false, expired: true, refunded: true, message: EXPIRED_REFUND_MESSAGE });
        }
        if (order.otp_received) {
            return res.json({ received: true, code: order.otp_code });
        }
        if (String(order.status || order.order_status || '').toLowerCase() !== 'pending') {
            return res.json({ received: false, inactive: true, status: order.status || order.order_status });
        }
        if (!order.activation_id) {
            return res.json({ received: false, error: 'No activation ID' });
        }
        const now = new Date();
        const expiry = new Date(order.expires_at);
        if (now >= expiry && !order.otp_received && String(order.status || order.order_status || '').toLowerCase() === 'pending') {
            const expireResult = await expireOrderAndRefund(order.id);
            return res.json({
                received: false,
                expired: true,
                refunded: expireResult.refunded,
                message: expireResult.message || EXPIRED_REFUND_MESSAGE
            });
        }
        if (String(order.status || order.order_status || '').toLowerCase() !== 'pending') {
            return res.json({ received: false, inactive: true, status: order.status || order.order_status });
        }
        const smsResult = await checkSmsStatus(order.activation_id);
        if (smsResult.success && smsResult.code) {
            await updateOrder(order.id, {
                otp_received: true,
                otp_code: smsResult.code,
                order_status: 'active',
                status: 'active'
            });
            return res.json({ received: true, code: smsResult.code });
        }
        if (smsResult.success && smsResult.waiting) {
            return res.json({ received: false, waiting: true });
        }
        return res.json({ received: false, error: true });
    } catch {
        res.status(500).json({ received: false, error: true });
    }
});

app.get('/api/admin/orders', ensureAdmin, async (req, res) => {
    try {
        const allOrders = await getAllOrders();
        res.json(allOrders);
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/admin/transactions', ensureAdmin, async (req, res) => {
    try {
        const pending = await getPendingTransactions();
        res.json(pending);
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/admin/transactions/history', ensureAdmin, async (req, res) => {
    try {
        const history = await getTransactionHistory();
        res.json(history);
    } catch {
        res.status(500).send('Server error');
    }
});

app.post('/api/admin/transactions/:txId/approve', ensureAdmin, async (req, res) => {
    try {
        await approveTransaction(Number(req.params.txId));
        res.send('OK');
    } catch (err) {
        res.status(404).send(formatSafeError(err, 'Transaction not found'));
    }
});

app.post('/api/admin/transactions/:txId/cancel', ensureAdmin, async (req, res) => {
    try {
        await cancelTransaction(Number(req.params.txId));
        res.send('OK');
    } catch (err) {
        res.status(404).send(formatSafeError(err, 'Transaction not found'));
    }
});

app.post('/api/request-payment', ensureAuth, upload.single('screenshot'), async (req, res) => {
    try {
        const amount = parseFloat(req.body.amount);
        if (!amount || amount < 100) return res.status(400).send('Minimum amount 100 PKR');
        if (paymentRateLimiter[req.session.userId] && Date.now() - paymentRateLimiter[req.session.userId] < 60000) {
            return res.status(429).send('Please wait 1 minute between requests');
        }
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        const transaction_id = typeof req.body.transaction_id === 'string' ? req.body.transaction_id.trim() : '';
        const screenshot = req.file ? req.file.filename : null;
        if (!screenshot && !transaction_id) return res.status(400).send('Screenshot or transaction ID is required');
        await queryRun(
            'INSERT INTO payment_requests (user_id, user_email, amount, transaction_id, screenshot, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [req.session.userId, user.email, amount, transaction_id || null, screenshot, 'pending']
        );
        paymentRateLimiter[req.session.userId] = Date.now();
        res.json({ success: true });
    } catch (err) {
        if (err && err.code === '23505') {
            return res.status(400).send('This transaction ID has already been submitted');
        }
        res.status(500).send(formatSafeError(err));
    }
});

app.post('/api/add-funds', ensureAuth, upload.single('screenshot'), async (req, res) => {
    try {
        const amount = parseFloat(req.body.amount);
        if (!amount || amount < 100) return res.status(400).send('Minimum amount 100 PKR');
        if (paymentRateLimiter[req.session.userId] && Date.now() - paymentRateLimiter[req.session.userId] < 60000) {
            return res.status(429).send('Please wait 1 minute between requests');
        }
        const user = await findUserById(req.session.userId);
        if (!user) return res.status(401).send('User not found');
        const transaction_id = typeof req.body.transaction_id === 'string' ? req.body.transaction_id.trim() : '';
        const screenshot = req.file ? req.file.filename : null;
        if (!screenshot && !transaction_id) return res.status(400).send('Screenshot or transaction ID is required');
        await queryRun(
            'INSERT INTO payment_requests (user_id, user_email, amount, transaction_id, screenshot, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [req.session.userId, user.email, amount, transaction_id || null, screenshot, 'pending']
        );
        paymentRateLimiter[req.session.userId] = Date.now();
        res.json({ success: true });
    } catch (err) {
        if (err && err.code === '23505') {
            return res.status(400).send('This transaction ID has already been submitted');
        }
        res.status(500).send(formatSafeError(err));
    }
});

app.get('/api/admin/payment-requests', ensureAdmin, async (req, res) => {
    try {
        const requests = await getAllPaymentRequests();
        res.json(requests);
    } catch {
        res.status(500).send('Server error');
    }
});

app.get('/api/my-payment-history', ensureAuth, async (req, res) => {
    try {
        const requests = await getPaymentHistoryByUser(req.session.userId);
        res.json(requests);
    } catch {
        res.status(500).send('Server error');
    }
});

app.post('/api/admin/payment-requests/:id/approve', ensureAdmin, async (req, res) => {
    const client = await pool.connect();
    let screenshotToDelete = null;
    try {
        await client.query('BEGIN');
        const requestRes = await client.query('SELECT * FROM payment_requests WHERE id = $1 FOR UPDATE', [Number(req.params.id)]);
        const paymentRequest = requestRes.rows[0];
        if (!paymentRequest) throw new Error('Payment request not found');
        if (paymentRequest.status !== 'pending') throw new Error('Only pending payment requests can be approved');
        screenshotToDelete = paymentRequest.screenshot || null;
        const userRes = await client.query('SELECT * FROM users WHERE id = $1 FOR UPDATE', [paymentRequest.user_id]);
        const user = userRes.rows[0];
        if (!user) throw new Error('User not found');
        await client.query('UPDATE users SET balance = COALESCE(balance, 0) + $1 WHERE id = $2', [Number(paymentRequest.amount || 0), paymentRequest.user_id]);
        await client.query(
            'INSERT INTO transactions (user_id, user_email, amount, type, status, description, transaction_id, screenshot) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [paymentRequest.user_id, paymentRequest.user_email, paymentRequest.amount, 'deposit', 'approved', `Approved payment request #${paymentRequest.id}`, paymentRequest.transaction_id, null]
        );
        await client.query('UPDATE payment_requests SET status = $1, screenshot = NULL WHERE id = $2', ['approved', paymentRequest.id]);
        await client.query('COMMIT');
        await removeUploadedFile(screenshotToDelete);
        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(400).send(formatSafeError(err, 'Payment request approval failed'));
    } finally {
        client.release();
    }
});

app.post('/api/admin/payment-requests/:id/reject', ensureAdmin, async (req, res) => {
    const client = await pool.connect();
    let screenshotToDelete = null;
    try {
        await client.query('BEGIN');
        const requestRes = await client.query('SELECT * FROM payment_requests WHERE id = $1 FOR UPDATE', [Number(req.params.id)]);
        const request = requestRes.rows[0];
        if (!request) {
            await client.query('ROLLBACK');
            return res.status(404).send('Payment request not found');
        }
        if (request.status !== 'pending') {
            await client.query('ROLLBACK');
            return res.status(400).send('Only pending payment requests can be cancelled');
        }
        screenshotToDelete = request.screenshot || null;
        await client.query('UPDATE payment_requests SET status = $1, screenshot = NULL WHERE id = $2', ['cancelled', Number(req.params.id)]);
        await client.query('COMMIT');
        await removeUploadedFile(screenshotToDelete);
        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(400).send(formatSafeError(err, 'Payment request cancellation failed'));
    } finally {
        client.release();
    }
});

app.use('/uploads', express.static(UPLOAD_DIR));

function startServer() {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on http://0.0.0.0:${PORT}`);
    });
}

initDB()
    .then(() => {
        startServer();
    })
    .catch((err) => {
        console.error('Database initialization failed:', err);
        startServer();
    });
