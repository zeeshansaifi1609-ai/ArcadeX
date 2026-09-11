const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8787);
const DATA_FILE = process.env.HIGHWAY_DATA_FILE || path.join(__dirname, 'highway-data.json');
const SESSION_FILE = process.env.HIGHWAY_SESSION_FILE || `${DATA_FILE}.sessions`;
const SESSION_TTL = 1000 * 60 * 60 * 24 * 30;
const PUBLIC_ORIGIN = String(process.env.PUBLIC_ORIGIN || '').replace(/\/$/, '');
const API_ORIGIN = String(process.env.API_ORIGIN || '').replace(/\/$/, '');
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false' && process.env.NODE_ENV === 'production';
const sessions = new Map();
const persistentSessions = new Map();
const attempts = new Map();

function defaultSettings() {
    return { sound: true, music: true, shake: true, weather: true, sensitivity: 3 };
}
function defaultStats() {
    return { gamesPlayed: 0, totalCoinsEarned: 0, totalDistance: 0, totalDodged: 0, totalNearMisses: 0, bestScore: 0, highestWave: 0 };
}
function defaultSave() {
    return {
        coins: 0,
        bestScore: 0,
        totalDistance: 0,
        totalDodged: 0,
        totalNearMisses: 0,
        selectedCarId: 'car_01',
        unlockedCars: ['car_01'],
        activeMissionId: 1,
        completedMissions: [],
        unlockedAchievements: [],
        settings: defaultSettings(),
        leaderboard: [
            { name: 'VIPER', score: 25000, date: '2026-01-10' },
            { name: 'APEX', score: 18400, date: '2026-02-01' },
            { name: 'GHOST', score: 12100, date: '2026-02-14' },
            { name: 'TURBO', score: 7500, date: '2026-02-20' },
            { name: 'ROOKIE', score: 3000, date: '2026-02-25' }
        ],
        space: { bestScore: 0, highestWave: 0 }
    };
}
function mergeSave(save) {
    const base = defaultSave();
    if (!save || typeof save !== 'object') return base;
    const merged = { ...base, ...save };
    merged.settings = { ...base.settings, ...(save.settings || {}) };
    merged.leaderboard = Array.isArray(save.leaderboard) ? save.leaderboard : base.leaderboard;
    merged.unlockedCars = Array.isArray(save.unlockedCars) ? save.unlockedCars : base.unlockedCars;
    merged.completedMissions = Array.isArray(save.completedMissions) ? save.completedMissions : base.completedMissions;
    merged.unlockedAchievements = Array.isArray(save.unlockedAchievements) ? save.unlockedAchievements : base.unlockedAchievements;
    merged.space = { ...base.space, ...(save.space || {}) };
    return merged;
}
function normalizeUser(user) {
    if (!user || typeof user !== 'object') return user;
    user.save = mergeSave(user.save);
    user.level = Number.isFinite(user.level) ? Number(user.level) : 1;
    user.xp = Number.isFinite(user.xp) ? Number(user.xp) : 0;
    user.axPoints = Number.isFinite(user.axPoints) ? Number(user.axPoints) : 0;
    user.avatar = typeof user.avatar === 'string' && user.avatar.trim() ? user.avatar.trim() : String(user.username || 'A').slice(0, 1).toUpperCase();
    user.missions = Array.isArray(user.missions) ? user.missions : [];
    user.achievements = Array.isArray(user.achievements) ? user.achievements : [];
    user.stats = { ...defaultStats(), ...(user.stats || {}) };
    user.settings = { ...defaultSettings(), ...(user.settings || {}) };
    return user;
}
function loadDatabase() {
    try {
        const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
        if (!parsed || typeof parsed !== 'object') return { users: {}, leaderboard: [] };
        parsed.users = parsed.users || {};
        Object.values(parsed.users).forEach(normalizeUser);
        return parsed;
    }
    catch { return { users: {}, leaderboard: [] }; }
}
let database = loadDatabase();
function persist() { fs.writeFileSync(DATA_FILE, JSON.stringify(database, null, 2), { mode: 0o600 }); }
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function loadPersistentSessions() {
    try {
        const stored = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
        Object.entries(stored).forEach(([hash, session]) => {
            if (session && session.expires >= Date.now()) persistentSessions.set(hash, session);
        });
    } catch { }
}
function persistSessions() {
    const stored = Object.fromEntries(persistentSessions);
    fs.writeFileSync(SESSION_FILE, JSON.stringify(stored), { mode: 0o600 });
}
loadPersistentSessions();
function json(res, status, body, headers = {}) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
}
function allowedOrigin(origin) {
    if (!origin) return null;
    if (origin === 'null') return 'null';
    if (PUBLIC_ORIGIN && origin === PUBLIC_ORIGIN) return origin;
    try {
        const parsed = new URL(origin);
        if (['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) return origin;
        if (API_ORIGIN && origin === API_ORIGIN) return origin;
        return null;
    } catch { return null; }
}
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 100000) req.destroy(); }); req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('invalid json')); } }); }); }
function username(value) { return typeof value === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(value); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) { return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`; }
function passwordMatches(password, stored) { const [salt, digest] = String(stored).split(':'); if (!salt || !digest) return false; const actual = crypto.scryptSync(password, salt, 64).toString('hex'); const expected = Buffer.from(digest, 'hex'); const actualBuffer = Buffer.from(actual, 'hex'); return expected.length === actualBuffer.length && crypto.timingSafeEqual(actualBuffer, expected); }
function playerView(user) {
    const normalized = normalizeUser(user);
    const { passwordHash, ...safe } = normalized;
    return safe;
}
function cookie(req, name) { const match = (req.headers.cookie || '').match(new RegExp(`(?:^|; )${name}=([^;]+)`)); return match && match[1]; }
function currentUser(req) { const token = cookie(req, 'hr_session'); const hash = token && tokenHash(token); const session = token && (sessions.get(token) || persistentSessions.get(hash)); if (!session || session.expires < Date.now()) { if (token) { sessions.delete(token); persistentSessions.delete(hash); persistSessions(); } return null; } const user = database.users[session.username]; return user ? normalizeUser(user) : null; }
function limited(req, bucket, max, windowMs) { const key = `${req.socket.remoteAddress}:${bucket}`; const now = Date.now(); const recent = (attempts.get(key) || []).filter(time => time > now - windowMs); recent.push(now); attempts.set(key, recent); return recent.length <= max; }
function validateSave(save) { return save && typeof save === 'object' && Number.isFinite(save.bestScore) && Number.isFinite(save.totalDistance) && Number.isFinite(save.totalDodged) && Number.isFinite(save.totalNearMisses) && Array.isArray(save.unlockedCars) && Array.isArray(save.completedMissions) && save.unlockedCars.length <= 10 && save.completedMissions.length <= 50 && save.totalDistance >= 0 && save.totalDistance <= 1e9 && save.totalDodged >= 0 && save.totalNearMisses >= 0 && (!save.space || (typeof save.space === 'object' && Number.isFinite(save.space.bestScore) && Number.isFinite(save.space.highestWave) && save.space.bestScore >= 0 && save.space.highestWave >= 0 && save.space.bestScore <= 1e9 && save.space.highestWave <= 10000)); }
function route(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const origin = allowedOrigin(req.headers.origin);
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');
    }
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Max-Age': '86400'
        });
        return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    if (!url.pathname.startsWith('/api/')) return json(res, 404, { error: 'Not found.' });
    if (req.method === 'POST' && url.pathname === '/api/accounts') return body(req).then(data => {
        if (!username(data.username) || typeof data.password !== 'string' || data.password.length < 5 || data.password.length > 10) return json(res, 400, { error: 'Use a 3-20 character username and a password of 5-10 characters.' });
        if (typeof data.confirmPassword === 'string' && data.confirmPassword !== data.password) return json(res, 400, { error: 'Passwords do not match.' });
        const key = data.username.toLowerCase();
        if (database.users[key]) return json(res, 409, { error: 'That username is already taken.' });
        const guestSave = data.save && validateSave(data.save) ? mergeSave(data.save) : defaultSave();
        const id = `HR-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
        database.users[key] = {
            username: data.username,
            playerId: id,
            passwordHash: hashPassword(data.password),
            save: guestSave,
            level: 1,
            xp: 0,
            axPoints: 0,
            avatar: data.username.slice(0, 1).toUpperCase(),
            missions: [],
            achievements: [],
            stats: defaultStats(),
            settings: defaultSettings(),
            createdAt: new Date().toISOString()
        };
        persist();
        return loginUser(res, database.users[key], data.remember === true);
    }).catch(() => json(res, 400, { error: 'Invalid request.' }));
    if (req.method === 'POST' && url.pathname === '/api/session') return body(req).then(data => {
        if (!limited(req, 'login', Number.MAX_SAFE_INTEGER, 900000)) return json(res, 429, { error: 'Too many login attempts. Try again later.' });
        const user = username(data.username) && database.users[data.username.toLowerCase()];
        if (!user || typeof data.password !== 'string' || !passwordMatches(data.password, user.passwordHash)) return json(res, 401, { error: 'Incorrect username or password.' });
        normalizeUser(user);
        return loginUser(res, user, data.remember === true);
    }).catch(() => json(res, 400, { error: 'Invalid request.' }));
    if (req.method === 'DELETE' && url.pathname === '/api/session') { const token = cookie(req, 'hr_session'); if (token) { sessions.delete(token); persistentSessions.delete(tokenHash(token)); persistSessions(); } return json(res, 204, {}, { 'Set-Cookie': 'hr_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/' }); }
    const user = currentUser(req);
    if (req.method === 'GET' && url.pathname === '/api/me') {
        return user ? json(res, 200, { profile: playerView(user), save: user.save }) : json(res, 200, { profile: null, save: null });
    }
    if (!user) return json(res, 401, { error: 'Please log in to continue.' });
    if (req.method === 'GET' && url.pathname === '/api/leaderboard') {
        const rows = [...database.leaderboard].sort((a, b) => b.totalScore - a.totalScore).slice(0, 50).map((entry, index) => ({ rank: index + 1, username: entry.username, playerId: entry.playerId, highwayScore: entry.highwayScore, spaceScore: entry.spaceScore, totalScore: entry.totalScore }));
        const totalScore = (user.save?.bestScore || 0) + (user.save?.space?.bestScore || 0);
        const rank = database.leaderboard.filter(entry => entry.totalScore > totalScore).length + 1;
        return json(res, 200, { rows, playerRank: rank });
    }
    if (req.method === 'PUT' && url.pathname === '/api/me/save') return body(req).then(data => {
        if (!validateSave(data.save)) return json(res, 400, { error: 'Save data failed server validation.' });
        user.save = { ...(user.save || {}), ...data.save, space: data.save.space || user.save?.space || { bestScore: 0, highestWave: 0 } };
        const highwayScore = Math.floor(Math.max(0, Math.min(user.save.bestScore, user.save.totalDistance * 100 + user.save.totalDodged * 500 + user.save.totalNearMisses * 1000)));
        const spaceScore = Math.floor(Math.max(0, Math.min(user.save.space.bestScore, 1e9)));
        const totalScore = highwayScore + spaceScore;
        const existing = database.leaderboard.find(e => e.playerId === user.playerId);
        if (!existing || totalScore >= existing.totalScore) database.leaderboard = database.leaderboard.filter(e => e.playerId !== user.playerId).concat({ playerId: user.playerId, username: user.username, highwayScore, spaceScore, totalScore });
        persist(); return json(res, 200, { profile: playerView(user), save: user.save });
    }).catch(() => json(res, 400, { error: 'Invalid save request.' }));
    return json(res, 404, { error: 'Not found.' });
}
function loginUser(res, user, remember) {
    const token = crypto.randomBytes(32).toString('hex');
    const session = { username: user.username.toLowerCase(), expires: Date.now() + SESSION_TTL };
    if (remember) {
        persistentSessions.set(tokenHash(token), session);
        persistSessions();
    } else {
        sessions.set(token, session);
    }
    const persistence = remember ? `; Max-Age=${SESSION_TTL / 1000}` : '';
    // Same-origin deployments can use Lax. Separate frontend/API deployments need None + Secure.
    const sameSite = PUBLIC_ORIGIN && API_ORIGIN && PUBLIC_ORIGIN !== API_ORIGIN ? 'None' : 'Lax';
    const secure = COOKIE_SECURE || sameSite === 'None' ? '; Secure' : '';
    return json(res, 200, { profile: playerView(user), save: user.save }, {
        'Set-Cookie': `hr_session=${token}${persistence}; HttpOnly; SameSite=${sameSite}; Path=/${secure}`
    });
}
http.createServer((req, res) => { try { route(req, res); } catch (error) { console.error(error); json(res, 500, { error: 'Request could not be completed.' }); } }).listen(PORT, '0.0.0.0', () => console.log(`ArcadeX API listening on port ${PORT}`));
