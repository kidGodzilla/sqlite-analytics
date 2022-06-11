require('dotenv').config();

const MobileDetect = require('mobile-detect');
const Database = require('better-sqlite3');
const anonymize = require('ip-anonymize');
const schedule = require('node-schedule');
const CryptoJS_SIV = require('./siv.js');
const { randomUUID } = require('crypto');
const requestIp = require('request-ip');
const SHA3 = require('crypto-js/sha3');
const uaparser = require('ua-parser');
const CryptoJS = require('crypto-js');
const AES = require('crypto-js/aes');
const geoip = require('geoip-lite');
const express = require('express');
const crypto = require('crypto');
const Url = require('url-parse');
const cors = require('cors');
const fs = require('fs');
let drop = 0;
let db;

const server_encryption_string = process.env.ENCSTR || 'defaultencryptionstring';
const debug = process.env.DEBUG || false;
const PORT = process.env.PORT || 5001;
const delete_older_data = false;
const app = express();
app.use(cors());

// Move local file to /storage if exists and /storage is empty
if (fs.existsSync('/storage') && fs.existsSync('./analytics.sqlite3') && !fs.existsSync('/storage/analytics.sqlite3')) {
    fs.copyFileSync('./public/analytics.sqlite3', '/storage/analytics.sqlite3');
}

function ready(cb) {
    // Data format descriptor
    let format = 'cache_status|status_code|timestamp|bytes_sent|pull_zone_id|remote_ip|referer_url|url|edge_location|user_agent|unique_request_id|country_code'.split('|');

    // Determine device type
    function determineDeviceType(ua, type) {
        let deviceType = 'mobile,tablet,desktop,laptop'.split(',');
        let md = new MobileDetect(ua);

        // md.maxPhoneWidth 992 - 1440 = laptop
        // console.log(md.maxPhoneWidth)

        if (!(md.mobile() || md.tablet())) type = 2;
        else if (!!md.mobile()) type = 0;
        else if (!!md.tablet()) type = 1;

        // Attempted but Not very accurate
        // if (type === 2 && md.maxPhoneWidth <= 1440) type = 3;

        return deviceType[type];
    }

    // Parse Bunny CDN logs
    function parseLogs(logs) {
        if (!logs || typeof logs !== 'string') return false;

        let a = logs.split(/\n/).reverse();

        a.map(line => {
            if (!line || typeof line !== 'string' || line.length < 4) return;

            let parts = line.split('|');
            let AES_SIV_Encrypter = null;
            let out = {};

            if (!(parts[7] || '').includes('/o.png') && !(parts[7] || '').includes('/o')) return;

            // referrer host href width bot headless
            let parsed = new Url(parts[7], true);
            if (parsed.query.href) {
                if (parsed.query.key) {
                    const private_key = SHA3(parsed.query.key + server_encryption_string).toString(CryptoJS.enc.Base64);
                    AES_SIV_Encrypter = CryptoJS_SIV.SIV.create(CryptoJS_SIV.enc.Hex.parse(private_key));
                }

                if (parsed.query.headless) out.headless = parseInt(parsed.query.headless);
                if (parsed.query.width) out.width = parseInt(parsed.query.width);
                if (parsed.query.bot) out.bot = parseInt(parsed.query.bot);
                if (parsed.query.event) out.event = parsed.query.event;
                if (parsed.query.value) out.value = parsed.query.value;
                if (parsed.query.lang) out.lang = parsed.query.lang;
                if (parsed.query.href) parts[7] = parsed.query.href;
                if (parsed.query.sid) out.sid = parsed.query.sid;

                out.session = parseInt(parsed.query.session);
                out.is_new = parseInt(parsed.query.new);

                if (parsed.query.time) out.session_length = parseFloat(parsed.query.time);
                if (parsed.query.views) out.pageviews = parseInt(parsed.query.views);
                if (parsed.query.load) out.load_time = parseFloat(parsed.query.load);
                if (out.load_time < 0) out.load_time = 0;

                parts[6] = parsed.query.referrer || '';
            }

            parts.forEach((part, i) => {
                out[format[i]] = part === '-' ? null : part;

                if (format[i] === 'timestamp') {
                    let ts = parseInt(part / 1000);
                    out[format[i]] = ts;

                    let d = new Date(parseInt(part));
                    let iso_date = d.toISOString().slice(0,10);
                    out.iso_date = iso_date;
                    out.hour = d.getUTCHours();


                } else if (format[i] === 'user_agent') {
                    const uaParts = uaparser.parse(part);

                    out.device_type = determineDeviceType(part);
                    out.device_family = uaParts.device.family;
                    out.browser = uaParts.family;
                    out.browser_major_version = uaParts.major;
                    out.browser_minor_version = uaParts.minor;
                    out.os = uaParts.os.family;
                    out.os_major_version = uaParts.os.major;
                    out.os_minor_version = uaParts.os.minor;


                } else if (format[i] === 'referer_url') {
                    if (!part || part === '-') return;

                    parsed = new Url(part, true);
                    out.referer_protocol = parsed.protocol;
                    out.referer_pathname = parsed.pathname;
                    out.referer_host = parsed.host;
                    out.referer_url = part;


                } else if (format[i] === 'url') {
                    if (!part || part === '-') return;

                    parsed = new Url(part, true);
                    out.protocol = parsed.protocol;
                    out.pathname = parsed.pathname;
                    out.host = parsed.host;

                    if (parsed.query.href) {
                        parsed = new Url(parsed.query.href, true);

                        out.protocol = parsed.protocol;
                        out.pathname = parsed.pathname;
                        out.host = parsed.host;
                    }

                    let { utm_source, utm_medium, utm_content, utm_campaign, utm_term } = parsed.query;
                    out = Object.assign(out, { utm_source, utm_medium, utm_content, utm_campaign, utm_term });

                    if (out.host.indexOf('www.') === 0) out.host = out.host.replace('www.', '');
                }
            });

            if (out.remote_ip && !out.country_code) {
                const geo = geoip.lookup(out.remote_ip);
                if (!geo) return;

                if (geo.country) out.country_code = geo.country;
            }

            if (!out.referer_pathname) out.referer_pathname = '';
            if (!out.session_length) out.session_length = 0;
            if (!out.referer_host) out.referer_host = '';
            if (!out.referer_url) out.referer_url = '';
            out.status_code = parseInt(out.status_code);
            if (!out.event) out.event = 'pageview';
            if (!out.pageviews) out.pageviews = 0;
            if (!out.load_time) out.load_time = 0;
            if (!out.headless) out.headless = 0;
            if (!out.session) out.session = 0;
            if (!out.is_new) out.is_new = 0;
            if (!out.value) out.value = '';
            if (!out.width) out.width = 0;
            if (!out.lang) out.lang = '';
            if (!out.sid) out.sid = '';
            if (!out.bot) out.bot = 0;


            // Encrypt specific fields if private_key
            if (AES_SIV_Encrypter) {
                if (out.referer_pathname) out.referer_pathname = AES_SIV_Encrypter.encrypt(out.referer_pathname).toString();
                if (out.referer_host) out.referer_host = AES_SIV_Encrypter.encrypt(out.referer_host).toString();
                if (out.referer_url) out.referer_url = AES_SIV_Encrypter.encrypt(out.referer_url).toString();
                out.pathname = AES_SIV_Encrypter.encrypt(out.pathname).toString();
                out.host = AES_SIV_Encrypter.encrypt(out.host).toString();
                out.url = AES_SIV_Encrypter.encrypt(out.url).toString();

                if (out.utm_campaign) out.utm_campaign = AES_SIV_Encrypter.encrypt(out.utm_campaign).toString();
                if (out.utm_content) out.utm_content = AES_SIV_Encrypter.encrypt(out.utm_content).toString();
                if (out.utm_medium) out.utm_medium = AES_SIV_Encrypter.encrypt(out.utm_medium).toString();
                if (out.utm_source) out.utm_source = AES_SIV_Encrypter.encrypt(out.utm_source).toString();
                if (out.utm_term) out.utm_term = AES_SIV_Encrypter.encrypt(out.utm_term).toString();

                out.remote_ip = CryptoJS.MD5(out.remote_ip).toString();
            } else {
                out.remote_ip = anonymize(out.remote_ip);
            }


            delete out.pull_zone_id;
            delete out.cache_status;
            delete out.user_agent;
            delete out.bytes_sent;
            out.url = '';

            if (debug) console.log(out);

            insertMany(out);
        });

        // Vacuum (again)
        let stmt = db.prepare(`vacuum;`);
        stmt.run();
    }

    function constructDb() {
        // Use SQLite3 Database
        db = new Database(fs.existsSync('/storage') ? '/storage/analytics.sqlite3' : './public/analytics.sqlite3'); // , { verbose: console.log }

        // Drop previous `visits` table
        let stmt = db.prepare(`DROP TABLE visits`);
        if (drop) {
            console.log('Dropping previous visits table');
            stmt.run();
        }

        // Drop previous `summaries` table
        stmt = db.prepare(`DROP TABLE summaries`);
        if (drop) {
            console.log('Dropping previous summaries table');
            stmt.run();
        }
    }

    try {
        constructDb();
    } catch(e) {
        // Restore backup
        console.log('error:', e, '\n');
    }

    // Optional Recommended Improvements
    stmt = db.prepare(`pragma journal_mode = delete;`);
    stmt.run();

    stmt = db.prepare(`pragma page_size = 32768;`);
    stmt.run();

    stmt = db.prepare(`vacuum;`);
    stmt.run();

    // Create `visits` Table
    stmt = db.prepare(`CREATE TABLE IF NOT EXISTS visits (
        id TEXT PRIMARY KEY,
        date TEXT,
        ts INTEGER,
        hour INTEGER,
        ip TEXT,
        url TEXT,
        event TEXT,
        value TEXT,
        protocol TEXT,
        pathname TEXT,
        host TEXT,
        device_type TEXT,
        device_family TEXT,
        browser TEXT,
        browser_major_version TEXT,
        browser_minor_version TEXT,
        os TEXT,
        os_major_version TEXT,
        os_minor_version TEXT,
        country_code TEXT,
        referer_host TEXT,
        headless INTEGER,
        bot INTEGER,
        width INTEGER,
        session_length REAL,
        pageviews INTEGER,
        load_time REAL,
        lang TEXT,
        edge_location TEXT,
        session REAL,
        is_new REAL,
        utm_source TEXT,
        utm_medium TEXT,
        utm_content TEXT,
        utm_campaign TEXT,
        utm_term TEXT,
        referer_pathname TEXT,
        referer_url TEXT,
        session_id TEXT
    )`);

    stmt.run();

    // Create `summaries` Table
    stmt = db.prepare(`CREATE TABLE IF NOT EXISTS summaries (
        id TEXT PRIMARY KEY,
        date TEXT,
        host TEXT,
        data TEXT
    )`);

    stmt.run();

    // Add columns
    function addColumn(name, type) {
        try {
            let stmt = db.prepare(`ALTER TABLE visits ADD COLUMN ${ name } ${ type };`);
            stmt.run();
        } catch(e) {
            console.log(`column ${ name } already exists, skipping`);
        }
    }

    // addColumn('hour', 'INTEGER');
    addColumn('referer_pathname', 'TEXT');
    addColumn('referer_url', 'TEXT');
    addColumn('session_id', 'TEXT');

    // Add indexes
    function addIndex(column, table = 'visits') {
        try {
            let stmt = db.prepare(`CREATE INDEX idx_${ column } ON ${ table } (${ column });`);
            stmt.run();
        } catch(e) {
            console.log(`index idx_${ column } already exists, skipping`);
        }
    }

    addIndex('ip');
    addIndex('date');
    addIndex('ts');
    addIndex('hour');
    addIndex('event');
    addIndex('value');
    addIndex('pathname');
    addIndex('host');
    addIndex('device_type');
    // addIndex('device_family');
    addIndex('browser');
    addIndex('os');
    addIndex('country_code');
    addIndex('referer_host');
    addIndex('referer_pathname');
    addIndex('referer_url');
    addIndex('headless');
    addIndex('bot');
    // addIndex('width');
    addIndex('session_length');
    addIndex('session_id');
    addIndex('pageviews');
    addIndex('load_time');
    addIndex('lang');
    addIndex('is_new');
    addIndex('utm_source');
    addIndex('utm_medium');
    addIndex('utm_content');
    addIndex('utm_campaign');
    addIndex('utm_term');

    addIndex('hour', 'summaries');
    addIndex('host', 'summaries');

    // Vacuum again
    stmt = db.prepare(`vacuum;`);
    stmt.run();

    // Insert via prepared statement
    const insert = db.prepare(`INSERT OR IGNORE INTO visits (
        id, 
        date, 
        ts, 
        hour,
        ip, 
        url,
        event,
        value,
        protocol, 
        pathname, 
        host, 
        device_type, 
        device_family, 
        browser, 
        browser_major_version, 
        browser_minor_version, 
        os, 
        os_major_version, 
        os_minor_version, 
        country_code,
        referer_host,
        headless,
        bot,
        width,
        session_length,
        pageviews,
        load_time,
        lang,
        edge_location,
        session,
        is_new,
        utm_source,
        utm_medium,
        utm_content,
        utm_campaign,
        utm_term,
        referer_pathname,
        referer_url,
        session_id
    ) VALUES (
        @unique_request_id, 
        @iso_date,
        @timestamp,
        @hour,
        @remote_ip,
        @url,
        @event,
        @value,
        @protocol, 
        @pathname, 
        @host, 
        @device_type, 
        @device_family, 
        @browser, 
        @browser_major_version, 
        @browser_minor_version, 
        @os, 
        @os_major_version, 
        @os_minor_version, 
        @country_code,
        @referer_host,
        @headless,
        @bot,
        @width,
        @session_length,
        @pageviews,
        @load_time,
        @lang,
        @edge_location,
        @session,
        @is_new,
        @utm_source,
        @utm_medium,
        @utm_content,
        @utm_campaign,
        @utm_term,
        @referer_pathname,
        @referer_url,
        @sid
    )`);

    // Insert via prepared statement
    const insertSummary = db.prepare(`INSERT OR IGNORE INTO summaries (
        id, 
        date, 
        host,
        data
    ) VALUES (
        @id, 
        @date,
        @host,
        @data
    )`);

    // Insert one or many function
    const insertMany = db.transaction(rows => {
        if (Array.isArray(rows)) {
            for (const row of rows) insert.run(row);
        } else {
            insert.run(rows);
        }
    });

    if (cb && typeof cb === 'function') cb();

    return { parseLogs, insertSummary };
}

const { parseLogs, insertSummary } = ready(() => {
    const server = app.listen(PORT, function () {
        console.log(`App listening on port ${ PORT }!`);
        server.keepAliveTimeout = 0;
    });
});


// Generate an encryption key pair, return it to the user
app.get('/keypair', function (req, res) {
    let { length } = req.query;
    const randomString = crypto.randomBytes(parseInt(length) || 14).toString('hex');
    const private_key = SHA3(randomString + server_encryption_string).toString(CryptoJS.enc.Base64);

    res.json({
        url_safe_private_key: encodeURIComponent(private_key),
        private_key,
        private_key_length: private_key.length,
        strength: (private_key.length * 16) + ' bit',
        public_key: randomString,
        public_key_length: parseInt(length) || 14,
    });
});

function analyticsHit(req, res) {
    let ip = null;
    try { ip = requestIp.getClientIp(req) } catch(e) {}
    try { if (req.headers['cf-connecting-ip']) ip = req.headers['cf-connecting-ip'] } catch(e){}
    let uid = (Math.random().toString(36).substr(2)+Math.random().toString(36).substr(2));

    // Log request
    let s = `HIT|200|${ Date.now() }|||${ ip }|${ req.headers.referrer || req.headers.referer }|${ req.protocol }://${ req.get('host') }${ req.originalUrl }||${ req.get('user-agent') }|${ uid }|`;
    if (debug) console.log(s);
    parseLogs(s);
}

// Record an analytics hit
app.get('/o.png', function (req, res) {
    analyticsHit(req, res);
    res.sendFile('./public/o.png', { root: __dirname });
});

// Record an analytics hit
app.get('/o', function (req, res) {
    analyticsHit(req, res);
    res.send('ok');
});

// Static directories
app.use(express.static('frontend'));
app.use(express.static('/storage'));
app.use(express.static('public'));


// JOB TO CLEANUP OLD DATA AND MOVE DATABASE TO analytics.sqlite3.png

function rotateDatabaseToPNG() {
    // Cleanup old rows, vacuum
    const priorDate = new Date(new Date().setDate((new Date()).getDate() - 32));

    if (delete_older_data) {
        try {
            let stmt = db.prepare(`DELETE from visits WHERE date < '${ priorDate.toISOString().slice(0,10) }'`);
            stmt.run();

            stmt = db.prepare(`vacuum;`);
            stmt.run();
        } catch(e) {
            console.log(`error cleaning database`);
        }
    }

    // Backup Database to .PNG (format fixes header issues for some services with range requests)
    db.backup(`./public/analytics.sqlite3.png`).then(() => {
        if (debug) console.log('database was backed up to ./public/analytics.sqlite3.png');
    }).catch((err) => {
        console.log('backup failed:', err);
    });
}

schedule.scheduleJob('*/5 * * * *', rotateDatabaseToPNG);
setTimeout(rotateDatabaseToPNG, 20000);


// DATA SUMMARIZATION JOB

function lastMonthString() {
    let D = new Date();
    let m = D.getMonth() - 1;
    let y = D.getFullYear();
    if (m < 0) {
        m = 11;
        y -= 1;
    }
    m += 1;

    return `${ y }-${ m < 10 ? '0' : '' }${ m }`;
}

function performMonthlySummarization(domain, lastMonth) {
    let data = {};
    if (debug) console.log('Preparing monthly summarization for:', domain);
    const whereClause = ` WHERE host = '${ domain }' AND date LIKE '${ lastMonth }-%'`;
    const id = (Math.random().toString(36).substr(2)+Math.random().toString(36).substr(2));

    function queryCounts(column, whereClause, countBy = 'count(*)') {
        let obj = {}, result = db.prepare(`SELECT ${ column }, ${ countBy } FROM visits${ whereClause } GROUP BY ${ column };`).all();

        // Convert SQL rows object to categorical breakdown object
        result.forEach(r => {
            let key = Object.keys(r).filter(x => x !== countBy)[0];
            obj[r[key]] = r[countBy];
        });

        return obj;
    }

    // Numeric data
    data.visitors = db.prepare(`SELECT count(DISTINCT ip) from visits${ whereClause };`).all()[0]['count(DISTINCT ip)'];
    data.pageviews = db.prepare(`SELECT count(*) from visits${ whereClause };`).all()[0]['count(*)'];
    data.onePageVisits = db.prepare(`SELECT count(DISTINCT ip) from visits${ whereClause } AND is_new = 1;`).all()[0]['count(DISTINCT ip)'];
    data.sessionLength = db.prepare(`SELECT AVG(x.MaxValue) FROM (SELECT ip, max(session_length) as MaxValue from visits${whereClause} GROUP BY ip) x;`).all()[0]['AVG(x.MaxValue)'] || 0;
    data.loadTimes = db.prepare(`SELECT pathname, AVG(load_time) as AvgLoadTime from visits${ whereClause } GROUP BY pathname;`).all();
    data.bounceRate = data.visitors === 0 ? 0 : (data.onePageVisits / data.visitors);

    // Counts (categorical)
    data.device_type = queryCounts('device_type', whereClause);
    data.country_code = queryCounts('country_code', whereClause);
    data.device_family = queryCounts('device_family', whereClause);
    data.referer_host = queryCounts('referer_host', whereClause);
    data.referer_url = queryCounts('referer_url', whereClause);
    data.browser = queryCounts('browser', whereClause);
    data.pathname = queryCounts('pathname', whereClause);
    data.is_new = queryCounts('is_new', whereClause);
    data.lang = queryCounts('lang', whereClause);
    data.bot = queryCounts('bot', whereClause);
    data.os = queryCounts('os', whereClause);
    data.utm_campaign = queryCounts('utm_campaign', whereClause);
    data.utm_content = queryCounts('utm_content', whereClause);
    data.utm_medium = queryCounts('utm_medium', whereClause);
    data.utm_source = queryCounts('utm_source', whereClause);
    data.utm_term = queryCounts('utm_term', whereClause);

    data.device_type__visitors = queryCounts('device_type', whereClause, 'count(DISTINCT ip)');
    data.country_code__visitors = queryCounts('country_code', whereClause, 'count(DISTINCT ip)');
    data.device_family__visitors = queryCounts('device_family', whereClause, 'count(DISTINCT ip)');
    data.referer_host__visitors = queryCounts('referer_host', whereClause, 'count(DISTINCT ip)');
    data.referer_url__visitors = queryCounts('referer_url', whereClause, 'count(DISTINCT ip)');
    data.browser__visitors = queryCounts('browser', whereClause, 'count(DISTINCT ip)');
    data.pathname__visitors = queryCounts('pathname', whereClause, 'count(DISTINCT ip)');
    data.is_new__visitors = queryCounts('is_new', whereClause, 'count(DISTINCT ip)');
    data.lang__visitors = queryCounts('lang', whereClause, 'count(DISTINCT ip)');
    data.bot__visitors = queryCounts('bot', whereClause, 'count(DISTINCT ip)');
    data.os__visitors = queryCounts('os', whereClause, 'count(DISTINCT ip)');
    data.utm_campaign__visitors = queryCounts('utm_campaign', whereClause, 'count(DISTINCT ip)');
    data.utm_content__visitors = queryCounts('utm_content', whereClause, 'count(DISTINCT ip)');
    data.utm_medium__visitors = queryCounts('utm_medium', whereClause, 'count(DISTINCT ip)');
    data.utm_source__visitors = queryCounts('utm_source', whereClause, 'count(DISTINCT ip)');
    data.utm_term__visitors = queryCounts('utm_term', whereClause, 'count(DISTINCT ip)');


    // Prior Month's Timeseries charts :))))
    data.pageviewsTimeseries = queryCounts('date', whereClause);
    data.visitorsTimeseries = queryCounts('date', whereClause, 'count(DISTINCT ip)');

    // Delete previous row
    let stmt = db.prepare(`DELETE FROM summaries WHERE host = '${ domain }' AND date LIKE '${ lastMonth }'`);
    stmt.run();

    // Insert new summary row
    insertSummary.run({
        id,
        date: lastMonth,
        host: domain,
        data: JSON.stringify(data)
    });
}

function summarizeData() {
    const lastMonth = lastMonthString();
    const domains = db.prepare('SELECT DISTINCT host FROM visits').all().map(x => x.host);
    domains.forEach(domain => performMonthlySummarization(domain, lastMonth));
}

// Test out monthly summarization function
// setTimeout(summarizeData, 2222);

// Summarize data monthly
schedule.scheduleJob('20 3 1 * *', summarizeData);
