const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('../config/db');

const router = express.Router();

router.post('/check-email', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  try {
    const sha1 = crypto.createHash('sha1').update(email.trim().toLowerCase()).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      timeout: 10000,
      headers: { 'User-Agent': 'WebSecurityScanner/2.0', 'Accept': 'text/plain' },
    });

    const hashes = response.data.split('\n').map(line => line.trim());
    let count = 0;
    for (const hash of hashes) {
      const [hashSuffix, hashCount] = hash.split(':');
      if (hashSuffix.toUpperCase() === suffix) {
        count = parseInt(hashCount) || 0;
        break;
      }
    }

    const breachNames = [];
    let breached = false;
    try {
      const breachRes = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email.trim())}`, {
        timeout: 10000,
        headers: { 'User-Agent': 'WebSecurityScanner/2.0', 'hibp-api-key': req.headers['x-hibp-key'] || '' },
        validateStatus: s => s < 500,
      });
      if (breachRes.status === 200 && Array.isArray(breachRes.data)) {
        breached = breachRes.data.length > 0;
        for (const b of breachRes.data) {
          breachNames.push({ name: b.Name, domain: b.Domain, date: b.BreachDate, dataClasses: b.DataClasses });
        }
      }
    } catch {}

    try {
      db.prepare('INSERT INTO breach_checks (email, breached, breach_count, breaches) VALUES (?, ?, ?, ?)')
        .run(email.trim(), breached ? 1 : 0, count, JSON.stringify(breachNames));
      db.save();
    } catch {}

    res.json({
      email: email.trim(),
      pwned: count > 0,
      pwnedCount: count,
      breached: breached,
      breaches: breachNames,
      totalBreaches: breachNames.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/check-password', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  try {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      timeout: 10000,
      headers: { 'User-Agent': 'WebSecurityScanner/2.0' },
    });

    const hashes = response.data.split('\n').map(line => line.trim());
    let count = 0;
    for (const hash of hashes) {
      const [hashSuffix, hashCount] = hash.split(':');
      if (hashSuffix.toUpperCase() === suffix) {
        count = parseInt(hashCount) || 0;
        break;
      }
    }

    res.json({
      passwordLength: password.length,
      pwned: count > 0,
      pwnedCount: count,
      strength: password.length < 8 ? 'weak' : password.length < 12 ? 'moderate' : 'strong',
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecial: /[^A-Za-z0-9]/.test(password),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
