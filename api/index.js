module.exports = async function handler(req, res) {
  try {
    const app = require('../server/index');
    if (typeof app.startup === 'function') {
      await app.startup();
    }
    app(req, res);
  } catch (e) {
    if (!res.headersSent) {
      res.status(500).json({ error: 'Startup failed: ' + e.message });
    } else {
      res.end();
    }
  }
};

module.exports.config = { maxDuration: 60 };