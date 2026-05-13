require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const bcrypt = require('bcryptjs');

async function seed() {
  console.log('[Seed] Initializing database...');
  const db = require('../server/config/db');
  await db.init();

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL);
  if (!existing) {
    const hashed = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare(
      'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)'
    ).run(process.env.ADMIN_EMAIL, hashed, 'Admin', 'admin');
    console.log(`[Seed] Admin user created: ${process.env.ADMIN_EMAIL}`);
  } else {
    console.log('[Seed] Admin user already exists');
  }

  console.log('[Seed] Database initialized successfully');
  process.exit(0);
}

seed().catch(err => {
  console.error('[Seed] Error:', err);
  process.exit(1);
});
