const { scanTech } = require('./tech-detect');

const STACK_REMEDIATIONS = {
  // JavaScript / Node.js
  'Express': {
    sqli: 'Use parameterized queries with a library like `mysql2` or `pg`. Never concatenate SQL strings. Use an ORM like Sequelize, Prisma, or TypeORM.',
    xss: 'Use helmet.js for security headers. Sanitize output with DOMPurify server-side. Use template engine auto-escaping (EJS with `<%= %>`, not `<%- %>`). Set CSP headers.',
    csrf: 'Use csurf middleware or double-submit cookie pattern. Express has built-in CSRF protection via same-site cookies.',
    cmdi: 'Avoid `child_process.exec()` — use `child_process.execFile()` or `spawn()` with arguments array. Never pass user input to shell commands.',
    ssrf: 'Validate URLs with `new URL()` against an allowlist. Use `axios` with `baseURL` to prevent path traversal.',
  },
  'React': {
    xss: 'Use React\'s built-in JSX escaping (dangerouslySetInnerHTML is dangerous). Implement CSP headers. Sanitize with DOMPurify before dangerouslySetInnerHTML.',
    ssrf: 'Avoid fetching user-supplied URLs from the client. Proxy through a server-side endpoint.',
  },
  'Next.js': {
    xss: 'Next.js auto-escapes JSX output. Use `next/headers` for CSP. Avoid `dangerouslySetInnerHTML`. Use middleware for security headers.',
    ssrf: 'Use `rewrites` in next.config.js instead of direct fetch from server components. Validate redirect targets.',
  },
  'Django': {
    sqli: 'Use Django ORM querysets — they auto-parameterize. Avoid `raw()` and `extra()` with user input. Never use `cursor.execute()` with string formatting.',
    xss: 'Django templates auto-escape by default. Use `|safe` filter cautiously. Set `SECURE_*` settings. Use django-csp package.',
    csrf: 'Django has built-in CSRF protection. Ensure `CsrfViewMiddleware` is enabled and `{% csrf_token %}` is in forms.',
    auth: 'Use Django\'s built-in authentication. Implement password validators. Set `SECURE_*` cookie flags.',
  },
  'Flask': {
    sqli: 'Use SQLAlchemy ORM with parameterized queries. Avoid raw SQL with string formatting.',
    xss: 'Jinja2 auto-escapes by default. Use `|safe` filter carefully. Set CSP headers via Flask-Talisman.',
    csrf: 'Use Flask-WTF for CSRF protection. Ensure CSRF tokens on all POST forms.',
  },
  'Laravel': {
    sqli: 'Use Eloquent ORM or the query builder — both use PDO parameter binding. Avoid `DB::raw()` with user input.',
    xss: 'Blade templates auto-escape `{{ }}` statements. Use `{!! !!}` only for trusted content. Set CSP headers.',
    csrf: 'Laravel includes CSRF protection via `@csrf` directive. Keep `VerifyCsrfToken` middleware enabled.',
  },
  'Ruby on Rails': {
    sqli: 'Use ActiveRecord query methods (`.where()`, `.find_by()`). Avoid `where("column = \'#{param}\'")` string interpolation.',
    xss: 'Rails auto-escapes in ERB templates. Use `raw()` and `html_safe` cautiously. Set CSP headers.',
    csrf: 'Rails has built-in CSRF protection. Keep `protect_from_forgery` enabled with `with: :exception`.',
  },
  'ASP.NET': {
    sqli: 'Use Entity Framework or parameterized SQL with SqlCommand. Never concatenate SQL strings.',
    xss: 'Razor views auto-HTML-encode by default. Use `@Html.Raw()` carefully. Implement CSP headers.',
    csrf: 'ASP.NET Core has built-in anti-forgery tokens. Use `[AutoValidateAntiforgeryToken]` attribute.',
  },
  'WordPress': {
    sqli: 'Use `$wpdb->prepare()` for all SQL queries. Never interpolate variables directly into queries.',
    xss: 'Use `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()` for output. Apply WordPress CSP.',
    auth: 'Enforce strong passwords. Limit login attempts. Use two-factor authentication plugins.',
  },
  'Drupal': {
    sqli: 'Use the Database API with placeholders. Never use `db_query()` with string concatenation.',
    xss: 'Use `\Drupal\Component\Utility\Html::escape()` and `Xss::filter()`. Drupal\'s Twig auto-escapes.',
  },
  'PHP': {
    sqli: 'Use PDO with prepared statements (`$stmt = $pdo->prepare()`) or MySQLi with bound params. Never use `mysql_*` functions (deprecated).',
    xss: 'Use `htmlspecialchars()` with ENT_QUOTES for output. Implement CSP. Never use `echo $_GET[\'param\']` directly.',
    lfi: 'Disable `allow_url_include`. Use a whitelist of allowed files. Never use `include($_GET[\'page\'])`.',
    cmdi: 'Avoid `exec()`, `system()`, `passthru()`, `shell_exec()` with user input. Use `escapeshellarg()` if unavoidable.',
  },
};

const DEFAULT_REMEDIATIONS = {
  sqli: {
    generic: 'Use parameterized queries or prepared statements for all database operations. Never concatenate user input into SQL strings. Implement input validation with an allowlist approach.',
    short: 'Use parameterized queries / prepared statements.',
  },
  xss: {
    generic: 'Implement Content Security Policy (CSP) headers. Use context-aware output encoding. Apply the principle of least privilege for script sources.',
    short: 'Apply CSP + context-aware output encoding.',
  },
  csrf: {
    generic: 'Implement anti-CSRF tokens for all state-changing operations. Use SameSite cookie attribute (Lax or Strict). Validate Origin/Referer headers.',
    short: 'Add CSRF tokens + SameSite cookies.',
  },
  'command-injection': {
    generic: 'Never pass user input to system commands. Use language-native APIs instead of shell commands. Implement strict allowlist-based validation.',
    short: 'Avoid shell commands with user input.',
  },
  lfi: {
    generic: 'Use a whitelist of allowed files. Map user input to file identifiers via database lookup. Do not construct file paths from user input.',
    short: 'Use file whitelist + indirect references.',
  },
  ssrf: {
    generic: 'Validate and sanitize all URL parameters against an allowlist of permitted protocols and hosts. Disable unnecessary URL schemes (file://, dict://, gopher://).',
    short: 'Validate URLs against allowlist.',
  },
  default: {
    generic: 'Apply security patches and updates. Follow OWASP guidelines for the specific vulnerability type. Implement defense-in-depth with multiple security layers.',
    short: 'Follow OWASP guidelines for remediation.',
  },
};

async function getStackSpecificRemediation(targetUrl, vulnerabilityType, httpClient) {
  let techStack = [];
  try {
    const techResult = await scanTech(targetUrl, httpClient);
    techStack = techResult.technologies || [];
  } catch {}

  const matchedTechs = techStack.filter(t =>
    Object.keys(STACK_REMEDIATIONS).includes(t.name)
  );

  if (matchedTechs.length > 0) {
    for (const tech of matchedTechs) {
      const techFix = STACK_REMEDIATIONS[tech.name];
      if (techFix[vulnerabilityType]) {
        return {
          technology: tech.name,
          remediation: techFix[vulnerabilityType],
          stack: techStack.map(t => t.name),
        };
      }
    }
  }

  const runtimeTechs = techStack.filter(t =>
    ['PHP', 'Python', 'Java', 'Node.js', 'Ruby', 'ASP.NET'].includes(t.name)
  );
  if (runtimeTechs.length > 0) {
    for (const rt of runtimeTechs) {
      const techFix = STACK_REMEDIATIONS[rt.name];
      if (techFix && techFix[vulnerabilityType]) {
        return {
          technology: rt.name,
          remediation: techFix[vulnerabilityType],
          stack: techStack.map(t => t.name),
        };
      }
    }
  }

  const genericFix = DEFAULT_REMEDIATIONS[vulnerabilityType] || DEFAULT_REMEDIATIONS.default;
  return {
    technology: 'generic',
    remediation: genericFix.generic + ` Detected stack: ${techStack.map(t => t.name).join(', ') || 'unknown'}.`,
    short: genericFix.short,
    stack: techStack.map(t => t.name),
  };
}

async function enrichRemediations(vulnerabilities, targetUrl, httpClient) {
  const enriched = [];
  for (const v of vulnerabilities) {
    const fix = await getStackSpecificRemediation(targetUrl, v.type, httpClient);
    enriched.push({
      ...v,
      stackRemediation: fix.remediation,
      detectedStack: fix.stack,
      remediationTechnology: fix.technology,
    });
  }
  return enriched;
}

module.exports = { getStackSpecificRemediation, enrichRemediations, STACK_REMEDIATIONS };
