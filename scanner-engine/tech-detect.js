const axios = require('axios');

const TECH_PATTERNS = [
  { name: 'React', category: 'JavaScript Framework', regex: /react(-dom)?[.\/]/i, header: null, meta: null },
  { name: 'Angular', category: 'JavaScript Framework', regex: /angular/i, header: null, meta: null },
  { name: 'Vue.js', category: 'JavaScript Framework', regex: /vue(\.js)?/i, header: null, meta: null },
  { name: 'Next.js', category: 'JavaScript Framework', regex: /__next|next\.js|_next\/static/i, header: 'x-vercel-id', headerRegex: null },
  { name: 'Nuxt.js', category: 'JavaScript Framework', regex: /__nuxt|nuxt\.js/i, header: null, meta: null },
  { name: 'Svelte', category: 'JavaScript Framework', regex: /svelte/i, header: null, meta: null },
  { name: 'jQuery', category: 'JavaScript Library', regex: /jquery/i, header: null, meta: null },
  { name: 'Bootstrap', category: 'CSS Framework', regex: /bootstrap/i, header: null, meta: null },
  { name: 'Tailwind CSS', category: 'CSS Framework', regex: /tailwind/i, header: null, meta: null },
  { name: 'Drupal', category: 'CMS', regex: /drupal/i, header: 'X-Drupal', headerRegex: null },
  { name: 'WordPress', category: 'CMS', regex: /wordpress|wp-content|wp-includes/i, header: null, meta: /wordpress/i },
  { name: 'Joomla', category: 'CMS', regex: /joomla/i, header: null, meta: null },
  { name: 'Magento', category: 'CMS', regex: /magento|mage\-/i, header: null, meta: null },
  { name: 'Shopify', category: 'E-commerce', regex: /shopify/i, header: 'x-shopid', headerRegex: null },
  { name: 'WooCommerce', category: 'E-commerce', regex: /woocommerce/i, header: null, meta: null },
  { name: 'Django', category: 'Web Framework', regex: /django/i, header: null, meta: null, cookie: /django/i },
  { name: 'Flask', category: 'Web Framework', regex: /flask/i, header: null, meta: null },
  { name: 'Ruby on Rails', category: 'Web Framework', regex: /rails/i, header: 'x-powered-by', headerRegex: /rails/i, cookie: /_session/i },
  { name: 'Laravel', category: 'Web Framework', regex: /laravel/i, header: null, meta: null, cookie: /laravel_session/i },
  { name: 'Symfony', category: 'Web Framework', regex: /symfony/i, header: null, meta: null },
  { name: 'CakePHP', category: 'Web Framework', regex: /cakephp/i, header: null, meta: null },
  { name: 'CodeIgniter', category: 'Web Framework', regex: /codeigniter/i, header: null, meta: null },
  { name: 'ASP.NET', category: 'Web Framework', regex: /asp\.net|__viewstate/i, header: 'x-powered-by', headerRegex: /asp\.net/i },
  { name: 'Express', category: 'Web Framework', regex: /express/i, header: 'x-powered-by', headerRegex: /express/i },
  { name: 'Koa.js', category: 'Web Framework', regex: /koa/i, header: null, meta: null },
  { name: 'Fastify', category: 'Web Framework', regex: /fastify/i, header: null, meta: null },
  { name: 'Nginx', category: 'Web Server', regex: null, header: 'server', headerRegex: /nginx/i },
  { name: 'Apache', category: 'Web Server', regex: null, header: 'server', headerRegex: /apache/i },
  { name: 'IIS', category: 'Web Server', regex: null, header: 'server', headerRegex: /iis|microsoft\-iis/i },
  { name: 'Tomcat', category: 'Web Server', regex: null, header: 'server', headerRegex: /tomcat/i },
  { name: 'Caddy', category: 'Web Server', regex: null, header: 'server', headerRegex: /caddy/i },
  { name: 'Cloudflare', category: 'CDN', regex: null, header: 'server', headerRegex: /cloudflare/i, header2: 'cf-ray', headerRegex2: null },
  { name: 'Cloudflare', category: 'CDN', regex: null, header: 'cf-ray', headerRegex: null },
  { name: 'Akamai', category: 'CDN', regex: null, header: 'server', headerRegex: /akamai/i },
  { name: 'Fastly', category: 'CDN', regex: null, header: 'x-served-by', headerRegex: /fastly/i },
  { name: 'Vercel', category: 'Hosting', regex: null, header: 'x-vercel-id', headerRegex: null },
  { name: 'Netlify', category: 'Hosting', regex: null, header: 'server', headerRegex: /netlify/i },
  { name: 'GitHub Pages', category: 'Hosting', regex: null, header: 'x-github-request-id', headerRegex: null },
  { name: 'AWS', category: 'Cloud', regex: null, header: 'server', headerRegex: /awselb|amazons3|cloudfront/i },
  { name: 'Google Cloud', category: 'Cloud', regex: null, header: 'x-cloud-trace-context', headerRegex: null },
  { name: 'Azure', category: 'Cloud', regex: null, header: 'x-azure-ref', headerRegex: null },
  { name: 'Node.js', category: 'Runtime', regex: /node\.js/i, header: 'x-powered-by', headerRegex: /node/i },
  { name: 'PHP', category: 'Runtime', regex: null, header: 'x-powered-by', headerRegex: /php/i },
  { name: 'Python', category: 'Runtime', regex: null, header: 'server', headerRegex: /python/i },
  { name: 'Java', category: 'Runtime', regex: null, header: 'server', headerRegex: /java|tomcat|jetty/i },
  { name: 'Google Analytics', category: 'Analytics', regex: /google\-analytics|gtag|ga\.js/i, header: null, meta: null },
  { name: 'Hotjar', category: 'Analytics', regex: /hotjar/i, header: null, meta: null },
  { name: 'Mixpanel', category: 'Analytics', regex: /mixpanel/i, header: null, meta: null },
  { name: 'Cloudflare Analytics', category: 'Analytics', regex: null, header: 'cf-analytics', headerRegex: null },
  { name: 'New Relic', category: 'Monitoring', regex: /newrelic|new\-relic/i, header: null, meta: null },
  { name: 'Datadog', category: 'Monitoring', regex: /datadog/i, header: null, meta: null },
  { name: 'Sentry', category: 'Monitoring', regex: /sentry/i, header: null, meta: null },
  { name: 'Stripe', category: 'Payment', regex: /stripe/i, header: null, meta: null },
  { name: 'PayPal', category: 'Payment', regex: /paypal/i, header: null, meta: null },
  { name: 'Recaptcha', category: 'Security', regex: /recaptcha|g\-recaptcha/i, header: null, meta: null },
  { name: 'hCaptcha', category: 'Security', regex: /hcaptcha/i, header: null, meta: null },
  { name: 'GraphQL', category: 'API', regex: /graphql/i, header: null, meta: null },
  { name: 'REST API', category: 'API', regex: /api|json|xml/i, header: null, meta: null },
  { name: 'Socket.io', category: 'Realtime', regex: /socket\.io/i, header: null, meta: null },
  { name: 'Algolia', category: 'Search', regex: /algolia/i, header: null, meta: null },
  { name: 'Elasticsearch', category: 'Search', regex: /elasticsearch/i, header: null, meta: null },
  { name: 'Redis', category: 'Cache', regex: null, header: 'x-cache', headerRegex: /redis/i },
  { name: 'Varnish', category: 'Cache', regex: null, header: 'x-varnish', headerRegex: null },
  { name: 'Memcached', category: 'Cache', regex: null, header: 'x-cache', headerRegex: /memcached/i },
  { name: 'Docker', category: 'Container', regex: null, header: 'server', headerRegex: /docker/i },
  { name: 'Kubernetes', category: 'Container', regex: null, header: 'server', headerRegex: /kube/i },
  { name: 'Webpack', category: 'Build Tool', regex: /webpack/i, header: null, meta: null },
  { name: 'Vite', category: 'Build Tool', regex: /vite/i, header: null, meta: null },
  { name: 'Babel', category: 'Build Tool', regex: /babel/i, header: null, meta: null },
  { name: 'Gulp', category: 'Build Tool', regex: /gulp/i, header: null, meta: null },
  { name: 'Grunt', category: 'Build Tool', regex: /grunt/i, header: null, meta: null },
  { name: 'ESBuild', category: 'Build Tool', regex: /esbuild/i, header: null, meta: null },
  { name: 'SWR', category: 'Data Fetching', regex: /swr/i, header: null, meta: null },
  { name: 'React Query', category: 'Data Fetching', regex: /react\-query|tanstack/i, header: null, meta: null },
  { name: 'Axios', category: 'HTTP Client', regex: /axios/i, header: null, meta: null },
  { name: 'Font Awesome', category: 'Icon Library', regex: /font\-awesome|fa\./i, header: null, meta: null },
  { name: 'Material UI', category: 'UI Library', regex: /material\-ui|@mui/i, header: null, meta: null },
  { name: 'Ant Design', category: 'UI Library', regex: /ant\-design|antd/i, header: null, meta: null },
  { name: 'Chakra UI', category: 'UI Library', regex: /chakra/i, header: null, meta: null },
  { name: 'Shadcn UI', category: 'UI Library', regex: /shadcn/i, header: null, meta: null },
  { name: 'Sass/SCSS', category: 'CSS Preprocessor', regex: /\.scss|sass/i, header: null, meta: null },
  { name: 'Less', category: 'CSS Preprocessor', regex: /\.less/i, header: null, meta: null },
  { name: 'PostCSS', category: 'CSS Preprocessor', regex: /postcss/i, header: null, meta: null },
  { name: 'Alpine.js', category: 'JavaScript Framework', regex: /alpine/i, header: null, meta: null },
  { name: 'htmx', category: 'JavaScript Framework', regex: /htmx/i, header: null, meta: null },
  { name: 'Stimulus', category: 'JavaScript Framework', regex: /stimulus/i, header: null, meta: null },
  { name: 'Turbo', category: 'JavaScript Framework', regex: /turbo/i, header: null, meta: null },
  { name: 'Livewire', category: 'JavaScript Framework', regex: /livewire/i, header: null, meta: null },
  { name: 'Terraform', category: 'IaC', regex: /terraform/i, header: null, meta: null },
  { name: 'Serverless', category: 'Cloud', regex: /serverless/i, header: null, meta: null },
  { name: 'OpenAI', category: 'AI', regex: /openai/i, header: null, meta: null },
  { name: 'Hugging Face', category: 'AI', regex: /huggingface/i, header: null, meta: null },
];

function detectTech(headers, body, cookies) {
  const detected = new Map();
  const bodyLower = (body || '').toLowerCase();
  const cookieStr = (cookies || []).join(' ');

  for (const pattern of TECH_PATTERNS) {
    if (detected.has(pattern.name)) continue;
    let found = false;

    if (pattern.regex && pattern.regex.test(bodyLower)) found = true;
    if (pattern.meta && pattern.meta.test(bodyLower)) found = true;
    if (pattern.cookie && pattern.cookie.test(cookieStr)) found = true;

    if (pattern.header && headers[pattern.header]) {
      if (pattern.headerRegex) {
        if (pattern.headerRegex.test(headers[pattern.header])) found = true;
      } else {
        found = true;
      }
    }
    if (pattern.header2 && headers[pattern.header2]) {
      if (pattern.headerRegex2) {
        if (pattern.headerRegex2.test(headers[pattern.header2])) found = true;
      } else {
        found = true;
      }
    }

    if (found) {
      detected.set(pattern.name, { name: pattern.name, category: pattern.category, confidence: 'high' });
    }
  }

  return [...detected.values()];
}

async function scanTech(targetUrl, httpClient) {
  const result = { url: targetUrl, technologies: [], headers: {}, error: null };

  try {
    const response = await httpClient.get(targetUrl, { timeout: 15000, maxRedirects: 5 });
    const headers = {};
    for (const [k, v] of Object.entries(response.headers)) {
      headers[k.toLowerCase()] = v;
    }
    const body = typeof response.data === 'string' ? response.data : '';
    const cookies = (response.headers['set-cookie'] || []);

    result.technologies = detectTech(headers, body, cookies);
    result.headers = headers;

    const serverHeader = headers['server'] || headers['x-powered-by'] || null;
    if (serverHeader) result.serverHeader = serverHeader;

  } catch (err) {
    result.error = err.message;
  }

  return result;
}

module.exports = { scanTech, TECH_PATTERNS, detectTech };
