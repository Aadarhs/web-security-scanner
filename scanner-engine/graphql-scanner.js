const GRAPHQL_ENDPOINTS = [
  '/graphql', '/graphql?query=', '/gql', '/api/graphql',
  '/graph', '/query', '/v1/graphql', '/v2/graphql',
  '/api', '/api/gql', '/graphql/explorer', '/graphiql',
  '/playground', '/console',
];

const INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind description fields { name type { name kind ofType { name kind } } } }
    directives { name description locations }
  }
}`;

const DOS_QUERIES = [
  { name: 'Deep recursion', query: 'query { __typename ' + 'x: __typename '.repeat(50) + '}' },
  { name: 'Alias bombing', query: 'query { ' + Array.from({ length: 100 }, (_, i) => `a${i}: __typename`).join(' ') + ' }' },
  { name: 'Field duplication', query: '{ ' + '__typename '.repeat(200) + ' }' },
];

const SQLI_THROUGH_GQL = [
  { payload: "' OR '1'='1", name: 'Basic OR bypass' },
  { payload: "' OR 1=1--", name: 'Comment bypass' },
  { payload: "'; DROP TABLE users--", name: 'Drop table' },
];

const AUTH_BYPASS_GQL = [
  { query: '{__typename}', variables: '{}', description: 'Unauthenticated introspection' },
  { query: 'mutation { login(username:"admin",password:"admin") { token } }', variables: '{}', description: 'Default creds' },
  { query: 'mutation { __typename }', variables: '{}', description: 'Mutation without auth' },
];

async function scanGraphQL(targetUrl, httpClient) {
  const vulnerabilities = [];
  const baseUrl = targetUrl.replace(/\/$/, '');

  for (const endpoint of GRAPHQL_ENDPOINTS) {
    const gqlUrl = baseUrl + endpoint;
    const result = await testGraphQLEndpoint(gqlUrl, httpClient);
    if (result) {
      vulnerabilities.push(result);

      const introResult = await testIntrospection(gqlUrl, httpClient);
      if (introResult) vulnerabilities.push(introResult);

      const dosResults = await testDoS(gqlUrl, httpClient);
      vulnerabilities.push(...dosResults);

      const sqliResults = await testSQLiThroughGQL(gqlUrl, httpClient);
      vulnerabilities.push(...sqliResults);

      const authResults = await testAuthBypass(gqlUrl, httpClient);
      vulnerabilities.push(...authResults);
    }
  }

  return vulnerabilities;
}

async function testGraphQLEndpoint(gqlUrl, httpClient) {
  const testQueries = [
    { query: '{ __typename }', name: 'Simple query' },
    { query: 'query { __typename }', name: 'Named query' },
  ];

  for (const t of testQueries) {
    try {
      const resp = await httpClient.post(gqlUrl, { query: t.query }, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' },
        validateStatus: s => s < 500,
      });
      const data = resp.data;
      if (data && (data.data || data.errors)) {
        return {
          type: 'graphql',
          severity: 'medium',
          title: 'GraphQL Endpoint Detected',
          description: `GraphQL endpoint found at ${gqlUrl}. Responds to ${t.name}.`,
          endpoint: gqlUrl,
          parameter: 'POST body',
          payload: JSON.stringify(t),
          evidence: `URL: ${gqlUrl}\nQuery: ${t.query}\nResponse: ${JSON.stringify(data).substring(0, 200)}`,
          remediation: 'Restrict GraphQL endpoint access. Disable introspection in production. Implement query depth limiting and rate limiting.',
          owasp_category: 'A01:2021 – Broken Access Control',
          cve_id: 'CWE-200',
        };
      }
    } catch {}
  }
  return null;
}

async function testIntrospection(gqlUrl, httpClient) {
  try {
    const resp = await httpClient.post(gqlUrl, { query: INTROSPECTION_QUERY }, {
      timeout: 8000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: s => s < 500,
    });
    const data = resp.data;
    if (data && data.data && data.data.__schema) {
      const types = data.data.__schema.types || [];
      const typeCount = types.length;
      const hasMutations = !!data.data.__schema.mutationType;
      const hasSubscriptions = !!data.data.__schema.subscriptionType;
      const sensitiveTypes = types.filter(t =>
        /user|admin|password|token|secret|key|credential|auth/i.test(t.name || '')
      );

      return {
        type: 'graphql',
        severity: 'high',
        title: 'GraphQL Introspection Enabled',
        description: `GraphQL introspection is enabled at ${gqlUrl}. ${typeCount} types exposed${hasMutations ? ', mutations available' : ''}. ${sensitiveTypes.length > 0 ? `Found ${sensitiveTypes.length} sensitive type(s): ${sensitiveTypes.map(t => t.name).join(', ')}` : ''}`,
        endpoint: gqlUrl,
        parameter: 'Introspection query',
        payload: INTROSPECTION_QUERY.substring(0, 100) + '...',
        evidence: `Types: ${typeCount}\nMutations: ${hasMutations}\nSubscriptions: ${hasSubscriptions}\nSensitive: ${sensitiveTypes.map(t => `${t.name} (${t.description || 'no desc'})`).join(', ')}`,
        remediation: 'Disable GraphQL introspection in production. Use a whitelist of allowed queries (persisted queries).',
        owasp_category: 'A01:2021 – Broken Access Control',
        cve_id: 'CWE-200',
      };
    }
  } catch {}
  return null;
}

async function testDoS(gqlUrl, httpClient) {
  const results = [];
  for (const attack of DOS_QUERIES) {
    try {
      const resp = await httpClient.post(gqlUrl, { query: attack.query }, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' },
        validateStatus: s => s < 500,
      });
      const elapsed = resp.headers['x-response-time'] || 'unknown';
      if (resp.status === 200) {
        results.push({
          type: 'graphql',
          severity: 'medium',
          title: `GraphQL DoS Vector - ${attack.name}`,
          description: `GraphQL endpoint at ${gqlUrl} allows ${attack.name} queries. Possible DoS vector.`,
          endpoint: gqlUrl,
          parameter: 'Query complexity',
          payload: attack.query.substring(0, 100),
          evidence: `Attack: ${attack.name}\nFields: ${(attack.query.match(/__typename/g) || []).length} fields\nResponse status: ${resp.status}\nServer response time: ${elapsed}`,
          remediation: 'Implement query complexity analysis, depth limiting, and rate limiting on GraphQL endpoints.',
          owasp_category: 'A04:2021 – Insecure Design',
          cve_id: 'CWE-400',
        });
        break;
      }
    } catch {}
  }
  return results;
}

async function testSQLiThroughGQL(gqlUrl, httpClient) {
  const results = [];
  for (const attack of SQLI_THROUGH_GQL) {
    try {
      const resp = await httpClient.post(gqlUrl, {
        query: `query { search(query: "${attack.payload}") { results } }`,
      }, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' },
        validateStatus: s => s < 500,
      });
      const body = JSON.stringify(resp.data || '');
      if (/(SQL syntax|mysql|ORA-|PostgreSQL|SQLite)/i.test(body)) {
        results.push({
          type: 'graphql',
          severity: 'critical',
          title: 'SQL Injection via GraphQL',
          description: `GraphQL endpoint ${gqlUrl} is vulnerable to SQL injection via ${attack.name}.`,
          endpoint: gqlUrl,
          parameter: 'GraphQL query argument',
          payload: attack.payload,
          evidence: `Attack: ${attack.name}\nPayload: ${attack.payload}\nError evidence in response`,
          remediation: 'Use parameterized queries in GraphQL resolvers. Validate and sanitize all arguments.',
          owasp_category: 'A03:2021 – Injection',
          cve_id: 'CWE-89',
        });
        break;
      }
    } catch {}
  }
  return results;
}

async function testAuthBypass(gqlUrl, httpClient) {
  const results = [];
  for (const attack of AUTH_BYPASS_GQL) {
    try {
      const resp = await httpClient.post(gqlUrl, { query: attack.query }, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' },
        validateStatus: s => s < 500,
      });
      const data = resp.data;
      if (data && data.data && !data.errors) {
        results.push({
          type: 'graphql',
          severity: 'high',
          title: `GraphQL Auth Bypass - ${attack.description}`,
          description: `GraphQL endpoint ${gqlUrl} responds to ${attack.description} without proper auth.`,
          endpoint: gqlUrl,
          parameter: 'GraphQL mutation/query',
          payload: attack.query.substring(0, 100),
          evidence: `Query: ${attack.query}\nResponse: ${JSON.stringify(data).substring(0, 200)}\nNo authentication required`,
          remediation: 'Implement authentication and authorization on all GraphQL queries and mutations. Use field-level permissions.',
          owasp_category: 'A07:2021 – Identification and Authentication Failures',
          cve_id: 'CWE-306',
        });
        break;
      }
    } catch {}
  }
  return results;
}

module.exports = { scanGraphQL, GRAPHQL_ENDPOINTS };
