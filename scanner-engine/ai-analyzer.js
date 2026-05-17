const ANALYSIS_PROMPT = `You are a senior application security engineer. Analyze the following vulnerability findings from a web security scan and provide:
1. A brief risk assessment summary
2. Prioritized remediation recommendations
3. Potential business impact of each finding
4. Related attack vectors or chaining possibilities

Target URL: {targetUrl}
Scan Risk Score: {riskScore}/100
Total Vulnerabilities: {totalVulns}

Vulnerabilities:
{vulnerabilities}

Provide response as JSON with fields: riskSummary, prioritizedActions (array of {severity, title, action, businessImpact}), and chainingPossibilities (array of strings).`;

const REMEDIATION_PROMPT = `Given the following web vulnerability, provide a detailed step-by-step remediation guide:

Vulnerability: {title}
Type: {type}
Severity: {severity}
Description: {description}
Current Remediation: {currentRemediation}
OWASP Category: {owaspCategory}

Provide response as JSON with fields: stepByStepGuide (array of strings), codeExamples (array of {language, code}), testingSteps (array of strings), and preventionTips (array of strings).`;

function generateAnalysis(targetUrl, riskScore, vulnerabilities) {
  return new Promise(async (resolve) => {
    try {
      const vulnSummary = vulnerabilities.map((v, i) =>
        `[${i + 1}] ${v.title} (${v.severity.toUpperCase()})\n   Type: ${v.type}\n   Description: ${(v.description || '').substring(0, 200)}`
      ).join('\n');

      const prompt = ANALYSIS_PROMPT
        .replace('{targetUrl}', targetUrl)
        .replace('{riskScore}', riskScore)
        .replace('{totalVulns}', vulnerabilities.length)
        .replace('{vulnerabilities}', vulnSummary || 'No vulnerabilities found');

      const result = await executeLLMAnalysis(prompt, 'analysis');
      resolve(result);
    } catch {
      resolve(getFallbackAnalysis(targetUrl, riskScore, vulnerabilities));
    }
  });
}

function generateRemediation(title, type, severity, description, currentRemediation, owaspCategory) {
  return new Promise(async (resolve) => {
    try {
      const prompt = REMEDIATION_PROMPT
        .replace('{title}', title)
        .replace('{type}', type)
        .replace('{severity}', severity)
        .replace('{description}', (description || '').substring(0, 500))
        .replace('{currentRemediation}', currentRemediation || 'Not specified')
        .replace('{owaspCategory}', owaspCategory || 'N/A');

      const result = await executeLLMAnalysis(prompt, 'remediation');
      resolve(result);
    } catch {
      resolve(getFallbackRemediation(title, type, severity, currentRemediation));
    }
  });
}

async function executeLLMAnalysis(prompt, type) {
  const axios = require('axios');

  const { Configuration, OpenAIApi } = (function() {
    try {
      return require('openai');
    } catch {
      return { Configuration: null, OpenAIApi: null };
    }
  })();

  const apiKey = process.env.OPENAI_API_KEY || process.env.LLM_API_KEY;
  const apiUrl = process.env.LLM_API_URL || 'https://api.openai.com/v1';
  const model = process.env.LLM_MODEL || 'gpt-3.5-turbo';

  if (!apiKey) {
    if (process.env.LLM_ENABLED !== 'true') {
      throw new Error('LLM not enabled');
    }
    return localAnalysis(prompt, type);
  }

  try {
    const response = await axios.post(`${apiUrl}/chat/completions`, {
      model,
      messages: [
        { role: 'system', content: 'You are a cybersecurity analysis assistant. Respond ONLY with valid JSON.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.3,
      max_tokens: 2000,
    }, {
      timeout: 30000,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
    });

    const content = response.data?.choices?.[0]?.message?.content || '{}';
    return JSON.parse(content.replace(/```json|```/g, '').trim());
  } catch {
    return localAnalysis(prompt, type);
  }
}

async function localAnalysis(prompt, type) {
  try {
    const axios = require('axios');
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
    const model = process.env.OLLAMA_MODEL || 'codellama';

    const response = await axios.post(`${ollamaUrl}/api/generate`, {
      model,
      prompt: 'Respond with valid JSON only.\n' + prompt,
      stream: false,
      temperature: 0.3,
    }, { timeout: 60000 });

    const text = response.data?.response || '{}';
    return JSON.parse(text.replace(/```json|```/g, '').trim());
  } catch {
    throw new Error('Local LLM unavailable');
  }
}

function getFallbackAnalysis(targetUrl, riskScore, vulnerabilities) {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const priorityActions = [];

  for (const sev of severityOrder) {
    const sevVulns = vulnerabilities.filter(v => v.severity === sev);
    for (const v of sevVulns.slice(0, 3)) {
      priorityActions.push({
        severity: v.severity,
        title: v.title,
        action: v.remediation || 'Apply security fix based on OWASP guidelines.',
        businessImpact: sev === 'critical' || sev === 'high'
          ? 'Potential data breach, financial loss, or reputational damage.'
          : 'Moderate security risk, may aid attackers in further exploitation.',
      });
    }
  }

  return {
    riskSummary: riskScore > 50
      ? `HIGH RISK: Target ${targetUrl} has a risk score of ${riskScore}/100 with ${vulnerabilities.length} vulnerabilities. Immediate remediation required for critical and high-severity findings.`
      : riskScore > 20
        ? `MEDIUM RISK: Target ${targetUrl} has a risk score of ${riskScore}/100. Address high-severity issues and plan remediation for others.`
        : `LOW RISK: Target ${targetUrl} has a risk score of ${riskScore}/100. Mostly informational findings.`,
    prioritizedActions: priorityActions,
    chainingPossibilities: [
      'SQL injection + XSS can be combined for stored XSS via database',
      'Open redirect can be used to bypass URL validation in SSRF filters',
      'Directory listing + exposed config files can reveal credentials',
    ],
  };
}

function getFallbackRemediation(title, type, severity, currentRemediation) {
  return {
    stepByStepGuide: [
      `Identify all code paths where this vulnerability (${title}) can be triggered.`,
      `Implement input validation and output encoding for all user-supplied data.`,
      `Apply the principle of least privilege to affected components.`,
      `Test the fix with both automated and manual security testing.`,
    ],
    codeExamples: [
      { language: 'javascript', code: '// Use parameterized queries\nconst result = await db.query("SELECT * FROM users WHERE id = ?", [userId]);' },
    ],
    testingSteps: [
      'Run automated scanner to verify the fix',
      'Perform manual penetration testing on the affected endpoint',
      'Review code changes for similar patterns',
    ],
    preventionTips: [
      'Adopt a security-by-design approach in development',
      'Regular security training for developers',
      'Implement automated security testing in CI/CD pipeline',
    ],
  };
}

module.exports = { generateAnalysis, generateRemediation, getFallbackAnalysis };