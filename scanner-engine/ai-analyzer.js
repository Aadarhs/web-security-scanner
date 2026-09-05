'use strict';

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
      const vulnSummary = (vulnerabilities || []).map((v, i) =>
        `[${i + 1}] ${v.title} (${v.severity.toUpperCase()}, confidence: ${v.confidence || 'confirmed'})\n   Type: ${v.type}\n   Description: ${(v.description || '').substring(0, 200)}`
      ).join('\n');

      const prompt = ANALYSIS_PROMPT
        .replace('{targetUrl}', targetUrl)
        .replace('{riskScore}', riskScore)
        .replace('{totalVulns}', (vulnerabilities || []).length)
        .replace('{vulnerabilities}', vulnSummary || 'No vulnerabilities found');

      const result = await executeLLMAnalysis(prompt, 'analysis');
      resolve({
        provider: 'llm',
        riskSummary: result.riskSummary || 'No summary provided.',
        prioritizedActions: Array.isArray(result.prioritizedActions) ? result.prioritizedActions : [],
        chainingPossibilities: Array.isArray(result.chainingPossibilities) ? result.chainingPossibilities : [],
      });
    } catch {
      resolve(buildFallbackAnalysis(targetUrl, riskScore, vulnerabilities));
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
      resolve({
        provider: 'llm',
        stepByStepGuide: Array.isArray(result.stepByStepGuide) ? result.stepByStepGuide : [],
        codeExamples: Array.isArray(result.codeExamples) ? result.codeExamples : [],
        testingSteps: Array.isArray(result.testingSteps) ? result.testingSteps : [],
        preventionTips: Array.isArray(result.preventionTips) ? result.preventionTips : [],
      });
    } catch {
      resolve(buildFallbackRemediation(title, type, severity, currentRemediation));
    }
  });
}

async function executeLLMAnalysis(prompt, type) {
  const axios = require('axios');

  const apiKey = process.env.OPENAI_API_KEY || process.env.LLM_API_KEY;
  const apiUrl = process.env.LLM_API_URL || 'https://api.openai.com/v1';
  const model = process.env.LLM_MODEL || 'gpt-3.5-turbo';

  if (!apiKey) {
    if (process.env.LLM_ENABLED !== 'true') {
      throw new Error('LLM not enabled');
    }
    return localAnalysis(prompt, type);
  }

  const response = await axios.post(`${apiUrl}/chat/completions`, {
    model,
    messages: [
      { role: 'system', content: 'You are a cybersecurity analysis assistant. Respond ONLY with valid JSON.' },
      { role: 'user', content: prompt },
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
}

async function localAnalysis(prompt, type) {
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
}

function buildFallbackAnalysis(targetUrl, riskScore, vulnerabilities) {
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const findings = vulnerabilities || [];
  const prioritizedActions = [];

  for (const sev of severityOrder) {
    const sevVulns = findings.filter(v => v.severity === sev);
    const considered = sev === 'critical' || sev === 'high' ? sevVulns.slice(0, 5) : sevVulns.slice(0, 3);
    for (const v of considered) {
      prioritizedActions.push({
        severity: v.severity,
        title: v.title,
        confidence: v.confidence || 'confirmed',
        action: v.remediation || 'Apply the OWASP guidance for the reported issue.',
        businessImpact: null,
      });
    }
  }

  return {
    provider: 'builtin-summary',
    riskSummary: `Automated summary for ${targetUrl} (risk score ${riskScore}/100, ${findings.length} finding(s)). This is not an expert verdict: the scanner only reports what its checks observed, and it cannot guarantee that all issues were found.`,
    prioritizedActions,
    chainingPossibilities: [],
    disclaimer: 'Generated locally by the scanner (no LLM connected). Business impact and attack chaining require manual expert assessment.',
  };
}

function buildFallbackRemediation(title, type, severity, currentRemediation) {
  return {
    provider: 'builtin-template',
    stepByStepGuide: [
      `Locate every code path that can trigger "${title || 'this issue'}".`,
      currentRemediation
        ? `Apply the recommended remediation: ${currentRemediation}`
        : 'Apply the OWASP guidance for the reported issue type.',
      'Review surrounding code for similar patterns.',
      'Re-run the scanner to confirm the finding is resolved.',
    ],
    codeExamples: [],
    testingSteps: [
      'Re-run the relevant scanner module against the endpoint.',
      'Perform manual verification of the affected parameter/endpoint.',
      'Review the fix for regressions and similar code patterns.',
    ],
    preventionTips: [
      'Adopt secure-by-design practices and input validation.',
      'Add security scanning to CI/CD.',
      'Provide regular security training for developers.',
    ],
    disclaimer: 'Generated locally from a template (no LLM connected). No framework-specific code is suggested.',
  };
}

module.exports = { generateAnalysis, generateRemediation, buildFallbackAnalysis, buildFallbackRemediation };