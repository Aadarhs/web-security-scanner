const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const REPORTS_DIR = process.env.VERCEL === '1' ? '/tmp/reports/generated' : path.join(__dirname, 'generated');
try {
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
} catch (e) {
  console.error('[Reports] Could not create reports dir:', e.message);
}

const SEVERITY_LABELS = {
  critical: { emoji: '🔴', severity: 'Critical', color: '#ff0044', risk: 'Immediate action required. These vulnerabilities pose a direct threat to system security and may result in data breach, system compromise, or service disruption.' },
  high: { emoji: '🟠', severity: 'High', color: '#ff6600', risk: 'Urgent attention needed. These vulnerabilities significantly increase the attack surface and could be exploited with moderate effort.' },
  medium: { emoji: '🟡', severity: 'Medium', color: '#ffcc00', risk: 'Should be addressed in the current sprint/cycle. May require specific conditions to exploit but still pose a meaningful risk.' },
  low: { emoji: '🔵', severity: 'Low', color: '#4488ff', risk: 'Low priority. Typically informational or requiring unlikely conditions. Address during regular maintenance cycles.' },
  info: { emoji: '⚪', severity: 'Informational', color: '#888888', risk: 'For awareness only. No direct security impact.' },
};

function generateExecutiveReport(scan, vulnerabilities, reportId) {
  return new Promise((resolve, reject) => {
    try {
      const filePath = path.join(REPORTS_DIR, `${reportId}-executive.pdf`);
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `Executive Summary - ${scan.target_url}`,
          Author: 'Web Security Scanner',
          Subject: 'Executive Security Summary (Non-Technical)',
        },
      });

      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
      const high = vulnerabilities.filter(v => v.severity === 'high').length;
      const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
      const low = vulnerabilities.filter(v => v.severity === 'low').length;
      const info = vulnerabilities.filter(v => v.severity === 'info').length;
      const total = vulnerabilities.length;
      const riskScore = scan.risk_score || 0;

      const riskLevel = riskScore >= 50 ? 'High' : riskScore >= 25 ? 'Medium' : 'Low';
      const riskColor = riskScore >= 50 ? '#ff0044' : riskScore >= 25 ? '#ff6600' : '#00cc66';

      doc.fontSize(22).font('Helvetica-Bold').fillColor('#1a1a2e').text('Executive Security Summary', { align: 'center' });
      doc.fontSize(12).font('Helvetica').fillColor('#666').text('Non-Technical Vulnerability Assessment Report', { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(9).fillColor('#999').text(`Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, { align: 'center' });
      doc.moveDown(1.5);

      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(1);

      doc.fontSize(16).fillColor('#1a1a2e').font('Helvetica-Bold').text('Overall Risk Assessment');
      doc.moveDown(0.5);

      doc.fontSize(28).fillColor(riskColor).font('Helvetica-Bold').text(`${riskLevel} Risk (${riskScore}/100)`, { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor('#555').font('Helvetica');
      doc.text(`Security scan of ${scan.target_url} identified ${total} vulnerabilities.`, { align: 'center' });
      doc.moveDown(0.3);

      if (riskScore >= 50) {
        doc.text('The system requires immediate security attention. Critical and high-severity findings must be addressed urgently to prevent potential data breaches or service compromise.', { align: 'center' });
      } else if (riskScore >= 25) {
        doc.text('The system has moderate security gaps that should be addressed. While no immediate critical threats are present, improvements are recommended.', { align: 'center' });
      } else {
        doc.text('The system has a good security posture with minimal findings. Continued monitoring and regular scans are recommended.', { align: 'center' });
      }

      doc.moveDown(1.5);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(1);

      doc.fontSize(16).fillColor('#1a1a2e').font('Helvetica-Bold').text('Vulnerability Summary');
      doc.moveDown(0.5);

      const barWidth = 400;
      const barHeight = 24;
      const barX = 70;
      let barY = doc.y;

      const severityOrder = [
        { key: 'critical', count: critical, label: 'Critical', color: '#ff0044' },
        { key: 'high', count: high, label: 'High', color: '#ff6600' },
        { key: 'medium', count: medium, label: 'Medium', color: '#ffcc00' },
        { key: 'low', count: low, label: 'Low', color: '#4488ff' },
        { key: 'info', count: info, label: 'Info', color: '#888888' },
      ];

      const maxCount = Math.max(...severityOrder.map(s => s.count), 1);

      for (const s of severityOrder) {
        if (doc.y > 700) { doc.addPage(); barY = doc.y; }

        doc.fontSize(10).fillColor('#333').font('Helvetica-Bold').text(s.label, barX - 55, barY + 4, { width: 50 });
        doc.roundedRect(barX, barY, barWidth, barHeight, 4).fillColor('#f0f0f0').fill();
        const fillWidth = maxCount > 0 ? (s.count / maxCount) * barWidth : 0;
        if (fillWidth > 0) {
          doc.roundedRect(barX, barY, Math.max(fillWidth, 4), barHeight, 4).fillColor(s.color).fill();
        }
        doc.fontSize(10).fillColor('#333').font('Helvetica-Bold').text(String(s.count), barX + barWidth + 10, barY + 4);
        barY += barHeight + 6;
      }

      doc.y = barY + 10;
      doc.moveDown(1);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(1);

      doc.fontSize(16).fillColor('#1a1a2e').font('Helvetica-Bold').text('What This Means for Your Business');
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#555').font('Helvetica');

      const businessImpacts = [];
      if (critical > 0) {
        businessImpacts.push(`Critical vulnerabilities (${critical} found) represent the highest security risk. These could allow attackers to gain full control of the system, access sensitive data, or disrupt operations. Immediate remediation is essential.`);
      }
      if (high > 0) {
        businessImpacts.push(`High-severity issues (${high} found) significantly increase attack surface. While requiring more effort to exploit, successful attacks could lead to data exposure, financial loss, or reputational damage.`);
      }
      if (medium > 0) {
        businessImpacts.push(`Medium-severity findings (${medium} found) should be addressed as part of regular security maintenance. Individually they pose moderate risk, but combined with other issues they can enable serious attacks.`);
      }
      if (total === 0) {
        businessImpacts.push('No vulnerabilities were detected during this scan. This indicates good security practices, though regular scanning should continue to maintain this posture.');
      }

      for (const impact of businessImpacts) {
        doc.font('Helvetica').fontSize(10).fillColor('#555');
        doc.text(`• ${impact}`, { indent: 10 });
        doc.moveDown(0.3);
      }

      doc.moveDown(1);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(1);

      doc.fontSize(16).fillColor('#1a1a2e').font('Helvetica-Bold').text('Recommended Actions');
      doc.moveDown(0.5);

      const topVulns = vulnerabilities
        .filter(v => v.severity === 'critical' || v.severity === 'high')
        .slice(0, 5);

      if (topVulns.length > 0) {
        doc.fontSize(10).fillColor('#1a1a2e').font('Helvetica-Bold').text('Priority Remediation Items:');
        doc.moveDown(0.3);
        for (const v of topVulns) {
          if (doc.y > 700) doc.addPage();
          const label = SEVERITY_LABELS[v.severity];
          doc.fontSize(9).fillColor(label.color).font('Helvetica-Bold').text(`[${label.severity}] ${v.title}`);
          doc.fontSize(8).fillColor('#555').font('Helvetica').text(`   ${v.remediation.substring(0, 200)}`);
          doc.moveDown(0.2);
        }
        doc.moveDown(0.5);
      }

      doc.fontSize(10).fillColor('#1a1a2e').font('Helvetica-Bold').text('General Recommendations:');
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor('#555').font('Helvetica');
      const generalRecs = [
        'Run regular security scans (weekly for critical systems, monthly for standard applications).',
        'Keep all software, frameworks, and libraries updated to their latest stable versions.',
        'Implement a vulnerability management program to track and remediate findings.',
        'Provide security awareness training for development and operations teams.',
        'Establish an incident response plan for addressing security breaches.',
        'Use a Web Application Firewall (WAF) as an additional layer of defense.',
      ];
      for (const rec of generalRecs) {
        doc.text(`• ${rec}`);
        doc.moveDown(0.2);
      }

      doc.moveDown(1.5);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(0.5);
      doc.fontSize(8).fillColor('#999').text(`This executive summary was automatically generated by Web Security Scanner for ${scan.target_url}.`, { align: 'center' });
      doc.fontSize(8).fillColor('#999').text('For technical details, refer to the full vulnerability assessment report.', { align: 'center' });
      doc.fontSize(8).fillColor('#999').text(`Report ID: ${reportId} | Scan ID: ${scan.id}`, { align: 'center' });

      doc.end();
      stream.on('finish', () => resolve(filePath));
      stream.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { generateExecutiveReport };
