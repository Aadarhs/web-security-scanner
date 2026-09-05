const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const REPORTS_DIR = process.env.VERCEL === '1' ? '/tmp/reports/generated' : path.join(__dirname, 'generated');
try {
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
} catch (e) {
  console.error('[Reports] Could not create reports dir:', e.message);
}

function generateJSONReport(scan, vulnerabilities, reportId) {
  return new Promise((resolve, reject) => {
    try {
      const report = {
        reportId,
        generatedAt: new Date().toISOString(),
        scan: {
          id: scan.id,
          targetUrl: scan.target_url,
          status: scan.status,
          riskScore: scan.risk_score,
          totalVulnerabilities: scan.total_vulnerabilities,
          critical: scan.critical_count,
          high: scan.high_count,
          medium: scan.medium_count,
          low: scan.low_count,
          info: scan.info_count,
          startedAt: scan.created_at,
          completedAt: scan.completed_at,
        },
        vulnerabilities: vulnerabilities.map(v => ({
          type: v.type,
          severity: v.severity,
          title: v.title,
          description: v.description,
          endpoint: v.endpoint,
          parameter: v.parameter,
          payload: v.payload,
          remediation: v.remediation,
          owasp: v.owasp_category,
          cve: v.cve_id,
        })),
        summary: {
          bySeverity: {
            critical: vulnerabilities.filter(v => v.severity === 'critical').length,
            high: vulnerabilities.filter(v => v.severity === 'high').length,
            medium: vulnerabilities.filter(v => v.severity === 'medium').length,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
            info: vulnerabilities.filter(v => v.severity === 'info').length,
          },
          byType: {},
        },
        disclaimer: 'This report is for authorized security testing purposes only. Unauthorized scanning of systems you do not own is illegal.',
      };

      for (const v of vulnerabilities) {
        report.summary.byType[v.type] = (report.summary.byType[v.type] || 0) + 1;
      }

      const filePath = path.join(REPORTS_DIR, `${reportId}.json`);
      fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
      resolve(filePath);
    } catch (err) {
      reject(err);
    }
  });
}

function generatePDFReport(scan, vulnerabilities, reportId) {
  return new Promise((resolve, reject) => {
    try {
      const filePath = path.join(REPORTS_DIR, `${reportId}.pdf`);
      const doc = new PDFDocument({ 
        size: 'A4', 
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `Security Scan Report - ${scan.target_url}`,
          Author: 'Web Security Scanner',
          Subject: 'Vulnerability Assessment Report',
        }
      });

      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      doc.fontSize(24).font('Helvetica-Bold').fillColor('#00f0ff').text('Web Security Scanner', { align: 'center' });
      doc.fontSize(14).font('Helvetica').fillColor('#888').text('Vulnerability Assessment Report', { align: 'center' });
      doc.moveDown(1.5);

      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#00f0ff').stroke();
      doc.moveDown(1);

      doc.fontSize(12).fillColor('#333');
      doc.font('Helvetica-Bold').text('Scan Summary');
      doc.moveDown(0.5);
      doc.font('Helvetica').fillColor('#555');

      const summaryData = [
        ['Target URL', scan.target_url],
        ['Scan ID', scan.id],
        ['Status', scan.status],
        ['Risk Score', `${scan.risk_score || 0}/100`],
        ['Total Vulnerabilities', String(scan.total_vulnerabilities || 0)],
        ['Started', scan.created_at],
        ['Completed', scan.completed_at || 'In Progress'],
      ];

      for (const [label, value] of summaryData) {
        doc.font('Helvetica-Bold').fillColor('#333').text(`${label}: `, { continued: true });
        doc.font('Helvetica').fillColor('#555').text(value);
      }

      doc.moveDown(1.5);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#ccc').stroke();
      doc.moveDown(1);

      doc.font('Helvetica-Bold').fillColor('#333').fontSize(16).text('Vulnerabilities', { underline: true });
      doc.moveDown(0.5);
      doc.font('Helvetica').fontSize(10);

      const severityColors = { critical: '#ff0044', high: '#ff6600', medium: '#ffcc00', low: '#4488ff', info: '#888888' };

      if (vulnerabilities.length === 0) {
        doc.moveDown(1);
        doc.font('Helvetica-Bold').fillColor('#00cc00').fontSize(14).text('No vulnerabilities detected.', { align: 'center' });
      } else {
        for (const v of vulnerabilities) {
          const color = severityColors[v.severity] || '#888';

          if (doc.y > 700) {
            doc.addPage();
          }

          doc.fillColor(color).font('Helvetica-Bold').fontSize(12).text(`[${v.severity.toUpperCase()}] ${v.title}`);
          doc.fillColor('#555').font('Helvetica').fontSize(9);
          doc.text(`Type: ${v.type} | OWASP: ${v.owasp_category || 'N/A'} | CVE: ${v.cve_id || 'N/A'}`);
          doc.text(`Endpoint: ${v.endpoint || 'N/A'}`);
          doc.text(`Parameter: ${v.parameter || 'N/A'}`);
          doc.moveDown(0.3);
          doc.fillColor('#333').fontSize(9).text(`Remediation: ${v.remediation}`);
          doc.moveDown(0.5);
          doc.moveTo(60, doc.y).lineTo(540, doc.y).strokeColor('#eee').stroke();
          doc.moveDown(0.5);
        }
      }

      doc.moveDown(2);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#00f0ff').stroke();
      doc.moveDown(0.5);
      doc.fillColor('#999').fontSize(8).text('This report is for authorized security testing purposes only.', { align: 'center' });
      doc.fillColor('#999').fontSize(8).text(`Generated: ${new Date().toISOString()}`, { align: 'center' });

      doc.end();
      stream.on('finish', () => resolve(filePath));
      stream.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { generatePDFReport, generateJSONReport };
