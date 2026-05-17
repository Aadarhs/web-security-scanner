const express = require('express');
const { getWebhookConfigs, saveWebhookConfig, deleteWebhookConfig, testWebhook } = require('../utils/notifications');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

router.get('/configs', authenticate, (req, res) => {
  const configs = getWebhookConfigs();
  res.json({ configs });
});

router.post('/configs', authenticate, (req, res) => {
  const { type, name, webhookUrl, ...rest } = req.body;
  if (!type || !name || !webhookUrl) {
    return res.status(400).json({ error: 'type, name, and webhookUrl are required' });
  }
  const result = saveWebhookConfig({ type, name, webhookUrl, ...rest });
  res.json(result);
});

router.delete('/configs/:id', authenticate, (req, res) => {
  const result = deleteWebhookConfig(parseInt(req.params.id));
  res.json(result);
});

router.post('/test', authenticate, async (req, res) => {
  const { type, webhookUrl, ...rest } = req.body;
  if (!type || !webhookUrl) {
    return res.status(400).json({ error: 'type and webhookUrl are required' });
  }
  const result = await testWebhook(type, { webhookUrl, ...rest });
  res.json(result);
});

module.exports = router;
