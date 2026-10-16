const express = require('express');
const router = express.Router();
const authService = require('../services/authService');
const db = require('../db');

// POST /api/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  try {
    const result = await authService.login(username, password, clientIp);
    res.json(result);
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

// GET /api/dashboard (Protegido con JWT)
router.get('/dashboard', authService.verifyToken, (req, res) => {
  db.all('SELECT severity, COUNT(*) as count FROM security_logs GROUP BY severity', [], (err, rows) => {
    const stats = { INFO: 0, WARN: 0, CRITICAL: 0 };
    if (!err && rows) {
      rows.forEach(r => { stats[r.severity] = r.count; });
    }

    res.json({
      message: 'Telemetría de Red y Seguridad Zero Trust',
      user: req.user,
      network: {
        backend_ip: '10.1.28.160',
        segment: 'VPC Backend Privada (/17)',
        status: 'Aislado (Sin salida a Internet pública)',
        peering: 'pcx-059... Activo'
      },
      metrics: {
        total_incidents: stats.WARN + stats.CRITICAL,
        system_integrity: '100% OK',
        audit_events: stats
      },
      timestamp: new Date().toISOString()
    });
  });
});

// GET /api/logs (Protegido con JWT - Consulta de logs)
router.get('/logs', authService.verifyToken, (req, res) => {
  db.all('SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 50', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al consultar logs' });
    res.json(rows);
  });
});

// POST /api/incident (Protegido con RBAC: Solo rol ADMIN)
router.post('/incident', authService.verifyToken, authService.requireRole(['ADMIN']), (req, res) => {
  const { action, severity, details } = req.body;
  const clientIp = req.ip || req.headers['x-forwarded-for'];

  if (!action || !details) {
    return res.status(400).json({ error: 'Acción y detalles del incidente requeridos' });
  }

  const sev = ['INFO', 'WARN', 'CRITICAL'].includes(severity) ? severity : 'WARN';

  db.run(
    `INSERT INTO security_logs (action, user_id, ip_origin, severity, details) VALUES (?, ?, ?, ?, ?)`,
    [action, req.user.username, clientIp, sev, details],
    function (err) {
      if (err) return res.status(500).json({ error: 'No se pudo guardar el incidente' });
      res.status(201).json({ message: 'Incidente registrado en la bitácora', id: this.lastID });
    }
  );
});

module.exports = router;
