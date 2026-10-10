const express = require('express');
const router = express.Router();
const authService = require('../services/authService');

// POST /api/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  try {
    const result = await authService.login(username, password);
    res.json(result);
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

// GET /api/dashboard (Protegido con JWT)
router.get('/dashboard', authService.verifyToken, (req, res) => {
  res.json({
    message: 'Acceso autorizado al Dashboard',
    user: req.user,
    timestamp: new Date().toISOString(),
    system: {
      status: 'Operativo',
      network: 'VPC Backend Privada',
      security: 'Zero Trust / JWT Validated'
    }
  });
});

module.exports = router;
