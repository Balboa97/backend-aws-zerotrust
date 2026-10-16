const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const authService = require('./services/authService');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de trust proxy para leer la IP real enviada por Nginx
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// 1. Rate Limiting general para la API (100 peticiones por 15 min)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes desde este origen. Intente más tarde.' }
});
app.use('/api/', generalLimiter);

// 2. Rate Limiting estricto para Login contra ataques de fuerza bruta (10 intentos por 15 min)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos fallidos de autenticación. Bloqueo temporal activo.' }
});
app.use('/api/login', loginLimiter);

// Sembrar usuario inicial
authService.seedAdminUser();

// Rutas base
app.use('/api', apiRoutes);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor Backend activo en http://0.0.0.0:${PORT}`);
});
