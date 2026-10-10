const express = require('express');
const cors = require('cors');
const authService = require('./services/authService');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Sembrar usuario inicial
authService.seedAdminUser();

// Rutas base
app.use('/api', apiRoutes);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor Backend activo en http://0.0.0.0:${PORT}`);
});
