const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database/db');

const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_super_segura_zero_trust';

const authService = {
  // Inicializa usuario admin por defecto si no existe
  seedAdminUser: async () => {
    const hash = await bcrypt.hash('admin123', 10);
    db.run(
      'INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
      ['admin', hash]
    );
  },

  // Lógica de inicio de sesión
  login: (username, password) => {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return reject({ status: 500, message: 'Error de base de datos' });
        if (!user) return reject({ status: 401, message: 'Credenciales inválidas' });

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return reject({ status: 401, message: 'Credenciales inválidas' });

        const token = jwt.sign(
          { id: user.id, username: user.username },
          JWT_SECRET,
          { expiresIn: '2h' }
        );

        resolve({ token, username: user.username });
      });
    });
  },

  // Middleware para verificar JWT (Zero Trust: cada petición debe ser validada)
  verifyToken: (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ error: 'Token no proporcionado' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Formato de token inválido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ error: 'Token inválido o expirado' });
      }
      req.user = decoded;
      next();
    });
  }
};

module.exports = authService;
