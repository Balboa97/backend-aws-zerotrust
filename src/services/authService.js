const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'clave_super_secreta_zerotrust_2026';

const authService = {
  // Inicializar usuarios semilla (admin y auditor)
  seedAdminUser: () => {
    const saltRounds = 10;
    const adminPass = bcrypt.hashSync('admin2026!', saltRounds);
    const auditorPass = bcrypt.hashSync('audit2026!', saltRounds);

    db.run(
      `INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`,
      ['admin', adminPass, 'ADMIN']
    );

    db.run(
      `INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`,
      ['auditor', auditorPass, 'AUDITOR']
    );
  },

  // Login con registro de eventos de auditoría
  login: (username, password, clientIp) => {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return reject({ status: 500, message: 'Error interno en la BD' });

        if (!user || !bcrypt.compareSync(password, user.password)) {
          // Registrar intento sospechoso en la bitácora
          db.run(
            `INSERT INTO security_logs (action, user_id, ip_origin, severity, details) 
             VALUES (?, ?, ?, ?, ?)`,
            ['LOGIN_FAILED', username || 'ANON', clientIp, 'WARN', 'Credenciales erróneas proporcionadas']
          );
          return reject({ status: 401, message: 'Credenciales inválidas' });
        }

        // Generar Token JWT con vigencia de 2 horas
        const token = jwt.sign(
          { id: user.id, username: user.username, role: user.role },
          JWT_SECRET,
          { expiresIn: '2h' }
        );

        // Registrar login exitoso
        db.run(
          `INSERT INTO security_logs (action, user_id, ip_origin, severity, details) 
           VALUES (?, ?, ?, ?, ?)`,
          ['LOGIN_SUCCESS', user.username, clientIp, 'INFO', `Sesión iniciada con rol ${user.role}`]
        );

        resolve({
          message: 'Autenticación exitosa',
          token,
          user: { id: user.id, username: user.username, role: user.role }
        });
      });
    });
  },

  // Middleware Zero Trust: Validar Token en cada solicitud
  verifyToken: (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Token no proporcionado. Acceso denegado.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ error: 'Token inválido o expirado.' });
      }
      req.user = decoded;
      next();
    });
  },

  // Middleware de Control de Acceso por Roles (RBAC)
  requireRole: (allowedRoles) => {
    return (req, res, next) => {
      if (!req.user || !allowedRoles.includes(req.user.role)) {
        return res.status(403).json({ 
          error: `Acceso no autorizado. Se requiere uno de los siguientes roles: ${allowedRoles.join(', ')}` 
        });
      }
      next();
    };
  }
};

module.exports = authService;
