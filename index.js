import express from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'panalsuite_secret_key_dev';

app.use(cors());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const TICKET_SELECT_FIELDS = `
  id_request AS "idRequest",
  flow_type AS "flowType",
  priority,
  state,
  requester,
  assignee,
  reference_location AS "referenceLocation",
  description,
  created_at AS "createdAt",
  updated_at AS "updatedAt",
  comments,
  history
`;

// Middleware para verificar el JWT emitido en /api/auth/login
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
    req.user = decoded;
    next();
  });
}

// Crea usuarios de prueba para los 5 roles de RoleExtensions.kt si la tabla está vacía
async function seedInitialUsers() {
  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM users');
    if (rows[0].count === 0) {
      const hash = await bcrypt.hash('123456', 10);
      await pool.query(
        `INSERT INTO users (name, email, password_hash, role) VALUES
          ('Ana Solicitante', 'solicitante@panalbit.cl', $1, 'REQUESTER'),
          ('Raúl Resolutor', 'resolutor@panalbit.cl', $1, 'RESOLVER'),
          ('Sofía Supervisora', 'supervisor@panalbit.cl', $1, 'SUPERVISOR'),
          ('Admin Prueba', 'admin@panalbit.cl', $1, 'ADMIN'),
          ('Gael Gerencia', 'gerencia@panalbit.cl', $1, 'MANAGER')`,
        [hash]
      );
      console.log('Usuarios iniciales creados (contraseña: 123456)');
    }
  } catch (err) {
    console.error('Error al verificar/crear usuarios iniciales:', err.message);
  }
}

// 1. POST api/auth/login (pública)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error interno en login' });
  }
});

// 2. GET api/users/{id}
app.get('/api/users/:id', verifyToken, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  try {
    const result = await pool.query(
      'SELECT id, name, email, role FROM users WHERE id = $1',
      [userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener usuario' });
  }
});

// 3. GET api/tickets
app.get('/api/tickets', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ${TICKET_SELECT_FIELDS}
      FROM tickets
      ORDER BY created_at DESC
    `);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al listar tickets' });
  }
});

// 4. POST api/tickets
app.post('/api/tickets', verifyToken, async (req, res) => {
  const {
    idRequest,
    flowType,
    priority,
    state,
    requester,
    assignee,
    referenceLocation,
    description,
    createdAt,
    updatedAt,
    comments,
    history
  } = req.body;

  const now = new Date().toISOString();

  try {
    let finalIdRequest = idRequest && idRequest.trim() !== '' ? idRequest.trim() : null;
    if (!finalIdRequest) {
      const seqRes = await pool.query("SELECT 'REQ-' || nextval('ticket_req_seq') AS code");
      finalIdRequest = seqRes.rows[0].code;
    }

    const result = await pool.query(
      `INSERT INTO tickets (
        id_request, flow_type, priority, state, requester, assignee,
        reference_location, description, created_at, updated_at, comments, history
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb)
      RETURNING ${TICKET_SELECT_FIELDS}`,
      [
        finalIdRequest,
        flowType || 'Mesa de ayuda',
        priority || 'Media',
        state || 'Abierto',
        requester,
        assignee || null,
        referenceLocation || '',
        description,
        createdAt && createdAt.trim() !== '' ? createdAt : now,
        updatedAt && updatedAt.trim() !== '' ? updatedAt : now,
        JSON.stringify(comments || []),
        JSON.stringify(history || [])
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al crear ticket' });
  }
});

// 5. PUT api/tickets/{id}
app.put('/api/tickets/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const {
    flowType,
    priority,
    state,
    requester,
    assignee,
    referenceLocation,
    description,
    updatedAt,
    comments,
    history
  } = req.body;

  const now = new Date().toISOString();

  try {
    const result = await pool.query(
      `UPDATE tickets
       SET flow_type = $1,
           priority = $2,
           state = $3,
           requester = $4,
           assignee = $5,
           reference_location = $6,
           description = $7,
           updated_at = $8,
           comments = $9::jsonb,
           history = $10::jsonb
       WHERE id_request = $11
       RETURNING ${TICKET_SELECT_FIELDS}`,
      [
        flowType,
        priority,
        state,
        requester,
        assignee || null,
        referenceLocation || '',
        description,
        updatedAt && updatedAt.trim() !== '' ? updatedAt : now,
        JSON.stringify(comments || []),
        JSON.stringify(history || []),
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Ticket no encontrado' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al actualizar ticket' });
  }
});

// 6. DELETE api/tickets/{id}
app.delete('/api/tickets/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM tickets WHERE id_request = $1 RETURNING id_request',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Ticket no encontrado' });
    }

    res.status(200).json({ message: 'Ticket eliminado correctamente', idRequest: id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al eliminar ticket' });
  }
});

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Servidor PanalSuite corriendo en http://0.0.0.0:${PORT}`);
  await seedInitialUsers();
});