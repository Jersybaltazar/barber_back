const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // Cambia esto a algo más seguro en producción.

// Configuración de middleware
app.use(cors());
app.use(bodyParser.json());

// Configuración de la base de datos
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "barberia1",
});

db.connect((err) => {
  if (err) {
    console.error("Error al conectar a la base de datos:", err);
    return;
  }
  console.log("Conectado a la base de datos MySQL");
});

app.post("/register", async (req, res) => {
  const { email, password, rol, cliente, barbero } = req.body;

  try {
    // Validar que se envíen los datos obligatorios
    if (!email || !password || !rol) {
      return res
        .status(400)
        .json({ message: "Email, contraseña y rol son obligatorios" });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar en la tabla `usuarios`
    const queryUsuario = `
      INSERT INTO usuarios (email, password, rol, estado)
      VALUES (?, ?, ?, 1)
    `;
    db.query(queryUsuario, [email, hashedPassword, rol], (err, userResult) => {
      if (err) {
        console.error("Error al registrar usuario:", err);
        return res.status(500).json({ message: "Error al registrar usuario" });
      }

      const userId = userResult.insertId;

      // Validar y procesar según el rol
      if (rol === "CLIENTE") {
        if (
          !cliente ||
          !cliente.nombre ||
          !cliente.apellido ||
          !cliente.telefono
        ) {
          return res
            .status(400)
            .json({ message: "Datos del cliente incompletos" });
        }

        const queryCliente = `
          INSERT INTO clientes (id_usuario, nombre, apellido, telefono, direccion)
          VALUES (?, ?, ?, ?, ?)
        `;
        const valuesCliente = [
          userId,
          cliente.nombre,
          cliente.apellido,
          cliente.telefono,
          cliente.direccion || null,
        ];
        db.query(queryCliente, valuesCliente, (err) => {
          if (err) {
            console.error("Error al registrar cliente:", err);
            return res
              .status(500)
              .json({ message: "Error al registrar cliente" });
          }
          res.status(201).json({ message: "Cliente registrado exitosamente" });
        });
      } else if (rol === "BARBERO") {
        if (
          !barbero ||
          !barbero.nombre ||
          !barbero.apellido ||
          !barbero.telefono ||
          !barbero.especialidad ||
          !barbero.horario
        ) {
          return res
            .status(400)
            .json({ message: "Datos del barbero incompletos" });
        }

        const queryBarbero = `
          INSERT INTO barberos (id_usuario, nombre, especialidad, horario, estado, apellido, telefono)
          VALUES (?, ?, ?, ?, 1, ?, ?)
        `;
        const valuesBarbero = [
          userId,
          barbero.nombre,
          barbero.especialidad,
          barbero.horario,
          barbero.apellido,
          barbero.telefono,
        ];

        // Ejecución de la consulta para barbero
        db.query(queryBarbero, valuesBarbero, (err) => {
          if (err) {
            console.error("Error al registrar barbero:", err);
            return res
              .status(500)
              .json({ message: "Error al registrar barbero" });
          }
          res.status(201).json({ message: "Barbero registrado exitosamente" });
        });
      } else {
        // Rol inválido
        res.status(400).json({ message: "Rol inválido" });
      }
    });
  } catch (error) {
    console.error("Error interno:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Autenticación de usuarios
// Inicio de sesión
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Validar que los datos no estén vacíos
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "El correo y la contraseña son obligatorios" });
  }

  // Consulta a la base de datos
  const query = "SELECT * FROM usuarios WHERE email = ?";
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error("Error al buscar usuario:", err);
      return res.status(500).json({ message: "Error interno del servidor" });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ message: "Correo o contraseña incorrectos" });
    }

    const user = results[0];

    // Comparar la contraseña encriptada
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: "Correo o contraseña incorrectos" });
    }

    if (user.rol === "CLIENTE") {
      const clienteQuery =
        "SELECT id_cliente FROM clientes WHERE id_usuario = ?";
      db.query(clienteQuery, [user.id_usuario], (err, clienteResults) => {
        if (err) {
          console.error("Error al buscar cliente:", err);
          return res
            .status(500)
            .json({ message: "Error interno del servidor" });
        }

        const id_cliente = clienteResults[0]?.id_cliente || null;

        // Generar token JWT
        const token = jwt.sign(
          { id_usuario: user.id_usuario, rol: user.rol },
          SECRET_KEY,
          { expiresIn: "1h" }
        );

        res.json({
          message: "Inicio de sesión exitoso",
          token,
          user: {
            id: user.id_usuario,
            email: user.email,
            rol: user.rol,
            id_cliente,
          },
        });
      });
    } else if (user.rol === 'BARBERO') {
      // Obtener el id_barbero desde la tabla barberos
      const queryBarbero = 'SELECT id_barbero FROM barberos WHERE id_usuario = ?';
      db.query(queryBarbero, [user.id_usuario], (err, barberoResults) => {
        if (err) {
          console.error('Error al buscar barbero:', err);
          return res.status(500).json({ message: 'Error interno del servidor.' });
        }

        const id_barbero = barberoResults[0]?.id_barbero || null;

        const token = jwt.sign(
          { id_usuario: user.id_usuario, rol: user.rol },
          'your_secret_key',
          { expiresIn: '1h' }
        );

        res.json({
          message: 'Inicio de sesión exitoso',
          token,
          user: {
            id_usuario: user.id_usuario,
            email: user.email,
            rol: user.rol,
            id_barbero, // Se incluye el id_barbero para los barberos
          },
        });
      });
    } else {
      // Si el usuario tiene otro rol (ADMIN, por ejemplo)
      const token = jwt.sign(
        { id_usuario: user.id_usuario, rol: user.rol },
        'your_secret_key',
        { expiresIn: '1h' }
      );

      res.json({
        message: 'Inicio de sesión exitoso',
        token,
        user: {
          id_usuario: user.id_usuario,
          email: user.email,
          rol: user.rol,
        },
      });
    }
  });
});


app.post("/reservas", (req, res) => {
  const { id_cliente, id_servicio, fecha_hora } = req.body;

  // Validar los datos
  if (!id_cliente || !id_servicio || !fecha_hora) {
    return res
      .status(400)
      .json({ message: "Todos los campos son obligatorios" });
  }

  // Verificar que el cliente y el servicio existan
  const queryCliente = `
    SELECT c.id_cliente, u.rol
    FROM clientes c
    JOIN usuarios u ON c.id_usuario = u.id_usuario
    WHERE c.id_cliente = ?
  `;
  db.query(queryCliente, [id_cliente], (err, clienteResults) => {
    if (err) {
      console.error('Error al verificar cliente:', err);
      return res.status(500).json({ message: 'Error interno del servidor.' });
    }

    if (clienteResults.length === 0) {
      return res.status(404).json({ message: 'El cliente no existe.' });
    }
    const cliente = clienteResults[0];
    // Verificar que el rol del usuario sea CLIENTE
    if (cliente.rol !== 'CLIENTE') {
      return res.status(403).json({ message: 'Solo los clientes pueden realizar reservas.' });
    }

    const queryServicio = 'SELECT * FROM servicios WHERE id_servicio = ?';
    db.query(queryServicio, [id_servicio], (err, servicioResults) => {
      if (err) {
        console.error('Error al verificar servicio:', err);
        return res.status(500).json({ message: 'Error interno del servidor.' });
      }

      if (servicioResults.length === 0) {
        return res.status(404).json({ message: 'El servicio no existe.' });
      }

      // Insertar la cita en la tabla `citas`
      const queryReserva = `
        INSERT INTO citas (id_cliente, id_servicio, fecha_hora, estado)
        VALUES (?, ?, ?, 'PENDIENTE')
      `;
      db.query(queryReserva, [id_cliente, id_servicio, fecha_hora], (err, result) => {
        if (err) {
          console.error('Error al registrar la reserva:', err);
          return res.status(500).json({ message: 'Error interno al registrar la reserva.' });
        }

        res.status(201).json({
          message: 'Reserva creada exitosamente.',
          id_cita: result.insertId,
        });
      });
    });
  });
});

app.get("/servicios", (req, res) => {
  const query = "SELECT * FROM servicios";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error al obtener servicios:", err);
      return res.status(500).json({ message: "Error al obtener servicios" });
    }
    res.json(results);
  });
});
app.get('/reservas', (req, res) => {
  const query = `
    SELECT 
      c.id_cita AS numero_reserva,
      TIME(c.fecha_hora) AS hora,
      b.nombre AS barbero,
      s.nombre AS servicio,
      cl.nombre AS cliente,
      c.estado
    FROM citas c
    LEFT JOIN barberos b ON b.id_barbero = c.id_cliente
    LEFT JOIN servicios s ON s.id_servicio = c.id_servicio
    LEFT JOIN clientes cl ON cl.id_cliente = c.id_cliente
    ORDER BY c.fecha_hora;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al listar reservas:', err);
      return res.status(500).json({ message: 'Error interno al listar reservas.' });
    }

    res.json(results);
  });
});

app.put('/reservas/:id', (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  // Validar el nuevo estado
  if (!["COMPLETADA", "CANCELADA"].includes(estado)) {
    return res.status(400).json({ message: "Estado no válido." });
  }

  const query = "UPDATE citas SET estado = ? WHERE id_cita = ?";
  db.query(query, [estado, id], (err, result) => {
    if (err) {
      console.error("Error al actualizar la reserva:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reserva no encontrada." });
    }

    res.json({ message: "Estado de la reserva actualizado." });
  });
});


// Endpoint para obtener todos los productos
app.get('/productos', (req, res) => {
  const query = 'SELECT * FROM productos'; // Cambiar por el nombre exacto de tu tabla en la base de datos
  db.query(query, (err, results) => {
      if (err) {
          console.error("Error al obtener los productos:", err);
          return res.status(500).json({ message: "Error al obtener los productos." });
      }
      res.json(results);
  });
});

app.post('/carrito', (req, res) => {
  const { id_cliente, id_producto, cantidad } = req.body;

  if (!id_cliente || !id_producto) {
      return res.status(400).json({ message: "Faltan datos obligatorios." });
  }

  const query = `
      INSERT INTO carrito (id_cliente, id_producto, cantidad)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE cantidad = cantidad + ?;
  `;

  db.query(query, [id_cliente, id_producto, cantidad || 1, cantidad || 1], (err) => {
      if (err) {
          console.error("Error al agregar producto al carrito:", err);
          return res.status(500).json({ message: "Error interno del servidor." });
      }

      res.status(201).json({ message: "Producto agregado al carrito." });
  });
});


app.get('/carrito/:id_cliente', (req, res) => {
  const { id_cliente } = req.params;

  const query = `
      SELECT c.id_carrito, c.cantidad, p.nombre AS producto, p.precio, (c.cantidad * p.precio) AS total
      FROM carrito c
      JOIN productos p ON c.id_producto = p.id_producto
      WHERE c.id_cliente = ?;
  `;

  db.query(query, [id_cliente], (err, results) => {
      if (err) {
          console.error("Error al obtener productos del carrito:", err);
          return res.status(500).json({ message: "Error interno del servidor." });
      }

      res.json(results);
  });
});


app.delete('/carrito/:id_carrito', (req, res) => {
  const { id_carrito } = req.params;

  const query = "DELETE FROM carrito WHERE id_carrito = ?";

  db.query(query, [id_carrito], (err) => {
      if (err) {
          console.error("Error al eliminar producto del carrito:", err);
          return res.status(500).json({ message: "Error interno del servidor." });
      }

      res.json({ message: "Producto eliminado del carrito." });
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
