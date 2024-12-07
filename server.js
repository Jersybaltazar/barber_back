const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // Cambia esto a algo más seguro en producción.
const PDFDocument = require("pdfkit");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

const { CloudinaryStorage } = require("multer-storage-cloudinary");

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token no válido" });
    }
    req.user = user;
    next();
  });
};
const isAdmin = (req, res, next) => {
  if (req.user?.rol !== "ADMIN") {
    return res
      .status(403)
      .json({ message: "Acceso denegado. Solo para administradores." });
  }
  next();
};

cloudinary.config({
  cloud_name: "dwr7vfh3m",
  api_key: "637537267768459",
  api_secret: "WlJd9NFzth4uul2CDCFBiKCtfLI",
});
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "barberia_productos", // Carpeta donde se guardarán las imágenes
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});

const upload = multer({ storage });
// Configuración de middleware
app.use(cors());
app.use(bodyParser.json());

// Configuración de la base de datos
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "barberia",
});

db.connect((err) => {
  if (err) {
    console.error("Error al conectar a la base de datos:", err);
    return;
  }
  console.log("Conectado a la base de datos MySQL");
});

app.post("/register", async (req, res) => {
  const { email, password, cliente } = req.body;

  try {
    // Validar que se envíen los datos obligatorios
    if (
      !email ||
      !password ||
      !cliente ||
      !cliente.nombre ||
      !cliente.apellido ||
      !cliente.telefono
    ) {
      return res.status(400).json({ message: "Datos obligatorios faltantes." });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar en la tabla `usuarios` con rol CLIENTE
    const queryUsuario = `
      INSERT INTO usuarios (email, password, rol, estado)
      VALUES (?, ?, 'CLIENTE', 1)
    `;
    db.query(queryUsuario, [email, hashedPassword], (err, userResult) => {
      if (err) {
        console.error("Error al registrar usuario:", err);
        return res.status(500).json({ message: "Error al registrar usuario." });
      }

      const userId = userResult.insertId;

      // Insertar datos adicionales en la tabla `clientes`
      const queryCliente = `
        INSERT INTO clientes (id_usuario, nombre, apellido, telefono, direccion)
        VALUES (?, ?, ?, ?, ?)
      `;
      const valuesCliente = [
        userId,
        cliente.nombre,
        cliente.apellido,
        cliente.telefono,
        cliente.direccion || null, // Dirección es opcional
      ];
      db.query(queryCliente, valuesCliente, (err) => {
        if (err) {
          console.error("Error al registrar cliente:", err);
          return res
            .status(500)
            .json({ message: "Error al registrar cliente." });
        }

        res.status(201).json({ message: "Cliente registrado exitosamente." });
      });
    });
  } catch (error) {
    console.error("Error interno:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Validar que los datos no estén vacíos
  if (!email || !password) {
    return res
      .status(400)
      .json({ message: "El correo y la contraseña son obligatorios." });
  }

  // Consulta a la base de datos
  const query = "SELECT * FROM usuarios WHERE email = ?";
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error("Error al buscar usuario:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ message: "Correo o contraseña incorrectos." });
    }

    const user = results[0];

    // Comparar la contraseña encriptada
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: "Correo o contraseña incorrectos." });
    }

    // Generar token JWT
    const token = jwt.sign(
      { id_usuario: user.id_usuario, rol: user.rol },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    // Respuesta según el rol del usuario
    if (user.rol === "CLIENTE") {
      const clienteQuery =
        "SELECT id_cliente FROM clientes WHERE id_usuario = ?";
      db.query(clienteQuery, [user.id_usuario], (err, clienteResults) => {
        if (err) {
          console.error("Error al buscar cliente:", err);
          return res
            .status(500)
            .json({ message: "Error interno del servidor." });
        }

        const id_cliente = clienteResults[0]?.id_cliente || null;

        res.json({
          message: "Inicio de sesión exitoso.",
          token,
          user: {
            id_usuario: user.id_usuario,
            email: user.email,
            rol: user.rol,
            id_cliente,
          },
        });
      });
    } else if (user.rol === "ADMIN") {
      res.json({
        message: "Inicio de sesión exitoso.",
        token,
        user: {
          id_usuario: user.id_usuario,
          email: user.email,
          rol: user.rol,
        },
      });
    } else {
      res.status(403).json({ message: "Rol no autorizado." });
    }
  });
});

app.get("/auth/user", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id_usuario;

    // Consulta para obtener el usuario
    const userQuery = `SELECT * FROM usuarios WHERE id_usuario = ?`;
    const [userResult] = await db.promise().query(userQuery, [userId]);

    if (userResult.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userResult[0];

    // Si el rol es CLIENTE, buscar los datos adicionales en la tabla clientes
    if (user.rol === "CLIENTE") {
      const clientQuery = `SELECT * FROM clientes WHERE id_usuario = ?`;
      const [clientResult] = await db.promise().query(clientQuery, [userId]);

      if (clientResult.length === 0) {
        return res
          .status(404)
          .json({ message: "Datos del cliente no encontrados" });
      }

      const cliente = clientResult[0];

      // Combinar los datos del usuario y del cliente
      return res.json({
        message: "Usuario encontrado",
        user: { ...user, cliente },
      });
    }

    // Si el rol es ADMIN o cualquier otro, devolver solo los datos del usuario
    return res.json({
      message: "Usuario encontrado",
      user,
    });
  } catch (error) {
    console.error("Error al obtener el usuario:", error);
    res.status(500).json({ message: "Error del servidor" });
  }
});

app.get("/barberos", (req, res) => {
  const query = `
      SELECT 
          id_barbero, 
          nombre, 
          apellido, 
          telefono, 
          id_servicio, 
          horario, 
          imagen
      FROM barberos
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error al obtener los barberos:", err);
      return res
        .status(500)
        .json({ message: "Error al obtener los barberos." });
    }
    res.status(200).json(results);
  });
});

app.delete("/barberos/:id", (req, res) => {
  const { id } = req.params;

  const query = `DELETE FROM barberos WHERE id_barbero = ?`;
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Error al eliminar el barbero:", err);
      return res.status(500).json({ message: "Error al eliminar el barbero." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Barbero no encontrado." });
    }

    res.status(200).json({ message: "Barbero eliminado exitosamente." });
  });
});

app.post("/barberos", upload.single("imagen"), (req, res) => {
  const { nombre, apellido, telefono, horario, id_servicio } = req.body;
  const imagen = req.file ? req.file.path : null;
  if (req.file) {
    console.log("Ruta de la imagen cargada:", req.file.path);
  } else {
    console.error("No se recibió la imagen.");
  }

  // Obtén el nombre del servicio desde la base de datos
  const query =
    "INSERT INTO barberos (nombre, apellido, telefono, id_servicio, horario, imagen) VALUES (?, ?, ?, ?, ?, ?)";
  db.query(
    query,
    [nombre, apellido, telefono, id_servicio, horario, imagen],
    (err, result) => {
      if (err) {
        console.error("Error al insertar el barbero:", err);
        return res.status(500).json({ error: "Error al crear el barbero." });
      }
      res
        .status(201)
        .json({
          message: "Barbero creado exitosamente.",
          id_barbero: result.insertId,
        });
    }
  );
});

app.put("/barberos/:id", upload.single("imagen"), (req, res) => {
  const { id } = req.params;
  const { nombre, apellido, telefono, id_servicio, horario } = req.body;
  let query = `
      UPDATE barberos 
      SET nombre = ?, apellido = ?, telefono = ?, id_servicio = ?, horario = ?
  `;
  const values = [nombre, apellido, telefono, id_servicio, horario];

  // Si se sube una imagen, actualízala también
  if (req.file) {
    const imagenUrl = `https://res.cloudinary.com/<tu-cloud-name>/image/upload/${req.file.filename}`; // Sustituye con tu configuración
    query += `, imagen = ?`;
    values.push(imagenUrl);
  }

  query += ` WHERE id_barbero = ?`;
  values.push(id);

  db.query(query, values, (err, results) => {
    if (err) {
      console.error("Error al actualizar el barbero:", err);
      return res
        .status(500)
        .json({ message: "Error al actualizar el barbero." });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "Barbero no encontrado." });
    }

    res.status(200).json({ message: "Barbero actualizado exitosamente." });
  });
});

app.get("/barbers/:id", (req, res) => {
  const { id } = req.params;

  const queryBarber = `
    SELECT * FROM barberos WHERE id_barbero = ?
  `;

  const queryServices = `
    SELECT * FROM servicios WHERE id_barbero = ?
  `;

  db.query(queryBarber, [id], (err, barberResults) => {
    if (err || barberResults.length === 0) {
      return res.status(404).json({ message: "Barbero no encontrado" });
    }

    const barber = barberResults[0];

    db.query(queryServices, [id], (err, servicesResults) => {
      if (err) {
        return res.status(500).json({ message: "Error al obtener servicios" });
      }

      barber.services = servicesResults;
      res.json(barber);
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

app.post("/services", upload.single("imagen"), (req, res) => {
  const { nombre, precio } = req.body;
  const imagen = req.file ? req.file.path : null;
  if (!nombre || !precio) {
    return res
      .status(400)
      .json({ message: "El nombre y el precio son obligatorios." });
  }

  const query = `
    INSERT INTO servicios (nombre, precio, imagen)
    VALUES (?, ?, ?)
  `;
  db.query(query, [nombre, precio, imagen], (err, result) => {
    if (err) {
      console.error("Error al crear servicio:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }
    res
      .status(201)
      .json({
        message: "Servicio creado exitosamente.",
        id_servicio: result.insertId,
      });
  });
});

app.delete("/servicios/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM servicios WHERE id_servicio = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Error al eliminar el servicio:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Servicio no encontrado." });
    }

    res.json({ message: "Servicio eliminado exitosamente." });
  });
});

app.put("/servicios/:id", upload.single("imagen"), (req, res) => {
  const { id } = req.params;
  const { nombre, precio } = req.body;
  const imagen = req.file ? req.file.path : null;

  if (!nombre || !precio) {
    return res
      .status(400)
      .json({ message: "El nombre y el precio son obligatorios." });
  }

  let query = `
    UPDATE servicios
    SET nombre = ?, precio = ?
  `;
  const queryParams = [nombre, precio];

  if (imagen) {
    query += `, imagen = ?`;
    queryParams.push(imagen);
  }

  query += ` WHERE id_servicio = ?`;
  queryParams.push(id);

  db.query(query, queryParams, (err, result) => {
    if (err) {
      console.error("Error al actualizar el servicio:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Servicio no encontrado." });
    }

    res.json({ message: "Servicio actualizado exitosamente." });
  });
});

app.post("/productos", upload.single("imagen"), async (req, res) => {
  const { nombre, descripcion, precio, stock } = req.body;
  let imagenUrl = null;
  // Validación de campos obligatorios
  if (!nombre || !descripcion || !precio || !stock) {
    return res
      .status(400)
      .json({ message: "Todos los campos son obligatorios." });
  }
  if (req.file) {
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "productos",
      });
      imagenUrl = result.secure_url; // URL de la imagen subida
    } catch (error) {
      console.error("Error al subir imagen a Cloudinary:", error);
      return res.status(500).json({ message: "Error al subir imagen" });
    }
  }
  const query = `
INSERT INTO productos (nombre, descripcion, precio, stock, imagen)
VALUES (?, ?, ?, ?, ?)
`;
  db.query(
    query,
    [nombre, descripcion, precio, stock, imagenUrl],
    (err, result) => {
      if (err) {
        console.error("Error al crear el producto:", err);
        return res.status(500).json({ message: "Error interno del servidor" });
      }

      // Asegurar que 'result' tiene el ID del producto insertado
      if (result && result.insertId) {
        res.status(201).json({
          message: "Producto creado exitosamente.",
          id_producto: result.insertId,
        });
      } else {
        res
          .status(500)
          .json({ message: "Error al obtener el ID del producto creado." });
      }
    }
  );
});

app.get("/productos", async (req, res) => {
  try {
    const query = `SELECT * FROM productos`;
    db.query(query, (err, results) => {
      if (err) {
        console.error("Error al obtener productos:", err);
        return res.status(500).json({ message: "Error al obtener productos." });
      }

      res.status(200).json(results);
    });
  } catch (error) {
    console.error("Error interno del servidor:", error);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.delete("/productos/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM productos WHERE id_producto = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Error al eliminar el producto:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Producto no encontrado." });
    }

    res.json({ message: "Producto eliminado exitosamente." });
  });
});

app.put("/productos/:id", upload.single("imagen"), (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, precio, stock } = req.body;
  const imagen = req.file ? req.file.path : null;

  if (!nombre || !descripcion || !precio || !stock) {
    return res
      .status(400)
      .json({ message: "Todos los campos son obligatorios." });
  }

  let query = `
    UPDATE productos
    SET nombre = ?, descripcion = ?, precio = ?, stock = ?
  `;
  const queryParams = [nombre, descripcion, precio, stock];

  if (imagen) {
    query += `, imagen = ?`;
    queryParams.push(imagen);
  }

  query += ` WHERE id_producto = ?`;
  queryParams.push(id);

  db.query(query, queryParams, (err, result) => {
    if (err) {
      console.error("Error al actualizar el producto:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Producto no encontrado." });
    }

    res.json({ message: "Producto actualizado exitosamente." });
  });
});

app.post("/reservas", async (req, res) => {
  const { id_cliente, id_barbero, fecha_hora, estado } = req.body;

  // Validación de campos obligatorios
  if (!id_cliente || !id_barbero || !fecha_hora) {
    return res
      .status(400)
      .json({
        message: "id_cliente, id_barbero y fecha_hora son obligatorios.",
      });
  }

  // Verificamos el estado, si no se envía, lo dejamos como "PENDIENTE"
  const estadoReserva = estado || "PENDIENTE";

  const query = `
      INSERT INTO reservas (id_cliente, id_barbero, fecha_hora, estado)
      VALUES (?, ?, ?, ?)
  `;

  db.query(
    query,
    [id_cliente, id_barbero, fecha_hora, estadoReserva],
    (err, result) => {
      if (err) {
        console.error("Error al crear la reserva:", err);
        return res.status(500).json({ message: "Error interno del servidor" });
      }

      if (result && result.insertId) {
        res.status(201).json({
          message: "Reserva creada exitosamente.",
          id_reserva: result.insertId,
        });
      } else {
        res
          .status(500)
          .json({ message: "Error al obtener el ID de la reserva creada." });
      }
    }
  );
});

app.get("/reservas", (req, res) => {
  const query = `
      SELECT 
          r.id_reserva AS numero_reserva,
          DATE_FORMAT(r.fecha_hora, '%H:%i') AS hora_reserva,
          CONCAT(b.nombre, ' ', b.apellido) AS barbero,
          s.nombre AS servicio,
          CONCAT(c.nombre, ' ', c.apellido) AS cliente,
          r.estado
      FROM reservas r
      JOIN barberos b ON r.id_barbero = b.id_barbero
      JOIN clientes c ON r.id_cliente = c.id_cliente
      JOIN servicios s ON b.id_servicio = s.id_servicio;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error al obtener reservas:", err);
      return res.status(500).json({ message: "Error al obtener reservas." });
    }

    res.status(200).json(results);
  });
});

app.delete("/reservas/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM reservas WHERE id_reserva = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Error al eliminar la reserva:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reserva no encontrada." });
    }

    res.json({ message: "Reserva eliminada exitosamente." });
  });
});

app.put("/reservas/:id", (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  // Verificar que estado sea uno de los permitidos
  const estadosPermitidos = ["PENDIENTE", "ACEPTADO", "CANCELADO"];
  if (!estadosPermitidos.includes(estado)) {
    return res.status(400).json({ message: "Estado no válido." });
  }

  const query = `
    UPDATE reservas
    SET estado = ?
    WHERE id_reserva = ?
  `;

  db.query(query, [estado, id], (err, result) => {
    if (err) {
      console.error("Error al actualizar la reserva:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reserva no encontrada." });
    }

    res.json({ message: `Reserva ${id} actualizada a estado ${estado}.` });
  });
});


app.post("/ordenes", authenticateToken, (req, res) => {
  const { productos } = req.body;

  if (!Array.isArray(productos) || productos.length === 0) {
    return res.status(400).json({ message: "Se requieren productos para crear la orden." });
  }

  const id_usuario = req.user.id_usuario; // Obtenido del token

  // Obtener el id_cliente desde la tabla clientes
  const queryCliente = `SELECT id_cliente FROM clientes WHERE id_usuario = ?`;
  db.query(queryCliente, [id_usuario], (err, clienteResults) => {
    if (err) {
      console.error("Error al obtener id_cliente:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (clienteResults.length === 0) {
      return res.status(404).json({ message: "No se encontró id_cliente para este usuario." });
    }

    const id_cliente = clienteResults[0].id_cliente;

    // Insertar los productos en la tabla carrito
    const queryInsert = `INSERT INTO carrito (id_cliente, id_producto, cantidad) VALUES (?, ?, ?)`;

    let contador = 0;
    let errorOcurrido = false;

    productos.forEach((prod) => {
      db.query(queryInsert, [id_cliente, prod.id_producto, prod.quantity], (err, result) => {
        if (err) {
          console.error("Error al insertar producto en carrito:", err);
          errorOcurrido = true;
          return res.status(500).json({ message: "Error interno del servidor." });
        }

        contador++;
        if (contador === productos.length && !errorOcurrido) {
          // Todos los productos insertados correctamente
          // Ahora necesitamos obtener el nombre y precio de cada producto para el PDF.
          
          const ids = productos.map(p => p.id_producto);
          const queryProductos = `SELECT id_producto, nombre, precio FROM productos WHERE id_producto IN (${ids.join(',')})`;
          db.query(queryProductos, (err, prodResults) => {
            if (err) {
              console.error("Error al obtener detalles de productos:", err);
              return res.status(500).json({ message: "Error interno al obtener productos." });
            }

            // Ahora combinamos la información de cantidad con nombre y precio
            const productosConDatos = productos.map(prod => {
              const infoProd = prodResults.find(p => p.id_producto === prod.id_producto);
              return {
                id_producto: prod.id_producto,
                quantity: prod.quantity,
                nombre: infoProd ? infoProd.nombre : "Desconocido",
                precio: infoProd ? infoProd.precio : 0
              };
            });

            // Generamos el PDF
            generarPDF(productosConDatos, id_cliente, (pdfBase64) => {
              res.status(201).json({
                message: "Orden creada exitosamente.",
                comprobante: pdfBase64,
              });
            });
          });
        }
      });
    });
  });
});

function generarPDF(productos, id_cliente, callback) {
  const doc = new PDFDocument();
  let buffers = [];

  doc.on('data', buffers.push.bind(buffers));
  doc.on('end', () => {
    let pdfData = Buffer.concat(buffers);
    // Convertir a base64
    let base64 = pdfData.toString('base64');
    callback(base64);
  });

  doc.fontSize(18).text("Comprobante de Compra", { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`ID Cliente: ${id_cliente}`);
  doc.moveDown();
  doc.text("Productos adquiridos:");
  doc.moveDown();

  let total = 0;
  productos.forEach((prod) => {
    let subtotal = prod.precio * prod.quantity;
    total += subtotal;
    doc.text(`${prod.nombre} (x${prod.quantity}) - ${subtotal} USD`);
  });

  doc.moveDown();
  doc.text(`Total: ${total} USD`, { align: 'right' });

  doc.end();
}

app.get("/ordenes", authenticateToken, (req, res) => {
  const { id_usuario, rol } = req.user;

  // Obtener el id_cliente del usuario para filtrar si es CLIENTE
  const queryCliente = `SELECT id_cliente FROM clientes WHERE id_usuario = ?`;
  db.query(queryCliente, [id_usuario], (err, clienteResults) => {
    if (err) {
      console.error("Error al obtener id_cliente:", err);
      return res.status(500).json({ message: "Error interno del servidor." });
    }

    if (clienteResults.length === 0) {
      return res.status(404).json({ message: "No se encontró id_cliente para este usuario." });
    }

    const id_cliente = clienteResults[0].id_cliente;

    let query = `
      SELECT 
        c.id_carrito, 
        c.id_cliente, 
        p.id_producto, 
        p.nombre AS producto_nombre, 
        p.precio, 
        c.cantidad
      FROM carrito c
      JOIN productos p ON c.id_producto = p.id_producto
    `;

    const params = [];
    if (rol === 'CLIENTE') {
      // Si el rol es CLIENTE, filtrar por su id_cliente
      query += ` WHERE c.id_cliente = ?`;
      params.push(id_cliente);
    }
    // Si es ADMIN, no filtramos y devolvemos todas las "órdenes" (líneas de carrito)

    db.query(query, params, (err, results) => {
      if (err) {
        console.error("Error al obtener las órdenes:", err);
        return res.status(500).json({ message: "Error interno del servidor." });
      }

      // Opcional: Agrupar los resultados por id_cliente
      // para representar cada grupo de productos como una "orden".
      const ordenesMap = {};

      results.forEach(row => {
        const key = row.id_cliente;
        if (!ordenesMap[key]) {
          ordenesMap[key] = {
            id_cliente: row.id_cliente,
            productos: []
          };
        }
        ordenesMap[key].productos.push({
          id_carrito: row.id_carrito,
          id_producto: row.id_producto,
          nombre: row.producto_nombre,
          precio: row.precio,
          cantidad: row.cantidad
        });
      });

      const ordenes = Object.values(ordenesMap);
      res.json(ordenes);
    });
  });
});

// Endpoint para obtener todos los productos

app.post("/carrito", (req, res) => {
  const { id_cliente, id_producto, cantidad } = req.body;

  if (!id_cliente || !id_producto) {
    return res.status(400).json({ message: "Faltan datos obligatorios." });
  }

  const query = `
      INSERT INTO carrito (id_cliente, id_producto, cantidad)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE cantidad = cantidad + ?;
  `;

  db.query(
    query,
    [id_cliente, id_producto, cantidad || 1, cantidad || 1],
    (err) => {
      if (err) {
        console.error("Error al agregar producto al carrito:", err);
        return res.status(500).json({ message: "Error interno del servidor." });
      }

      res.status(201).json({ message: "Producto agregado al carrito." });
    }
  );
});

app.get("/carrito/:id_cliente", (req, res) => {
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

app.delete("/carrito/:id_carrito", (req, res) => {
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

// Endpoint para obtener servicios de un barbero
app.get("/services/:id_barbero", (req, res) => {
  const { id_barbero } = req.params;
  const query = "SELECT * FROM servicios WHERE id_barbero = ?";
  db.query(query, [id_barbero], (err, results) => {
    if (err) {
      console.error("Error al obtener servicios:", err);
      return res.status(500).json({ message: "Error al obtener servicios" });
    }
    res.json(results);
  });
});
// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
