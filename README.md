# API para Gestión de Inventarios y Empleados

Esta API, desarrollada en Flask, permite gestionar un sistema de inventarios y empleados para un sitio web y una aplicación móvil. Proporciona funcionalidades para registrar, actualizar, consultar y eliminar datos relacionados con usuarios, productos, ventas, compras, registros y boletas. Además, incluye características como autenticación JWT (la cual no está completamente implementada), WebSockets para comunicación en tiempo real, y un programador de tareas para manejar operaciones automatizadas.

---

## Requisitos
- **Python 3.8 o superior**
- Flask y extensiones:
  - `Flask-JWT-Extended`
  - `Flask-CORS`
  - `Flask-SocketIO`
  - `apscheduler`
- Base de datos compatible con MySQL/MariaDB.
- Configuración de variables de entorno:
  - `SECRET_KEY`: Clave secreta para la autenticación JWT.
  - Credenciales de la base de datos mediante `dotenv`.

---

## Configuración
1. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```
2. Configurar la base de datos en el archivo `.env`:
   ```env
   DB_HOST=<host_de_base_de_datos>
   DB_USER=<usuario>
   DB_PASSWORD=<contraseña>
   DB_NAME=<nombre_de_base_de_datos>
   SECRET_KEY=<clave_secreta>
   ```
3. Inicializar la base de datos con las tablas necesarias.

---

## Estructura de Funcionalidades

### 1. **Usuarios**
- Registro, inicio de sesión y gestión de usuarios.
- Tipos de usuario (`Administrador`, `Cajero`, `Cliente`).
- Manejo de estados (`Activo`, `Inactivo`).

### 2. **Productos**
- Gestión de inventarios.
- Actualización de precios, descuentos y stock.
- Registro y consulta por código de barras.

### 3. **Ventas y Compras**
- Registro y consulta de ventas con detalles.
- Gestión de boletas y compras con sus productos asociados.

### 4. **Registros y Monitoreo**
- Registro histórico de actividades.
- Consultas de logs para auditoría.

### 5. **WebSockets**
- Comunicación en tiempo real para eventos como escaneo de códigos de barras.

### 6. **Tareas Automatizadas**
- Eliminación de descuentos vencidos mediante un programador de tareas.

---

## Principales Endpoints

### Usuarios
- **Registro:** `POST /register`
- **Inicio de Sesión:** `POST /login`
- **Consulta de Usuarios:** `GET /users`
- **Actualizar Usuario:** `PUT /users/<rut>`
- **Desactivar Usuario:** `DELETE /users/<rut>`

### Productos
- **Agregar Producto:** `POST /product`
- **Consulta por Código de Barras:** `GET /product/barcode/<codigo_barras>`
- **Actualizar Producto:** `PUT /product/barcode/<codigo_barras>`

### Ventas
- **Registrar Venta con Detalles:** `POST /ventas-detalle`
- **Consulta de Ventas:** `GET /ventas`

### Compras
- **Registrar Compra con Detalles:** `POST /compras-detalle`
- **Consulta de Compras:** `GET /compras`

### Boletas
- **Consulta Boleta por Venta:** `GET /boleta/<id_venta>`
- **Consulta General de Boletas:** `GET /boletas`

### Registros
- **Consultar Historial:** `GET /registros`
- **Agregar Registro:** `POST /registros`

---

## WebSockets
La API utiliza `Flask-SocketIO` para habilitar comunicación en tiempo real. Eventos clave incluyen:
- **Conexión/Desconexión de Clientes.**
- **Escaneo de Código de Barras:** Responde a solicitudes de escaneo en vivo.
- **Notificaciones Personalizadas:** Envío de actualizaciones a usuarios específicos.

---

## Tareas Automatizadas
Se utiliza `APScheduler` para manejar procesos periódicos como la eliminación de descuentos vencidos. Esta tarea se ejecuta cada 24 horas.

---

## Ejecución
1. Ejecutar el servidor Flask:
   ```bash
   python app.py
   ```
2. Acceder a la API desde `http://localhost:5000`.
3. Para habilitar WebSockets, utilizar un cliente compatible con Socket.IO.

---