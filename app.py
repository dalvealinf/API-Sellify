from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from config import get_db_connection
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, origins="*")
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY')  # Clave estática para JWT
jwt = JWTManager(app)

# Función utilizada para la verificación de RUT
def validar_rut(rut):
    if len(rut) < 8 or not rut[:-1].isdigit() or not rut[-1].isalnum():
        return False

    cuerpo_rut = rut[:-1]
    dv = rut[-1].upper()

    suma = 0
    multiplicador = 2

    for c in reversed(cuerpo_rut):
        suma += int(c) * multiplicador
        multiplicador += 1
        if multiplicador == 8:
            multiplicador = 2

    digito_verificador_calculado = 11 - (suma % 11)
    if digito_verificador_calculado == 11:
        digito_verificador_calculado = "0"
    elif digito_verificador_calculado == 10:
        digito_verificador_calculado = "K"
    else:
        digito_verificador_calculado = str(digito_verificador_calculado)

    return dv == digito_verificador_calculado

#########################################################
#        Sección Administradores y Cajeros              #
#########################################################
# Ruta para el registro de usuarios
@app.route('/register', methods=['POST'])
def register():
    rut = request.json.get('rut')
    nombre = request.json.get('nombre')
    apellido = request.json.get('apellido')
    correo = request.json.get('correo')
    contrasena = request.json.get('contrasena')
    telefono = request.json.get('telefono')
    tipo_usuario = request.json.get('tipo_usuario')
    estado = request.json.get('estado')

    # Validar que los campos obligatorios estén presentes
    if not all([rut, nombre, apellido, correo, contrasena, telefono, tipo_usuario, estado]):
        return jsonify({"msg": "Faltan datos"}), 400
    
    # Validar el formato del RUT
    if not validar_rut(rut):
        return jsonify({"msg": "RUT inválido"}), 400

    password_hash = generate_password_hash(contrasena)
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Verificar si el tipo de usuario existe en la tabla TIPOUSUARIO
            cursor.execute('SELECT id_tipo_usuario FROM TIPOUSUARIO WHERE tipo = %s', (tipo_usuario,))
            tipo_usuario_id = cursor.fetchone()

            if not tipo_usuario_id:
                return jsonify({"msg": "Tipo de usuario no válido"}), 400

            # Verificar si el estado es válido en la tabla ESTADO
            cursor.execute('SELECT id_estado FROM ESTADO WHERE estado = %s', (estado,))
            estado_id = cursor.fetchone()

            if not estado_id:
                return jsonify({"msg": "Estado no válido"}), 400

            # Insertar el nuevo usuario
            cursor.execute('''
                INSERT INTO USUARIOS (rut, nombre, apellido, correo, contrasena, telefono, id_tipo_usuario, id_estado)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (rut, nombre, apellido, correo, password_hash, telefono, tipo_usuario_id['id_tipo_usuario'], estado_id['id_estado']))

            connection.commit()
        return jsonify({"msg": "Usuario registrado exitosamente"}), 201
    except Exception as e:
        return jsonify({"msg": "El usuario ya existe o ocurrió un error", "error": str(e)}), 400
    finally:
        connection.close()

# Ruta para el login
@app.route('/login', methods=['POST'])
def login():
    rut = request.json.get('rut')
    contrasena = request.json.get('contrasena')

    if not rut or not contrasena:
        return jsonify({"msg": "RUT y contraseÃ±a son obligatorios"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM USUARIOS WHERE rut = %s', (rut,))
            user = cursor.fetchone()

        if user and check_password_hash(user['contrasena'], contrasena):
            # Crear token de autenticaciÃ³n con el RUT como identidad
            access_token = create_access_token(identity={'rut': rut, 'nombre': user['nombre']})
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"msg": "RUT o contraseÃ±a incorrectos"}), 401
    finally:
        connection.close()

# Ruta para obtener todos los usuarios registrados según el parámetro dado
@app.route('/users', methods=['GET'])
def get_users():
    tipo_usuario = request.args.get('tipo_usuario')  # Obtener el parámetro tipo_usuario
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL con o sin filtro de tipo_usuario
            if tipo_usuario:
                cursor.execute('''
                    SELECT 
                        u.id_usuario, 
                        u.rut, 
                        u.nombre, 
                        u.apellido, 
                        u.correo, 
                        u.telefono, 
                        u.fecha_creacion,
                        (SELECT tipo FROM TIPOUSUARIO WHERE id_tipo_usuario = u.id_tipo_usuario) AS tipo_usuario,
                        (SELECT estado FROM ESTADO WHERE id_estado = u.id_estado) AS estado,
                        IFNULL(p.puntos, 0) AS puntos
                    FROM USUARIOS u
                    LEFT JOIN PUNTOS p ON u.id_usuario = p.id_cliente
                    WHERE (SELECT tipo FROM TIPOUSUARIO WHERE id_tipo_usuario = u.id_tipo_usuario) = %s
                ''', (tipo_usuario,))
            else:
                # Si no se proporciona tipo_usuario, devolver todos los usuarios
                cursor.execute('''
                    SELECT 
                        u.id_usuario, 
                        u.rut, 
                        u.nombre, 
                        u.apellido, 
                        u.correo, 
                        u.telefono, 
                        u.fecha_creacion,
                        (SELECT tipo FROM TIPOUSUARIO WHERE id_tipo_usuario = u.id_tipo_usuario) AS tipo_usuario,
                        (SELECT estado FROM ESTADO WHERE id_estado = u.id_estado) AS estado,
                        IFNULL(p.puntos, 0) AS puntos
                    FROM USUARIOS u
                    LEFT JOIN PUNTOS p ON u.id_usuario = p.id_cliente
                ''')

            users = cursor.fetchall()
        
        return jsonify(users), 200
    finally:
        connection.close()

# Ruta para obtener los datos de un usuario dado su rut
@app.route('/users/<string:rut>', methods=['GET'])
def get_user_by_rut(rut):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL para obtener el usuario
            cursor.execute('''
                SELECT 
                    u.id_usuario,
                    u.rut,
                    u.nombre,
                    u.apellido,
                    u.correo,
                    u.telefono,
                    u.fecha_creacion,
                    (SELECT estado FROM ESTADO WHERE id_estado = u.id_estado) AS estado,
                    (SELECT tipo FROM TIPOUSUARIO WHERE id_tipo_usuario = u.id_tipo_usuario) AS tipo_usuario,
                    IFNULL(p.puntos, 0) AS puntos
                FROM USUARIOS u
                LEFT JOIN PUNTOS p ON u.id_usuario = p.id_cliente
                WHERE u.rut = %s
            ''', (rut,))
            
            user = cursor.fetchone()

        if user:
            return jsonify(user), 200
        else:
            return jsonify({"msg": "Usuario no encontrado"}), 404
    finally:
        connection.close()

# Ruta para cambiar el estado de un usuario a inactivo utilizando su RUT
@app.route('/users/<string:rut>', methods=['DELETE'])
def deactivate_user(rut):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Obtener el id del estado 'inactivo' desde la tabla ESTADO
            cursor.execute('SELECT id_estado FROM ESTADO WHERE estado = %s', ('inactivo',))
            estado_inactivo = cursor.fetchone()

            if not estado_inactivo:
                return jsonify({"msg": "Estado inactivo no encontrado"}), 400

            # Actualizar el estado del usuario a inactivo
            cursor.execute('UPDATE USUARIOS SET id_estado = %s WHERE rut = %s', (estado_inactivo['id_estado'], rut))
            connection.commit()

            if cursor.rowcount == 0:
                return jsonify({'message': 'Usuario no encontrado'}), 404

        return jsonify({'message': 'Usuario desactivado exitosamente'}), 200
    finally:
        connection.close()

# Ruta para actualizar un usuario utilizando su RUT
@app.route('/users/<string:rut>', methods=['PUT'])
def update_user(rut):
    new_data = request.json
    nombre = new_data.get('nombre')
    apellido = new_data.get('apellido')
    correo = new_data.get('correo')
    telefono = new_data.get('telefono')
    contrasena = new_data.get('contrasena')
    tipo_usuario = new_data.get('tipo_usuario')
    estado = new_data.get('estado')
    
    # Validar que se han proporcionado algunos datos para actualizar
    if not any([nombre, apellido, correo, telefono, contrasena, tipo_usuario, estado]):
        return jsonify({"msg": "No se proporcionaron datos para actualizar"}), 400

    # Construir la consulta de actualización en base a los datos dados (no es necesario rellenarlos todos)
    updates = []
    params = []

    if nombre:
        updates.append("nombre = %s")
        params.append(nombre)
    if apellido:
        updates.append("apellido = %s")
        params.append(apellido)
    if correo:
        updates.append("correo = %s")
        params.append(correo)
    if telefono:
        updates.append("telefono = %s")
        params.append(telefono)
    if contrasena:
        hashed_password = generate_password_hash(contrasena)
        updates.append("contrasena = %s")
        params.append(hashed_password)
    
    # Si se proporciona el tipo de usuario, validar si existe en la tabla TIPOUSUARIO
    if tipo_usuario:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT id_tipo_usuario FROM TIPOUSUARIO WHERE tipo = %s', (tipo_usuario,))
                tipo_usuario_id = cursor.fetchone()
                
                if not tipo_usuario_id:
                    return jsonify({"msg": "Tipo de usuario no válido"}), 400
                
                # Si el tipo de usuario es válido, se añade a la lista de campos a actualizar
                updates.append("id_tipo_usuario = %s")
                params.append(tipo_usuario_id['id_tipo_usuario'])
        finally:
            connection.close()

    # Si se proporciona el estado, validar si existe en la tabla ESTADO
    if estado:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT id_estado FROM ESTADO WHERE estado = %s', (estado,))
                estado_id = cursor.fetchone()
                
                if not estado_id:
                    return jsonify({"msg": "Estado no válido"}), 400
                
                # Si el estado es válido, se añade a la lista de campos a actualizar
                updates.append("id_estado = %s")
                params.append(estado_id['id_estado'])
        finally:
            connection.close()

    if not updates:
        return jsonify({"msg": "No hay datos para actualizar"}), 400

    query = f"UPDATE USUARIOS SET {', '.join(updates)} WHERE rut = %s"
    
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, (*params, rut))
            connection.commit()

        if cursor.rowcount > 0:
            return jsonify({"msg": "Usuario actualizado exitosamente"}), 200
        else:
            return jsonify({"msg": "Usuario no encontrado"}), 404
    finally:
        connection.close()

# Ruta para obtener todos los tipos de usuario
@app.route('/tiposusuario', methods=['GET'])
def get_all_user_types():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL para obtener todos los tipos de usuario
            cursor.execute('SELECT id_tipo_usuario, tipo FROM TIPOUSUARIO')
            user_types = cursor.fetchall()
        
        # Retornar los tipos de usuario en formato JSON
        return jsonify(user_types), 200
    finally:
        connection.close()

# Ruta para modificar o agregar puntos de un usuario si tiene id_tipo_usuario = 3
@app.route('/users/<string:rut>/puntos', methods=['PUT'])
def update_user_points(rut):
    new_points = request.json.get('puntos')

    if new_points is None:
        return jsonify({"msg": "Faltan los puntos para actualizar"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Verificar si el usuario con el RUT existe y tiene id_tipo_usuario = 3
            cursor.execute('SELECT id_usuario, id_tipo_usuario FROM USUARIOS WHERE rut = %s', (rut,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"msg": "Usuario no encontrado"}), 404

            if user['id_tipo_usuario'] != 3:
                return jsonify({"msg": "Solo se pueden modificar los puntos de clientes"}), 403

            id_usuario = user['id_usuario']

            # Verificar si el usuario ya tiene puntos registrados
            cursor.execute('SELECT * FROM PUNTOS WHERE id_cliente = %s', (id_usuario,))
            points_record = cursor.fetchone()

            if points_record:
                # Si ya tiene puntos registrados, actualizarlos
                cursor.execute('UPDATE PUNTOS SET puntos = %s WHERE id_cliente = %s', (new_points, id_usuario))
                message = "Puntos actualizados exitosamente"
            else:
                # Si no tiene puntos registrados, crear un nuevo registro
                cursor.execute('INSERT INTO PUNTOS (id_cliente, puntos) VALUES (%s, %s)', (id_usuario, new_points))
                message = "Puntos agregados exitosamente"

            # Confirmar cambios en la base de datos
            connection.commit()

        return jsonify({"msg": message}), 200
    finally:
        connection.close()

# Ruta para obtener todos los datos de un usuario dado el token entregado
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    rut = current_user.get('rut')

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT 
                    u.rut,
                    u.nombre,
                    u.apellido,
                    u.correo,
                    u.telefono,
                    u.fecha_creacion,
                    (SELECT tipo FROM TIPOUSUARIO WHERE id_tipo_usuario = u.id_tipo_usuario) AS tipo_usuario
                FROM USUARIOS u
                WHERE u.rut = %s
            ''', (rut,))
            user = cursor.fetchone()

        if user:
            return jsonify(user), 200
        else:
            return jsonify({"msg": "Usuario no encontrado"}), 404
    finally:
        connection.close()

#########################################################
#                   Sección Productos                   #
#########################################################
# Ruta para obtener los datos de un producto con su codigo de barras
@app.route('/product/barcode/<string:codigo_barras>', methods=['GET'])
def get_product_by_barcode(codigo_barras):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL que obtiene todos los detalles del producto basado en el código de barras
            cursor.execute('''
                SELECT 
                    p.id_producto, 
                    p.nombre, 
                    p.descripcion, 
                    p.fecha_registro, 
                    p.fecha_vencimiento,
                    s.stock,
                    d.porcentaje AS descuento,
                    d.vencimiento_descuento,
                    cb.codigo AS codigo_barras,
                    pr.precio_venta,
                    e.estado AS estado_producto,
                    c.nombre_categoria AS categoria
                FROM PRODUCTOS p
                LEFT JOIN STOCK s ON p.id_producto = s.id_producto
                LEFT JOIN DESCUENTOS d ON p.id_producto = d.id_producto
                LEFT JOIN CODIGOBARRAS cb ON p.id_producto = cb.id_producto
                LEFT JOIN PRECIO pr ON p.id_producto = pr.id_producto
                LEFT JOIN ESTADO e ON p.id_estado = e.id_estado
                LEFT JOIN CATEGORIA c ON p.id_categoria = c.id_categoria
                WHERE cb.codigo = %s
            ''', (codigo_barras,))
            
            product = cursor.fetchone()

        if product:
            return jsonify(product), 200
        else:
            return jsonify({"msg": "Producto no encontrado"}), 404
    finally:
        connection.close()

# Ruta para cambiar el estado de un producto a inactivo dado su codigo de barras
@app.route('/product/barcode/<string:codigo_barras>', methods=['DELETE'])
def deactivate_product_by_barcode(codigo_barras):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Obtener el id del producto mediante el codigo de barras
            cursor.execute('SELECT id_producto FROM CODIGOBARRAS WHERE codigo = %s', (codigo_barras,))
            product = cursor.fetchone()

            if not product:
                return jsonify({"msg": "Producto no encontrado"}), 404

            # Obtener el id del estado 'inactivo' desde la tabla ESTADO
            cursor.execute('SELECT id_estado FROM ESTADO WHERE estado = %s', ('inactivo',))
            estado_inactivo = cursor.fetchone()

            if not estado_inactivo:
                return jsonify({"msg": "Estado inactivo no encontrado"}), 400

            # Actualizar el estado del producto a inactivo
            cursor.execute('UPDATE PRODUCTOS SET id_estado = %s WHERE id_producto = %s', (estado_inactivo['id_estado'], product['id_producto']))
            connection.commit()

        return jsonify({"msg": "Producto marcado como inactivo exitosamente"}), 200
    finally:
        connection.close()

# Ruta para actualizar los datos de un producto dado su codigo de barras
@app.route('/product/barcode/<string:codigo_barras>', methods=['PUT'])
def update_product_by_barcode(codigo_barras):
    new_data = request.json
    nombre = new_data.get('nombre')
    descripcion = new_data.get('descripcion')
    fecha_vencimiento = new_data.get('fecha_vencimiento')
    stock = new_data.get('stock')
    descuento = new_data.get('descuento')
    precio_venta = new_data.get('precio_venta')
    estado_producto = new_data.get('estado')
    categoria = new_data.get('categoria')
    vencimiento_descuento = new_data.get('vencimiento_descuento')

    # Validar que si se proporciona un vencimiento de descuento, no sea una fecha anterior a la actual
    if vencimiento_descuento:
        try:
            fecha_vencimiento_descuento = datetime.strptime(vencimiento_descuento, '%Y-%m-%d').date()
            fecha_actual = datetime.now().date()

            if fecha_vencimiento_descuento <= fecha_actual:
                return jsonify({"msg": "La fecha de vencimiento del descuento no puede ser igual o anterior a la fecha actual"}), 400

        except ValueError:
            return jsonify({"msg": "Formato de fecha inválido para el vencimiento del descuento"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id_producto FROM CODIGOBARRAS WHERE codigo = %s', (codigo_barras,))
            product = cursor.fetchone()

            if not product:
                return jsonify({"msg": "Producto no encontrado"}), 404

            id_producto = product['id_producto']

            # Actualizar los detalles del producto
            cursor.execute('''
                UPDATE PRODUCTOS 
                SET nombre = %s, descripcion = %s, fecha_vencimiento = %s, id_estado = (SELECT id_estado FROM ESTADO WHERE estado = %s), 
                id_categoria = (SELECT id_categoria FROM CATEGORIA WHERE nombre_categoria = %s) 
                WHERE id_producto = %s
            ''', (nombre, descripcion, fecha_vencimiento, estado_producto, categoria, id_producto))

            # Actualizar el stock
            cursor.execute('UPDATE STOCK SET stock = %s WHERE id_producto = %s', (stock, id_producto))

            # Actualizar el precio de venta
            cursor.execute('UPDATE PRECIO SET precio_venta = %s WHERE id_producto = %s', (precio_venta, id_producto))

            # Verificar si el producto ya tiene un descuento en la tabla DESCUENTOS
            cursor.execute('SELECT * FROM DESCUENTOS WHERE id_producto = %s', (id_producto,))
            descuento_existente = cursor.fetchone()

            if descuento is not None:
                if descuento_existente:
                    # Si ya existe un descuento, se actualiza
                    cursor.execute('''
                        UPDATE DESCUENTOS 
                        SET porcentaje = %s, vencimiento_descuento = %s 
                        WHERE id_producto = %s
                    ''', (descuento, vencimiento_descuento, id_producto))
                else:
                    # Si no existe, se inserta un nuevo descuento con fecha de vencimiento
                    cursor.execute('''
                        INSERT INTO DESCUENTOS (id_producto, porcentaje, vencimiento_descuento) 
                        VALUES (%s, %s, %s)
                    ''', (id_producto, descuento, vencimiento_descuento))

            connection.commit()

        return jsonify({"msg": "Producto actualizado exitosamente"}), 200
    finally:
        connection.close()

# Ruta para agregar un producto
@app.route('/product', methods=['POST'])
def add_product():
    new_data = request.json
    nombre = new_data.get('nombre')
    descripcion = new_data.get('descripcion')
    fecha_vencimiento = new_data.get('fecha_vencimiento')
    stock = new_data.get('stock')
    descuento = new_data.get('descuento')
    precio_venta = new_data.get('precio_venta')
    estado_producto = new_data.get('estado')
    categoria = new_data.get('categoria')
    codigo_barras = new_data.get('codigo_barras')
    vencimiento_descuento = new_data.get('vencimiento_descuento')

    # Validar que los campos estén correctos
    if not all([nombre, stock, precio_venta, estado_producto, categoria, codigo_barras]):
        return jsonify({"msg": "Faltan datos obligatorios"}), 400

    # Validar que si se proporciona un vencimiento de descuento, no sea una fecha anterior a la actual
    if vencimiento_descuento:
        try:
            fecha_vencimiento_descuento = datetime.strptime(vencimiento_descuento, '%Y-%m-%d').date()
            fecha_actual = datetime.now().date()

            if fecha_vencimiento_descuento <= fecha_actual:
                return jsonify({"msg": "La fecha de vencimiento del descuento no puede ser igual o anterior a la fecha actual"}), 400

        except ValueError:
            return jsonify({"msg": "Formato de fecha inválido para el vencimiento del descuento"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Insertar el nuevo producto
            cursor.execute('''
                INSERT INTO PRODUCTOS (nombre, descripcion, fecha_registro, fecha_vencimiento, id_estado, id_categoria)
                VALUES (%s, %s, current_timestamp(), %s, 
                (SELECT id_estado FROM ESTADO WHERE estado = %s), 
                (SELECT id_categoria FROM CATEGORIA WHERE nombre_categoria = %s))
            ''', (nombre, descripcion, fecha_vencimiento, estado_producto, categoria))

            # Obtener el id_producto
            product_id = connection.insert_id()

            # Insertar el código de barras en la tabla CODIGOBARRAS
            cursor.execute('INSERT INTO CODIGOBARRAS (codigo, id_producto) VALUES (%s, %s)', (codigo_barras, product_id))

            # Insertar el stock en la tabla STOCK
            cursor.execute('INSERT INTO STOCK (id_producto, stock) VALUES (%s, %s)', (product_id, stock))

            # Insertar el descuento en la tabla DESCUENTOS junto con vencimiento_descuento si aplica
            if descuento:
                cursor.execute('INSERT INTO DESCUENTOS (id_producto, porcentaje, vencimiento_descuento) VALUES (%s, %s, %s)', (product_id, descuento, vencimiento_descuento))

            # Insertar el precio en la tabla PRECIO
            cursor.execute('INSERT INTO PRECIO (id_producto, precio_venta) VALUES (%s, %s)', (product_id, precio_venta))

            # Confirmar los cambios en la base de datos
            connection.commit()

        return jsonify({"msg": "Producto agregado exitosamente"}), 201
    finally:
        connection.close()

# Ruta para obtener todos los productos
@app.route('/products', methods=['GET'])
def get_all_products():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL para obtener todos los productos y su información
            cursor.execute('''
                SELECT 
                    p.id_producto, 
                    p.nombre, 
                    p.descripcion, 
                    p.fecha_registro, 
                    p.fecha_vencimiento, 
                    s.stock, 
                    d.porcentaje AS descuento, 
                    d.vencimiento_descuento,
                    cb.codigo AS codigo_barras, 
                    pr.precio_venta, 
                    e.estado AS estado_producto, 
                    c.nombre_categoria AS categoria
                FROM PRODUCTOS p
                LEFT JOIN STOCK s ON p.id_producto = s.id_producto
                LEFT JOIN DESCUENTOS d ON p.id_producto = d.id_producto
                LEFT JOIN CODIGOBARRAS cb ON p.id_producto = cb.id_producto
                LEFT JOIN PRECIO pr ON p.id_producto = pr.id_producto
                LEFT JOIN ESTADO e ON p.id_estado = e.id_estado
                LEFT JOIN CATEGORIA c ON p.id_categoria = c.id_categoria
            ''')
            products = cursor.fetchall()
        
        # Retornar los productos en formato JSON
        return jsonify(products), 200
    finally:
        connection.close()

# Ruta para obtener todas las categorí­as
@app.route('/categories', methods=['GET'])
def get_all_categories():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Consulta SQL para obtener todas las categorí­as
            cursor.execute('SELECT id_categoria, nombre_categoria FROM CATEGORIA')
            categories = cursor.fetchall()
        
        # Retornar las categorí­as en formato JSON
        return jsonify(categories), 200
    finally:
        connection.close()

# Ruta para agregar una nueva categoría de productos
@app.route('/categories', methods=['POST'])
def add_category():
    nueva_categoria = request.json.get('nombre_categoria')

    # Validar que se proporcionó el nombre de la categoría
    if not nueva_categoria:
        return jsonify({"msg": "Nombre de la categoría faltante"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Verificar si la categoría ya existe
            cursor.execute('SELECT id_categoria FROM CATEGORIA WHERE nombre_categoria = %s', (nueva_categoria,))
            categoria_existente = cursor.fetchone()

            if categoria_existente:
                return jsonify({"msg": "La categoría ya existe"}), 400

            # Insertar la nueva categoría en la tabla CATEGORIA
            cursor.execute('''
                INSERT INTO CATEGORIA (nombre_categoria) 
                VALUES (%s)
            ''', (nueva_categoria,))
            connection.commit()

        return jsonify({"msg": "Categoría agregada exitosamente"}), 201
    except Exception as e:
        return jsonify({"msg": "Ocurrió un error al agregar la categoría", "error": str(e)}), 500
    finally:
        connection.close()

#########################################################
#                   Sección Ventas                      #
#########################################################

# Ruta para obtener todos los datos de la tabla DETALLEVENTA con el código de barras
@app.route('/detalleventa', methods=['GET'])
def get_all_detalle_venta():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT 
                    dv.id_venta,
                    cb.codigo AS codigo_barras,
                    dv.cantidad,
                    dv.total_sin_iva,
                    dv.total_con_iva
                FROM DETALLEVENTA dv
                LEFT JOIN CODIGOBARRAS cb ON dv.id_producto = cb.id_producto
            ''')
            detalle_venta = cursor.fetchall()

        return jsonify(detalle_venta), 200
    except Exception as e:
        print(f"Error al obtener los detalles de venta: {e}")
        return jsonify({"msg": "Ocurrió un error al obtener los datos de detalle de venta"}), 500
    finally:
        connection.close()

# Ruta para obtener los datos de venta de un producto dado su codigo de barras
@app.route('/detalleventa/<string:codigo_barras>', methods=['GET'])
def get_detalle_venta_by_codigo_barras(codigo_barras):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT 
                    dv.id_venta,
                    cb.codigo AS codigo_barras,  -- Obtener el código de barras del producto
                    dv.cantidad,
                    dv.total_sin_iva,
                    dv.total_con_iva
                FROM DETALLEVENTA dv
                LEFT JOIN CODIGOBARRAS cb ON dv.id_producto = cb.id_producto
                WHERE cb.codigo = %s
            ''', (codigo_barras,))
            detalle_venta = cursor.fetchall()

        if detalle_venta:
            return jsonify(detalle_venta), 200
        else:
            return jsonify({"msg": "No se encontraron detalles de venta para este código de barras"}), 404
    except Exception as e:
        print(f"Error al obtener los detalles de venta para el código de barras {codigo_barras}: {e}")
        return jsonify({"msg": "Ocurrió un error al obtener los datos de detalle de venta"}), 500
    finally:
        connection.close()

# Ruta para insertar una nueva venta basada en un código de barras
@app.route('/detalleventa', methods=['POST'])
def add_venta():
    data = request.json
    codigo_barras = data.get('codigo_barras')
    cantidad = data.get('cantidad')
    total_sin_iva = data.get('total_sin_iva')
    total_con_iva = data.get('total_con_iva')

    # Validar que los datos obligatorios estén presentes
    if not all([codigo_barras, cantidad, total_sin_iva, total_con_iva]):
        return jsonify({"msg": "Faltan datos obligatorios"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Obtener el id_producto asociado al código de barras
            cursor.execute('SELECT id_producto FROM CODIGOBARRAS WHERE codigo = %s', (codigo_barras,))
            producto = cursor.fetchone()

            if not producto:
                return jsonify({"msg": "Producto no encontrado para el código de barras proporcionado"}), 404

            id_producto = producto['id_producto']

            # Insertar los datos en la tabla DETALLEVENTA
            cursor.execute('''
                INSERT INTO DETALLEVENTA (id_producto, cantidad, total_sin_iva, total_con_iva)
                VALUES (%s, %s, %s, %s)
            ''', (id_producto, cantidad, total_sin_iva, total_con_iva))

            connection.commit()

        return jsonify({"msg": "Venta insertada exitosamente"}), 201
    except Exception as e:
        print(f"Error al insertar la venta: {e}")
        return jsonify({"msg": "Ocurrió un error al insertar la venta"}), 500
    finally:
        connection.close()

# Ruta para obtener todos los datos de la tabla VENTA, con opción de filtrar por fecha de venta
@app.route('/ventas', methods=['GET'])
def get_all_ventas():
    # Obtener los parámetros de fecha de inicio y fin de la solicitud
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = '''
                SELECT 
                    v.id_venta, 
                    v.id_cliente, 
                    v.id_cajero, 
                    v.total_sin_iva, 
                    v.total_con_iva, 
                    v.fecha_venta, 
                    v.numero_documento, 
                    v.porcentaje, 
                    v.id_forma_pago, 
                    v.id_tipodocumento
                FROM VENTA v
            '''
            params = []

            if fecha_inicio and fecha_fin:
                query += ' WHERE v.fecha_venta BETWEEN %s AND %s'
                params.extend([fecha_inicio, fecha_fin])
            elif fecha_inicio:
                query += ' WHERE v.fecha_venta >= %s'
                params.append(fecha_inicio)
            elif fecha_fin:
                query += ' WHERE v.fecha_venta <= %s'
                params.append(fecha_fin)

            cursor.execute(query, params)
            ventas = cursor.fetchall()

            if not ventas:
                return jsonify({"msg": "No se encontraron ventas en el rango de fechas proporcionado"}), 404

        return jsonify(ventas), 200
    except Exception as e:
        print(f"Error al obtener las ventas: {e}")
        return jsonify({"msg": "Ocurrió un error al obtener las ventas"}), 500
    finally:
        connection.close()


if __name__ == '__main__':
    app.run(debug=True)
