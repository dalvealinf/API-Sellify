from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from config import get_db_connection, get_auth_db_connection
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY') #Clave estática que se puede usar para verificar los tokens creados
jwt = JWTManager(app)

try:
    connection = get_auth_db_connection()
except Exception as e:
    print(f"Error al conectar a la base de datos: {e}")

@app.route('/register', methods=['POST']) #Registro de usuarios a la base de datos de la API (no tiene seguridad)
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"msg": "Faltan datos"}), 400

    password_hash = generate_password_hash(password)
    connection = get_auth_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO api_users (username, password_hash) VALUES (%s, %s)', (username, password_hash))
            connection.commit()
        return jsonify({"msg": "Usuario registrado exitosamente"}), 201
    except:
        return jsonify({"msg": "El usuario ya existe"}), 400
    finally:
        connection.close()

@app.route('/login', methods=['POST']) #Login para obtener un token con el usuario de la API
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    connection = get_auth_db_connection()
    user = None
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM api_users WHERE username = %s', (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            access_token = create_access_token(identity={'username': username})
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"msg": "Nombre de usuario o contraseña incorrectos"}), 401
    finally:
        connection.close()

@app.route('/users', methods=['GET']) #Obtener todos los datos de una tabla
@jwt_required()
def get_users():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
    connection.close()
    return jsonify(users)

@app.route('/users', methods=['POST']) #Registro de datos en una tabla sin verificación de dato ya existente
@jwt_required()
def add_user():
    new_user = request.json
    name = new_user['name']
    email = new_user['email']

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO users (name, email) VALUES (%s, %s)', (name, email))
        connection.commit()
    connection.close()
    return jsonify({'message': 'User added successfully!'}), 201

if __name__ == '__main__':
    app.run(debug=True)
