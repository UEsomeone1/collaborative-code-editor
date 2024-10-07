from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import jwt
import bcrypt
import mysql.connector
from mysql.connector import Error
import subprocess

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

# JWT secret key
JWT_SECRET = 'your-secret-key'

# Database connection
def create_db_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='collab_editor',
            user='root',
            password='root',
            port=5000
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL database: {e}")
        return None

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            connection.commit()
            user_id = cursor.lastrowid
            token = jwt.encode({'id': user_id}, JWT_SECRET, algorithm='HS256')
            return jsonify({'auth': True, 'token': token, 'userId': user_id}), 201
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    else:
        return jsonify({'error': 'Database connection failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                token = jwt.encode({'id': user['id']}, JWT_SECRET, algorithm='HS256')
                return jsonify({'auth': True, 'token': token, 'userId': user['id']})
            else:
                return jsonify({'error': 'Invalid username or password'}), 401
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    else:
        return jsonify({'error': 'Database connection failed'}), 500

@app.route('/api/projects', methods=['GET', 'POST'])
def projects():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No token provided'}), 403
    
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['id']
    except:
        return jsonify({'error': 'Invalid token'}), 403
    
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            if request.method == 'GET':
                cursor.execute("SELECT * FROM projects WHERE user_id = %s", (user_id,))
                projects = cursor.fetchall()
                return jsonify(projects)
            elif request.method == 'POST':
                data = request.json
                name = data['name']
                cursor.execute("INSERT INTO projects (name, user_id) VALUES (%s, %s)", (name, user_id))
                connection.commit()
                return jsonify({'id': cursor.lastrowid, 'name': name}), 201
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    else:
        return jsonify({'error': 'Database connection failed'}), 500

@app.route('/api/projects/<int:project_id>/files', methods=['GET', 'POST'])
def files(project_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No token provided'}), 403
    
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded['id']
    except:
        return jsonify({'error': 'Invalid token'}), 403
    
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            if request.method == 'GET':
                cursor.execute("SELECT * FROM files WHERE project_id = %s", (project_id,))
                files = cursor.fetchall()
                return jsonify(files)
            elif request.method == 'POST':
                data = request.json
                name = data['name']
                content = data['content']
                cursor.execute("INSERT INTO files (project_id, name, content) VALUES (%s, %s, %s)", (project_id, name, content))
                connection.commit()
                return jsonify({'id': cursor.lastrowid, 'name': name, 'content': content}), 201
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    else:
        return jsonify({'error': 'Database connection failed'}), 500

@app.route('/api/files/<int:file_id>', methods=['PUT'])
def update_file(file_id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No token provided'}), 403
    
    try:
        jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return jsonify({'error': 'Invalid token'}), 403
    
    connection = create_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            data = request.json
            content = data['content']
            cursor.execute("UPDATE files SET content = %s WHERE id = %s", (content, file_id))
            connection.commit()
            return jsonify({'message': 'File updated successfully'}), 200
        except Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    else:
        return jsonify({'error': 'Database connection failed'}), 500

@app.route('/api/execute', methods=['POST'])
def execute_code():
    data = request.json
    code = data['code']
    language = data['language']
    
    if language == 'python':
        try:
            result = subprocess.run(['python', '-c', code], capture_output=True, text=True, timeout=5)
            return jsonify({'result': result.stdout, 'error': result.stderr})
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Execution timed out'}), 408
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Unsupported language'}), 400

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('code_change')
def handle_code_change(data):
    emit('code_update', data, broadcast=True, include_self=False)

@socketio.on('cursor_move')
def handle_cursor_move(data):
    emit('cursor_update', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)