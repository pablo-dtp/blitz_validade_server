import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2

app = Flask(__name__)
CORS(app)

# Configurações do banco de dados para LOGIN ROLE (somente SELECT)
DATABASE = {
    'dbname': os.environ.get('DB_NAME'),
    'user': os.environ.get('DB_USER_LOGIN'),  # Login role
    'password': os.environ.get('DB_PASSWORD_LOGIN'),
    'host': os.environ.get('DB_HOST'),
    'port': os.environ.get('DB_PORT'),
    'options': "-c client_encoding=utf8"
}

# Configurações do banco de dados para ADMIN ROLE (permissões completas de CRUD)
WRITE_DATABASE = {
    'dbname': os.environ.get('DB_NAME'),
    'user': os.environ.get('DB_USER_ADMIN'),  # Admin role
    'password': os.environ.get('DB_PASSWORD_ADMIN'),
    'host': os.environ.get('DB_HOST'),
    'port': os.environ.get('DB_PORT'),
    'options': "-c client_encoding=utf8"
}

def get_db_connection(write_access=False):
    # Escolhe a configuração de banco de dados com base na necessidade de escrita ou leitura
    db_config = WRITE_DATABASE if write_access else DATABASE
    return psycopg2.connect(**db_config)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    usuario = data.get('username')
    senha = data.get('password')

    conn = get_db_connection()  # Usando as credenciais do login role (somente leitura)
    cur = conn.cursor()

    try:
        cur.execute('SELECT username, password, permission_level FROM users WHERE username = %s', (usuario,))
        user = cur.fetchone()

        if user is not None:
            db_username, db_password, permission_level = user
            if senha == db_password:
                return jsonify({
                    'status': 'success',
                    'message': 'Login bem-sucedido!',
                    'permission_level': permission_level
                }), 200
            else:
                return jsonify({'status': 'error', 'message': 'Nome ou senha incorretos.'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404
    except Exception as e:
        app.logger.error(f"Erro no login: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao processar a requisição.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data['username']
    password = data['password']
    name = data['name']
    permission_level = data['permission_level']

    conn = get_db_connection(write_access=True)  # Usando as credenciais do admin role (para CRUD)
    cur = conn.cursor()

    try:
        cur.execute(
            'INSERT INTO users (username, password, name, permission_level) VALUES (%s, %s, %s, %s) RETURNING id',
            (username, password, name, permission_level)
        )
        new_user_id = cur.fetchone()[0]  # Pega o ID do usuário recém-criado
        conn.commit()
        return jsonify({
            'status': 'success',
            'message': 'Usuário adicionado com sucesso!',
            'user_id': new_user_id
        }), 200
    except Exception as e:
        app.logger.error(f"Erro ao adicionar usuário: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao adicionar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/get_users', methods=['GET'])
def get_users():
    conn = get_db_connection()  # Usando as credenciais do login role (somente leitura)
    cur = conn.cursor()

    try:
        cur.execute('SELECT id, name, username, permission_level FROM users')
        users = cur.fetchall()
        user_list = [
            {'id': user[0], 'name': user[1], 'username': user[2], 'permission_level': user[3]}
            for user in users
        ]
        return jsonify({'users': user_list}), 200
    except Exception as e:
        app.logger.error(f"Erro ao obter usuários: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao obter usuários.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/update_user/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    name = data['name']
    permission_level = data['permission_level']

    conn = get_db_connection(write_access=True)  # Usando as credenciais do admin role (para CRUD)
    cur = conn.cursor()

    try:
        cur.execute('UPDATE users SET name = %s, permission_level = %s WHERE id = %s',
                    (name, permission_level, user_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Usuário atualizado com sucesso!'}), 200
    except Exception as e:
        app.logger.error(f"Erro ao atualizar usuário: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao atualizar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    conn = get_db_connection(write_access=True)  # Usando as credenciais do admin role (para CRUD)
    cur = conn.cursor()

    try:
        cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Usuário deletado com sucesso!'}), 200
    except Exception as e:
        app.logger.error(f"Erro ao deletar usuário: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao deletar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(port=5000)
