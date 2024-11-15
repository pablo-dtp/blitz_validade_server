import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import logging

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuração do log
logging.basicConfig(level=logging.INFO)  # Pode ser DEBUG para mais detalhes

DATABASE = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER_LOGIN'),
    'password': os.getenv('DB_PASSWORD_LOGIN'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'options': "-c client_encoding=utf8"
}

WRITE_DATABASE = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER_ADMIN'),
    'password': os.getenv('DB_PASSWORD_ADMIN'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'options': "-c client_encoding=utf8"
}

def get_db_connection(write_access=False):
    db_config = WRITE_DATABASE if write_access else DATABASE
    return psycopg2.connect(**db_config)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    usuario = data.get('username')
    senha = data.get('password')

    app.logger.info(f"Tentando logar usuário: {usuario}")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT username, password, permission_level FROM users WHERE username = %s', (usuario,))
        user = cur.fetchone()

        if user is not None:
            db_username, db_password, permission_level = user
            app.logger.info(f"Usuário encontrado: {db_username}, verificando senha...")

            # Verifica se a senha fornecida corresponde ao hash armazenado no banco de dados
            if check_password_hash(db_password, senha):
                app.logger.info(f"Login bem-sucedido para o usuário: {db_username}")
                return jsonify({
                    'status': 'success',
                    'message': 'Login bem-sucedido!',
                    'permission_level': permission_level
                }), 200
            else:
                app.logger.warning(f"Senha incorreta para o usuário: {db_username}")
                return jsonify({'status': 'error', 'message': 'Nome ou senha incorretos.'}), 401
        else:
            app.logger.warning(f"Usuário não encontrado: {usuario}")
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404
    except Exception as e:
        app.logger.error(f"Erro no login para o usuário {usuario}: {e}")
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

    # Cria o hash da senha antes de salvar no banco de dados
    hashed_password = generate_password_hash(password, method='sha256')

    app.logger.info(f"Adicionando usuário {username} com nível de permissão {permission_level}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        cur.execute(
            'INSERT INTO users (username, password, name, permission_level) VALUES (%s, %s, %s, %s) RETURNING id',
            (username, hashed_password, name, permission_level)
        )
        new_user_id = cur.fetchone()[0]
        conn.commit()
        app.logger.info(f"Usuário {username} adicionado com sucesso! ID: {new_user_id}")
        return jsonify({
            'status': 'success',
            'message': 'Usuário adicionado com sucesso!',
            'user_id': new_user_id
        }), 200
    except Exception as e:
        app.logger.error(f"Erro ao adicionar usuário {username}: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao adicionar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/get_users', methods=['GET'])
def get_users():
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT id, name, username, permission_level FROM users')
        users = cur.fetchall()
        user_list = [
            {'id': user[0], 'name': user[1], 'username': user[2], 'permission_level': user[3]}
            for user in users
        ]
        app.logger.info(f"Usuários recuperados: {len(user_list)}")
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

    app.logger.info(f"Atualizando usuário ID {user_id} para nome: {name}, permissão: {permission_level}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        cur.execute('UPDATE users SET name = %s, permission_level = %s WHERE id = %s',
                    (name, permission_level, user_id))
        conn.commit()
        app.logger.info(f"Usuário ID {user_id} atualizado com sucesso.")
        return jsonify({'status': 'success', 'message': 'Usuário atualizado com sucesso!'}), 200
    except Exception as e:
        app.logger.error(f"Erro ao atualizar usuário ID {user_id}: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao atualizar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    app.logger.info(f"Deletando usuário ID {user_id}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        app.logger.info(f"Usuário ID {user_id} deletado com sucesso.")
        return jsonify({'status': 'success', 'message': 'Usuário deletado com sucesso!'}), 200
    except Exception as e:
        app.logger.error(f"Erro ao deletar usuário ID {user_id}: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao deletar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
