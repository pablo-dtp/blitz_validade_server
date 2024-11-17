from flask import Flask, request, jsonify
from functools import wraps
import logging
import os
import jwt
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)

SECRET_KEY = os.getenv('SECRET_KEY')

DATABASE = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER_LOGIN'),
    'password': os.getenv('DB_PASSWORD_LOGIN'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
}

WRITE_DATABASE = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER_ADMIN'),
    'password': os.getenv('DB_PASSWORD_ADMIN'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
}

def get_db_connection(write_access=False):
    db_config = WRITE_DATABASE if write_access else DATABASE
    return psycopg2.connect(**db_config)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    app.logger.info(f"Tentativa de login para o usuário: {username}")
    
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT username, password, name, permission_level FROM users WHERE username = %s', (username,))
        user = cur.fetchone()

        if user:
            db_username, db_password, db_name, permission_level = user
            if check_password_hash(db_password, password):
                app.logger.info(f"Login bem-sucedido para o usuário: {db_username}")

                token = jwt.encode({'username': db_username}, SECRET_KEY, algorithm='HS256')

                return jsonify({
                    'status': 'success',
                    'token': token,  # Retornando o token gerado
                    'permission_level': permission_level
                }), 200
            else:
                return jsonify({'status': 'error', 'message': 'Senha incorreta.'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404
    except Exception as e:
        app.logger.error(f"Erro no login: {e}")
        return jsonify({'status': 'error', 'message': 'Erro no servidor.'}), 500
    finally:
        cur.close()
        conn.close()

# Decorador para verificar o token JWT
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Obtém o token no formato 'Bearer <token>'

        if not token:
            return jsonify({'message': 'Token de autenticação é necessário.'}), 401

        try:
            # Decodifica o token e extrai o username do usuário
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_username = data['username']  # Supondo que o username esteja no payload do token
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido.'}), 401

        return f(current_username, *args, **kwargs)  # Passa o current_username para a função chamada
    return decorated_function

@app.route('/add_user', methods=['POST'])
@token_required  # Aplica a verificação do token antes da execução da função
def add_user(current_username):  # Recebe o username do token decodificado
    data = request.json
    username = data['username']
    password = data['password']
    name = data['name']
    permission_level = data['permission_level']

    # Verificar se o nome de usuário já existe
    conn = get_db_connection(write_access=True)
    cur = conn.cursor()
    try:
        # Checa se já existe um usuário com o mesmo nome de usuário
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cur.fetchone()

        if existing_user:
            # Retorna erro se o nome de usuário já existir
            return jsonify({'status': 'error', 'message': 'Nome de usuário já existe. Escolha outro.'}), 400

        # Se o nome de usuário não existe, prossegue para criar o novo usuário
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        app.logger.info(f"Tentando adicionar usuário: {username}, Nome: {name}, Nível de permissão: {permission_level}")

        cur.execute('INSERT INTO users (username, password, name, permission_level) VALUES (%s, %s, %s, %s)',
                    (username, hashed_password, name, permission_level))
        conn.commit()
        
        app.logger.info(f"Usuário {username} adicionado com sucesso!")
        return jsonify({'status': 'success', 'message': 'Usuário adicionado com sucesso!'}), 200

    except Exception as e:
        app.logger.error(f"Erro ao adicionar usuário {username}: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao adicionar usuário. Tente novamente mais tarde.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/update_user/<username>', methods=['PUT'])
@token_required  # Aplica a verificação do token
def update_user(current_username, username):
    if current_username == username:
        return jsonify({'status': 'error', 'message': 'Você não pode atualizar seu próprio perfil.'}), 403

    data = request.json
    name = data['name']
    new_username = data['username']
    permission_level = data['permission_level']

    app.logger.info(f"Atualizando usuário {username}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        # Verificando se o username já existe
        cur.execute('SELECT username FROM users WHERE username = %s AND username != %s', (new_username, username))
        existing_user = cur.fetchone()

        if existing_user:
            return jsonify({'status': 'error', 'message': 'Nome de usuário já existente!'}), 400

        # Atualizando o usuário
        cur.execute('UPDATE users SET name = %s, username = %s, permission_level = %s WHERE username = %s',
                    (name, new_username, permission_level, username))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Usuário atualizado com sucesso!'}), 200

    except Exception as e:
        app.logger.error(f"Erro ao atualizar usuário: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao atualizar usuário.'}), 500

    finally:
        cur.close()
        conn.close()

@app.route('/get_users', methods=['GET'])
def get_users():
    app.logger.info("Recuperando lista de usuários")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT username, name, permission_level FROM users')
        users = cur.fetchall()
        user_list = [
            {
                'username': user[0],
                'name': user[1],
                'permission_level': user[2]
            }
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

@app.route('/delete_user/<username>', methods=['DELETE'])
@token_required  # Aplica a verificação do token
def delete_user(current_username, username):
    # Garantir que o usuário logado não tente deletar o próprio perfil
    if current_username == username:
        return jsonify({'status': 'error', 'message': 'Você não pode deletar seu próprio perfil.'}), 403

    app.logger.info(f"Deletando usuário {username}")
    
    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        # Verificar se o usuário logado tem permissão para deletar outro usuário
        cur.execute('SELECT permission_level FROM users WHERE username = %s', (current_username,))
        current_user = cur.fetchone()

        if current_user:
            permission_level = current_user[0]
            if permission_level < 3:  # Permissão mínima para deletar é 3 (Admin)
                return jsonify({'status': 'error', 'message': 'Você não tem permissão para deletar usuários.'}), 403

            # Deletando o usuário
            cur.execute('DELETE FROM users WHERE username = %s', (username,))
            conn.commit()
            return jsonify({'status': 'success', 'message': 'Usuário deletado com sucesso!'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404
    except Exception as e:
        app.logger.error(f"Erro ao deletar usuário: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao deletar usuário.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/get_product', methods=['POST'])
def get_product():
    data = request.json
    codigo_barras = data.get('codigo_barras')

    app.logger.info(f"Buscando produto com código de barras: {codigo_barras}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        cur.execute('SELECT produto, descricao, codigo_barras FROM produtos WHERE codigo_barras = %s', (codigo_barras,))
        produto = cur.fetchone()

        if produto:
            return jsonify({
                'produto': produto[0],
                'descricao': produto[1],
                'codigo_barras': produto[2]
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Produto não encontrado.'}), 404
    except Exception as e:
        app.logger.error(f"Erro ao buscar produto: {e}")
        return jsonify({'status': 'error', 'message': 'Erro no servidor.'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/add_validade', methods=['POST'])
def add_validade():
    data = request.json
    produto = data['produto']
    descricao = data['descricao']
    codigo_barras = data['codigo_barras']
    quantidade = data['quantidade']
    embalagem = data['embalagem']
    data_validade = data['data_validade']

    quantidade_total = quantidade * embalagem

    app.logger.info(f"Adicionando validade para o produto: {produto} com código de barras {codigo_barras}")

    conn = get_db_connection(write_access=True)
    cur = conn.cursor()

    try:
        cur.execute(
            'INSERT INTO validades (produto, descricao, codigo_barras, data_validade, quantidade) VALUES (%s, %s, %s, %s, %s)',
            (produto, descricao, codigo_barras, data_validade, quantidade_total)
        )
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Validade registrada com sucesso!'}), 200
    except Exception as e:
        app.logger.error(f"Erro ao adicionar validade: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao registrar validade.'}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
