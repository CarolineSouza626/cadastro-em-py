from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Modelo do banco de dados
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)

# Criar o banco de dados
with app.app_context():
    db.create_all()

# Rota para cadastro de usuário
@app.route('/usuarios/cadastro', methods=['POST'])
def cadastrar_usuario():
    dados = request.get_json()
    if not dados or 'nome' not in dados or 'email' not in dados or 'senha' not in dados:
        return jsonify({'erro': 'Dados inválidos'}), 400

    # Verificar se o email já está cadastrado
    if Usuario.query.filter_by(email=dados['email']).first():
        return jsonify({'erro': 'Email já cadastrado'}), 400

    senha_hash = bcrypt.generate_password_hash(dados['senha']).decode('utf-8')

    novo_usuario = Usuario(nome=dados['nome'], email=dados['email'], senha=senha_hash)
    db.session.add(novo_usuario)
    db.session.commit()

    return jsonify({'mensagem': 'Usuário cadastrado com sucesso!'}), 201

# Rota de login (autenticação de usuário)
@app.route('/usuarios/login', methods=['POST'])
def login():
    dados = request.get_json()
    if not dados or 'email' not in dados or 'senha' not in dados:
        return jsonify({'erro': 'Dados inválidos'}), 400

    usuario = Usuario.query.filter_by(email=dados['email']).first()

    if usuario and bcrypt.check_password_hash(usuario.senha, dados['senha']):
        return jsonify({'mensagem': 'Login bem-sucedido!'}), 200
    else:
        return jsonify({'erro': 'Credenciais inválidas'}), 401

# Rota para a página de login
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# Rota para a página de cadastro
@app.route('/cadastro', methods=['GET'])
def cadastro_page():
    return render_template('cadastro.html')

# Rota para a página inicial (Home) após login bem-sucedido
@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)
