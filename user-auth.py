from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test'
jwt = JWTManager(app)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request data'}), 400

    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400

    hashed_password = generate_password_hash(password, method='sha256')
    
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Registration successful'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request data'}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({'success': True, 'message': 'Login successful', 'token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({'success': True, 'message': 'Logout successful'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)