from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test'
jwt = JWTManager(app)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
uname = ""

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
class Tokens(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    token = db.Column(db.String, unique=True, nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
class Views(db.Model):
    id = db.Column(db.String, primary_key=True)
    views = db.Column(db.Integer, default=0)

    def __init__(self, id):
        self.id = id
    
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
        new_access = Tokens(username=username, token=access_token)
        #remove entry if there is already one associated with user
        user_authenticated = Tokens.query.filter_by(username=username).first()
        if user_authenticated:
            db.session.delete(user_authenticated)
            db.session.commit()
        db.session.add(new_access)
        db.session.commit()
        global uname
        uname = username
        return jsonify({'success': True, 'message': 'Login successful', 'token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    global uname
    uname = ""
    return jsonify({'success': True, 'message': 'Logout successful'}), 200

@app.route('/get_user_using_token', methods=['POST'])
def get_user_using_token():
    data = request.get_json()
    
    if 'token' not in data:
        return jsonify({'error': 'Need token'}), 400

    token = data['token']

    access = Tokens.query.filter_by(token=token).first()
    return jsonify({'success': True, 'message': 'Username retrieved', 'username': access.username}), 200

@app.route('/get_token', methods=['POST'])
def get_token():
    data = request.get_json()
    print(data['username'])
    if 'username' not in data:
        return jsonify({'error': 'No access'}), 400

    username = data['username']

    access = Tokens.query.filter_by(username=username).first()
    
    return jsonify({'success': True, 'message': 'Token retrieved', 'token': access.token}), 200

@app.route('/fetch_username', methods=['GET'])
def fetch_username():
    return jsonify({'success': True, 'name': uname}), 200

#views stuff
@app.route('/views/<video_id>', methods=['GET'])
def get_view_count(video_id):
    video = Views.query.get(video_id)
    if video:
        return jsonify({'views': video.views}), 200
    else:
        return jsonify({'error': 'Video not found'}), 404

@app.route('/increment/<video_id>', methods=['POST'])
def increase_view_count(video_id):
    video = Views.query.get(video_id)
    if video:
        video.views += 1
        db.session.commit()
        return jsonify({'views': video.views}), 200
    else:
        return jsonify({'error': 'Video not found'}), 404

@app.route('/initialize', methods=['POST'])
def create_video():
    data = request.get_json()
    video_id = data.get('video_id')
    if video_id:
        new_video = Views(id=video_id)
        db.session.add(new_video)
        db.session.commit()
        return jsonify({'message': 'Video created successfully'}), 201
    else:
        return jsonify({'error': 'Invalid video ID'}), 400

@app.route('/remove_views/<video_id>', methods=['DELETE'])
def delete_video(video_id):
    video = Views.query.get(video_id)
    if video:
        db.session.delete(video)
        db.session.commit()
        return jsonify({'message': 'Video deleted successfully'}), 200
    else:
        return jsonify({'error': 'Video not found'}), 404
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)