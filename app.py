from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, case
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import pymysql
import secrets
import jwt
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import json
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os


pymysql.install_as_MySQLdb()

app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Security configurations
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/chatproject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)


# Add these configurations after app initialization
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_photo = db.Column(db.String(200), default='default.png')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    
    @property
    def chats(self):
        chat_partners = User.query.join(Message, 
        ((Message.sender_id == User.id) & (Message.receiver_id == self.id)) |
        ((Message.receiver_id == User.id) & (Message.sender_id == self.id))
    ).filter(User.id != self.id).distinct().all()
        return chat_partners
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_last_seen(self):
        self.last_seen = datetime.utcnow()
        db.session.commit()

    # Add these methods to User class
    def get_unread_messages_count(self):
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()
    
    def mark_messages_as_read(self, sender_id):
        unread_messages = Message.query.filter_by(
            receiver_id=self.id,
            sender_id=sender_id,
            is_read=False
        ).all()
        for message in unread_messages:
            message.is_read = True
        db.session.commit()


# Add these new models after your User model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='sent')  # Values: 'sent', 'delivered', 'read'
    is_read = db.Column(db.Boolean, default=False)  # Keep this for other functionalities
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    
class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_group = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)  # New field
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    members = db.relationship('User', secondary='room_members')
    messages = db.relationship('RoomMessage', backref='room', lazy=True)

class RoomMembers(db.Model):
    __tablename__ = 'room_members'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class RoomMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    sender = db.relationship('User', backref='room_messages')



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_token(user_id):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def check_session_timeout():
    if 'last_activity' not in session:
        session['last_activity'] = datetime.utcnow().timestamp()
        return False
        
    last_activity = datetime.fromtimestamp(session['last_activity'])
    if datetime.utcnow() - last_activity > timedelta(minutes=30):  # Changed to 30 minutes
        logout_user()
        session.clear()
        flash('Your session has expired. Please log in again.', 'info')
        return True
        
    session['last_activity'] = datetime.utcnow().timestamp()
    return False

@app.before_request
def before_request():
    if current_user.is_authenticated:
        if check_session_timeout():
            return redirect(url_for('login'))
        token = session.get('jwt_token')
        if token and verify_token(token) is None:
            new_token = generate_token(current_user.id)
            session['jwt_token'] = new_token

            
def login_timeout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if check_session_timeout():
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        check_session_timeout()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/home')
@login_required
@login_timeout_required
def home():
    current_user.update_last_seen()
    
    # Get unread messages count
    unread_messages = Message.query.filter_by(
        receiver_id=current_user.id,
        is_read=False
    ).count()
    
    # Get recent messages
    recent_messages = Message.query.filter(
        ((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.desc()).limit(5).all()
    
    # Get all users for quick message
    users = User.query.filter(User.id != current_user.id).all()
    
    return render_template('home.html',
                         unread_messages=unread_messages,
                         recent_messages=recent_messages,
                         users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('This account has been deactivated. Please contact support.', 'error')
                return redirect(url_for('login'))
                
            login_user(user, remember=remember)
            session.permanent = True
            session['last_activity'] = datetime.utcnow().timestamp()
            
            # Generate and store JWT token
            token = generate_token(user.id)
            session['jwt_token'] = token
            
            user.update_last_seen()
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        
        flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another email.', 'error')
            return redirect(url_for('signup'))
        
        new_user = User(
            username=username,
            email=email,
            last_seen=datetime.utcnow(),
            is_active=True
        )
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Registration error: {e}")
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    current_user.update_last_seen()
    logout_user()
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

def init_db():
    with app.app_context():
        try:
            #db.drop_all()
            db.create_all()
            print("Database initialized successfully!")
        except Exception as e:
            print(f"Error initializing database: {e}")






@app.route('/upload_photo', methods=['POST'])
@login_required
def upload_photo():
    if 'photo' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['photo']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"user_{current_user.id}_{file.filename}")
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Update user's profile photo
        current_user.profile_photo = filename
        db.session.commit()
        
        flash('Profile photo updated successfully', 'success')
    else:
        flash('Invalid file type. Please upload an image file.', 'error')
    
    return redirect(url_for('profile'))

# Add these new routes
@app.route('/chat')
@login_required
def chat():
    # Mark user as online
    current_user.is_online = True
    db.session.commit()
    
    # Get latest messages and unread counts
    latest_messages = db.session.query(
        Message,
        func.row_number().over(
            partition_by=case(
                (Message.sender_id == current_user.id, Message.receiver_id),
                else_=Message.sender_id
            ),
            order_by=Message.timestamp.desc()
        ).label('rn')
    ).subquery()
    
    message_previews = db.session.query(latest_messages).filter(
        latest_messages.c.rn == 1
    ).all()
    
    # Get unread counts
    unread_counts = db.session.query(
        Message.sender_id,
        func.count(Message.id).label('unread')
    ).filter(
        Message.receiver_id == current_user.id,
        Message.is_read == False
    ).group_by(Message.sender_id).all()
    
    # Get users and rooms
    users = User.query.filter(User.id != current_user.id).all()
    rooms = ChatRoom.query.join(RoomMembers).filter(
        RoomMembers.user_id == current_user.id
    ).all()
    
    # Add public rooms
    public_rooms = ChatRoom.query.filter_by(is_private=False).all()
    rooms.extend([room for room in public_rooms if room not in rooms])
    
    # Create user previews
    user_previews = [{
        'user': user,
        'last_message': next((msg for msg in message_previews if 
            msg.sender_id == user.id or msg.receiver_id == user.id), None),
        'unread_count': next((count.unread for count in unread_counts if 
            count.sender_id == user.id), 0)
    } for user in users]
    
    return render_template('chat.html', 
                         user_previews=user_previews,
                         rooms=rooms)

@app.route('/chat/room/<int:room_id>')
@login_required
def chat_room(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    
    if room.is_private:
        member = RoomMembers.query.filter_by(room_id=room_id, user_id=current_user.id).first()
        if not member:
            flash('This is a private chat room. You do not have access.', 'error')
            return redirect(url_for('chat'))
            
    # Auto-join public rooms if not already a member
    if not room.is_private:
        member = RoomMembers.query.filter_by(room_id=room_id, user_id=current_user.id).first()
        if not member:
            new_member = RoomMembers(user_id=current_user.id, room_id=room_id)
            db.session.add(new_member)
            db.session.commit()
    
    messages = RoomMessage.query.filter_by(room_id=room_id).order_by(RoomMessage.timestamp).all()
    return render_template('chat_room.html', room=room, messages=messages)

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    try:
        name = request.form.get('name')
        is_group = request.form.get('is_group', 'false') == 'true'
        member_ids = request.form.getlist('members')

        # Private chats are always private, Group chats can be public/private
        is_private = True if not is_group else request.form.get('is_private', 'false') == 'true'

        room = ChatRoom(
            name=name,
            is_group=is_group,
            is_private=is_private,
            created_by_id=current_user.id
        )
        db.session.add(room)
        db.session.flush()
        
        room_members = [RoomMembers(
            user_id=current_user.id,
            room_id=room.id,
            is_admin=True
        )]
        
        if member_ids:
            for member_id in member_ids:
                if member_id.isdigit():
                    room_members.append(RoomMembers(
                        user_id=int(member_id),
                        room_id=room.id,
                        is_admin=False
                    ))
        
        db.session.add_all(room_members)
        db.session.commit()
        
        return redirect(url_for('chat_room', room_id=room.id))
        
    except Exception as e:
        db.session.rollback()
        return redirect(url_for('chat'))
    
# Add Socket.IO event handlers
# Update the Socket.IO event handlers
@socketio.on('join')
def on_join(data):
    if current_user.is_authenticated:
        room = data.get('room')
        if not room:
            return
            
        # Join main room
        join_room(room)
        
        # Join user's personal room
        join_room(f"user_{current_user.id}")
        
        # Handle room types
        if 'room_id' in data:
            join_room(f"room_{data['room_id']}")
        else:
            # Join private chat room
            other_user_id = data.get('other_user_id')
            if other_user_id:
                join_room(f"private_{current_user.id}_{other_user_id}")
                join_room(f"private_{other_user_id}_{current_user.id}")

        emit('status', {
            'msg': f'{current_user.username} has joined.',
            'user': current_user.username,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }, to=room)
        
@socketio.on('leave')
def on_leave(data):
    """Handle user leaving a room"""
    if current_user.is_authenticated:
        room = data.get('room')
        if room:
            leave_room(room)
            emit('status', {
                'msg': f'{current_user.username} has left the room.',
                'user': current_user.username,
                'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    if current_user.is_authenticated:
        try:
            if 'room_id' in data:  # Group message
                room_message = RoomMessage(
                    content=data['message'],
                    room_id=data['room_id'],
                    sender_id=current_user.id
                )
                db.session.add(room_message)
                db.session.commit()

                message_data = {
                    'id': room_message.id,
                    'content': room_message.content,
                    'sender_id': room_message.sender_id,
                    'sender_name': current_user.username,
                    'timestamp': room_message.timestamp.isoformat(),
                    'room_id': room_message.room_id
                }

                # Emit the message to all room members
                emit('new_message', message_data, to=f"room_{data['room_id']}", broadcast=True)
            else:  # Private message
                receiver = User.query.get(data['receiver_id'])
                initial_status = 'delivered' if receiver and receiver.is_online else 'sent'
                
                message = Message(
                    content=data['message'],
                    sender_id=current_user.id,
                    receiver_id=data['receiver_id'],
                    status=initial_status,
                    is_read=False
                )
                db.session.add(message)
                db.session.commit()

                message_data = {
                    'id': message.id,
                    'content': message.content,
                    'sender_id': message.sender_id,
                    'sender_name': current_user.username,
                    'receiver_id': data['receiver_id'],
                    'timestamp': message.timestamp.isoformat(),
                    'status': initial_status,
                    'is_read': False
                }

                # Emit to both private rooms
                private_room = f"private_{current_user.id}_{data['receiver_id']}"
                emit('new_message', message_data, to=private_room)
                emit('new_message', message_data, to=f"private_{data['receiver_id']}_{current_user.id}")

        except Exception as e:
            print(f"Error sending message: {e}")
            db.session.rollback()
            emit('error', {'message': 'Failed to send message'})

@socketio.on('message_received')
def handle_message_received(data):
    if current_user.is_authenticated:
        message = Message.query.get(data['message_id'])
        if message and message.receiver_id == current_user.id:
            message.status = 'delivered'
            db.session.commit()
            
            private_room = f"private_{message.sender_id}_{message.receiver_id}"
            emit('message_status_update', {
                'message_id': message.id,
                'status': 'delivered',
                'is_read': message.is_read
            }, to=private_room)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if current_user.is_authenticated:
        try:
            message = Message.query.get(data['message_id'])
            if message and message.receiver_id == current_user.id:
                message.is_read = True
                db.session.commit()
                
                private_room = f"private_{message.sender_id}_{message.receiver_id}"
                emit('message_status_update', {
                    'message_id': message.id,
                    'status': 'delivered',
                    'is_read': True
                }, to=private_room)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error marking message as read: {e}")
            emit('error', {'message': 'Failed to mark message as read'})

@socketio.on('message_received')
def handle_message_received(data):
    """Handle message received confirmation"""
    if current_user.is_authenticated:
        message = Message.query.get(data['message_id'])
        if message and message.receiver_id == current_user.id:
            message.status = 'delivered'
            db.session.commit()
            
            # Notify sender about delivery
            private_room = f"private_{message.sender_id}_{message.receiver_id}"
            emit('message_status_update', {
                'message_id': message.id,
                'status': 'delivered'
            }, to=private_room)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    """Handle message read receipts"""
    if current_user.is_authenticated:
        try:
            if isinstance(data['message_id'], list):
                # Handle multiple messages
                messages = Message.query.filter(
                    Message.id.in_(data['message_id']),
                    Message.receiver_id == current_user.id,
                    Message.status != 'read'
                ).all()
                
                for message in messages:
                    message.status = 'read'
                    message.is_read = True  # Update both fields
                    private_room = f"private_{message.sender_id}_{message.receiver_id}"
                    emit('message_status_update', {
                        'message_id': message.id,
                        'status': 'read'
                    }, to=private_room)
            else:
                # Handle single message
                message = Message.query.get(data['message_id'])
                if message and message.receiver_id == current_user.id:
                    message.status = 'read'
                    message.is_read = True  # Update both fields
                    private_room = f"private_{message.sender_id}_{message.receiver_id}"
                    emit('message_status_update', {
                        'message_id': message.id,
                        'status': 'read'
                    }, to=private_room)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error marking message as read: {e}")
            emit('error', {'message': 'Failed to mark message as read'})

            
@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicators"""
    if current_user.is_authenticated:
        if 'room_id' in data:
            emit('user_typing', {
                'user_id': current_user.id,
                'username': current_user.username
            }, room=str(data['room_id']))
        else:
            emit('user_typing', {
                'user_id': current_user.id,
                'username': current_user.username
            }, room=str(data['receiver_id']))

@socketio.on('stop_typing')
def handle_stop_typing(data):
    """Handle stop typing indicators"""
    if current_user.is_authenticated:
        if 'room_id' in data:
            emit('user_stop_typing', {
                'user_id': current_user.id
            }, room=str(data['room_id']))
        else:
            emit('user_stop_typing', {
                'user_id': current_user.id
            }, room=str(data['receiver_id']))


@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.is_online = True
        db.session.commit()
        join_room(str(current_user.id))
        # Broadcast updated status to all users
        emit('user_online', {'user_id': current_user.id}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_offline', {'user_id': current_user.id}, broadcast=True)

@app.route('/chat/<int:user_id>')
@login_required
def private_chat(user_id):
    other_user = User.query.get_or_404(user_id)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    current_user.mark_messages_as_read(user_id)
    
    return render_template('private_chat.html', other_user=other_user, messages=messages)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            username = request.form.get('username')
            email = request.form.get('email')
            
            if User.query.filter(User.id != current_user.id, User.username == username).first():
                flash('Username already taken', 'error')
                return redirect(url_for('profile'))
                
            if User.query.filter(User.id != current_user.id, User.email == email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('profile'))
                
            current_user.username = username
            current_user.email = email
            
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
                
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('profile'))
                
            current_user.set_password(new_password)
            flash('Password updated successfully', 'success')
            
        elif action == 'update_photo':
            if 'photo' not in request.files:
                flash('No photo selected', 'error')
                return redirect(url_for('profile'))
                
            file = request.files['photo']
            if file.filename == '':
                flash('No photo selected', 'error')
                return redirect(url_for('profile'))
                
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.id}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.profile_photo = filename
                
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
        
    return render_template('profile.html')


# Update the main section
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
