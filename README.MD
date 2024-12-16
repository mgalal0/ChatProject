# Flask Chat Application

A real-time chat application built with Flask, Socket.IO, and SQLAlchemy, featuring private messaging, group chats, and user management.

## Features

- 👥 User Authentication & Management
  - User registration and login
  - Profile management with photo upload
  - Password change functionality
  - Session management with timeout
  - Last seen and online status

- 💬 Messaging Features
  - Real-time private messaging
  - Group chat rooms
  - Message status tracking (sent, delivered, read)
  - Typing indicators
  - Unread message counters
  - Message history

- 🔐 Security
  - JWT token authentication
  - Password hashing
  - Session timeout management
  - Secure file uploads

- 👥 Group Chat Features
  - Create public/private rooms
  - Room member management
  - Admin controls
  - Join/leave notifications

## Technologies Used

- **Backend**: Flask, Python
- **Database**: MySQL with SQLAlchemy ORM
- **Real-time Communication**: Socket.IO
- **Authentication**: Flask-Login, JWT
- **File Handling**: Werkzeug
- **Security**: Password hashing, JWT tokens

## Prerequisites

- Python 3.x
- MySQL Server
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd flask-chat
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Configure MySQL database:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/chatproject'
```

5. Initialize the database:
```bash
python app.py
```

## Project Structure

```
flask-chat/
├── static/
│   └── uploads/        # User uploaded files
├── templates/          # HTML templates
├── app.py             # Main application file
├── requirements.txt   # Project dependencies
└── README.md
```

## Key Components

### Models

- `User`: User account management
- `Message`: Private message handling
- `ChatRoom`: Group chat room management
- `RoomMembers`: Room membership tracking
- `RoomMessage`: Group chat messages

### Socket.IO Events

- `join`: Handle user joining chat rooms
- `leave`: Handle user leaving chat rooms
- `send_message`: Message transmission
- `message_received`: Delivery confirmation
- `mark_as_read`: Read receipts
- `typing`: Typing indicators
- `connect/disconnect`: Online status management

## Security Features

1. Session Management:
   - 30-minute session timeout
   - JWT token authentication
   - Automatic session renewal

2. Password Security:
   - Password hashing
   - Minimum password length
   - Password confirmation

3. File Upload Security:
   - File type validation
   - Secure filename handling
   - Size limitations

## Configuration

Key configuration options in `app.py`:

```python
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
```

## Running the Application

```bash
python app.py
```
The application will be available at `http://localhost:5000`

## Error Handling

The application includes handlers for:
- 404 Not Found errors
- 500 Internal Server errors
- Database transaction errors
- File upload errors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## License

Copyright Mahmoud Galal © 2024. All rights reserved.

## Support

For support, please open an issue in the repository or contact with me.