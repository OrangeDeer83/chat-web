
import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, send, emit

# App Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions Initialization
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def __repr__(self):
        return f"Message('{self.content}' from {self.sender.username} to {self.recipient.username})"

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

connected_users = {}

# SocketIO Events
@socketio.on('connect')
@login_required
def handle_connect():
    connected_users[current_user.id] = request.sid
    users = User.query.all()
    users_list = [{'id': user.id, 'username': user.username} for user in users]
    emit('user_list', users_list, broadcast=True)

@socketio.on('disconnect')
@login_required
def handle_disconnect():
    if current_user.id in connected_users:
        del connected_users[current_user.id]
    # Re-broadcast user list on disconnect
    users = User.query.all()
    users_list = [{'id': user.id, 'username': user.username} for user in users]
    emit('user_list', users_list, broadcast=True)

@socketio.on('send_message')
@login_required
def handle_send_message(data):
    recipient_id = int(data['recipient_id'])
    message_content = data['message']

    message = Message(sender_id=current_user.id, recipient_id=recipient_id, content=message_content)
    db.session.add(message)
    db.session.commit()

    recipient_sid = connected_users.get(recipient_id)
    sender_sid = request.sid
    
    payload = {'msg': message_content, 'sender': current_user.username}

    if recipient_sid:
        emit('message', payload, room=recipient_sid)
    # Also send to self
    emit('message', payload, room=sender_sid)

@socketio.on('load_history')
@login_required
def handle_load_history(data):
    recipient_id = int(data['recipient_id'])
    
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == recipient_id),
            (Message.sender_id == recipient_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    messages_data = [
        {'sender': msg.sender.username, 'content': msg.content}
        for msg in messages
    ]
    
    emit('load_messages', {'messages': messages_data})

if __name__ == '__main__':
    socketio.run(app, debug=True)
