from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost:5432/slideapp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(10), default='offline')
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    groups = db.relationship('Group', secondary='user_groups', backref='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    shortcode = db.Column(db.String(8), unique=True, nullable=False)


class Slide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(128), nullable=False)
    current = db.Column(db.Boolean, default=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    group = db.relationship('Group', backref=db.backref('slides', lazy=True))


class UserGroup(db.Model):
    __tablename__ = 'user_groups'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)


class Messages(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    content = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('member'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        group_id = request.form['group_id']
        session['current_group_id'] = group_id
        return redirect(url_for('admin'))

    groups = Group.query.all()
    current_group_id = session.get('current_group_id')
    return render_template('admin.html', groups=groups, current_group_id=current_group_id)


@app.route('/member', methods=['GET', 'POST'])
@login_required
def member():
    return render_template('member_slide.html')


@app.route('/member_group', methods=['GET', 'POST'])
@login_required
def member_group():
    return render_template('member.html')


@app.route('/change_slide')
@login_required
def change_slide():
    if current_user.is_admin:
        group = Group.query.all()
        return render_template('change_slide.html', groups=group)


@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        shortcode = request.form['shortcode']
        existing_group = Group.query.filter_by(name=name).first()
        if existing_group:
            flash('Group name already exists', 'danger')
        else:
            new_group = Group(name=name, shortcode=shortcode)
            db.session.add(new_group)
            db.session.commit()
            flash('Group created successfully', 'success')
    return render_template('create_group.html')


@socketio.on('change_slide')
def handle_change_slide(data):
    group_id = data['group_id']
    direction = data['direction']
    user = User.query.get(current_user.id)

    if user.is_admin:
        current_slide = Slide.query.filter_by(current=True, group_id=group_id).first()

        if current_slide:
            if direction == 'next':
                next_slide = Slide.query.filter(Slide.id > current_slide.id, Slide.group_id == group_id).order_by(
                    Slide.id).first()
                if not next_slide:
                    next_slide = Slide.query.filter(Slide.group_id == group_id).order_by(
                        Slide.id).first()  # Wrap around to the first slide
            elif direction == 'previous':
                next_slide = Slide.query.filter(Slide.id < current_slide.id, Slide.group_id == group_id).order_by(
                    Slide.id.desc()).first()
                if not next_slide:
                    next_slide = Slide.query.filter(Slide.group_id == group_id).order_by(
                        Slide.id.desc()).first()  # Wrap around to the last slide

            if next_slide:
                current_slide.current = False
                next_slide.current = True
                db.session.commit()
                emit('slide_changed', {'slide': next_slide.image}, room=group_id)
                print(f"Slide changed to {next_slide.image} in group {group_id} by admin")
            else:
                print(f"No {direction} slide found in group {group_id}")
        else:
            print(f"No current slide found in group {group_id}")
    else:
        emit('status', {'msg': 'Only admins can change slides.'}, room=request.sid)
        print("Slide change request denied. User is not an admin.")


@app.route('/add_slide_to_group', methods=['GET', 'POST'])
@login_required
def add_slide_to_group():
    if request.method == 'POST':
        image = request.form['image']
        group_id = request.form['group_id']
        group = Group.query.get(group_id)
        if group:
            new_slide = Slide(image=image, group_id=group_id)
            db.session.add(new_slide)
            db.session.commit()
            flash('Slide added to group successfully', 'success')
        else:
            flash('Group not found', 'danger')
    return render_template('add_slide_to_group.html')


@app.route('/chat/<int:groupid>', methods=['GET'])
@login_required
def chat(groupid):
    group = Group.query.filter(Group.id == groupid).first()
    messages = Messages.query.filter(Messages.group_id == groupid).all()
    return render_template('chat.html', messages=messages, group=group)


@app.route('/chats')
def chats():
    chats = Group.query.all()
    return render_template('chats.html', chats=chats)


@app.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    if request.method == 'POST':
        group_shortcode = request.form['group_id']
        group = Group.query.filter_by(shortcode=group_shortcode).first()
        if group:
            current_user.groups.append(group)
            db.session.commit()
            flash('Joined group successfully', 'success')
            if current_user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('member'))
        else:
            flash('Group not found', 'danger')

    return render_template('join_group.html')


@socketio.on('join')
def handle_join(data):
    group_id = data['group_id']
    username = current_user.username

    join_room(group_id)
    emit('status', {'msg': f'{username} has joined the room.'}, room=group_id)


@socketio.on('leave')
def handle_leave(data):
    group_id = data['group_id']
    username = current_user.username

    leave_room(group_id)
    emit('status', {'msg': f'{username} has left the room.'}, room=group_id)


@socketio.on('message')
def handle_message(data):
    username = current_user.username
    group_id = data['group_id']
    content = data['content']
    timestamp = datetime.datetime.now()

    new_message = Messages(user_id=current_user.id, group_id=group_id, content=content, timestamp=timestamp)
    db.session.add(new_message)
    db.session.commit()

    emit('message', {
        'username': username,
        'content': content,
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=group_id)


@socketio.on('disconnect')
def handle_disconnect():
    username = current_user.username
    for group in current_user.groups:
        leave_room(group.id)
        emit('status', {'msg': f'{username} has disconnected.'}, room=group.id)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
