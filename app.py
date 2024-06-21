import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_login import current_user
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_

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


class MCQQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(255), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    options = db.relationship('MCQOption', backref='question', lazy=True)


class MCQOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.String(100), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    question_id = db.Column(db.Integer, db.ForeignKey('mcq_question.id'), nullable=False)


class MCQAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('mcq_question.id'), nullable=False)
    answer_option_id = db.Column(db.Integer, db.ForeignKey('mcq_option.id'), nullable=False)

    answer_option = db.relationship('MCQOption', backref='answers')


class StudentPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    points = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref=db.backref('student_points', lazy=True))
    group = db.relationship('Group', backref=db.backref('student_points', lazy=True))


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
                        Slide.id).first()
            elif direction == 'previous':
                next_slide = Slide.query.filter(Slide.id < current_slide.id, Slide.group_id == group_id).order_by(
                    Slide.id.desc()).first()
                if not next_slide:
                    next_slide = Slide.query.filter(Slide.group_id == group_id).order_by(
                        Slide.id.desc()).first()

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




@app.route('/add_mcq_question', methods=['GET', 'POST'])
@login_required
def add_mcq_question():
    if request.method == 'POST':
        group_id = request.form['group_id']
        content = request.form['content']
        options = request.form.getlist('options')
        correct_option = request.form['correct_option']

        new_mcq_question = MCQQuestion(question_text=content, group_id=group_id)
        db.session.add(new_mcq_question)
        db.session.commit()

        for option in options:
            is_correct = option == correct_option
            new_mcq_answer = MCQOption(option_text=option, is_correct=is_correct, question_id=new_mcq_question.id)
            db.session.add(new_mcq_answer)

        db.session.commit()
        flash('MCQ Question added successfully', 'success')
    groups = Group.query.all()
    return render_template('add_mcq_question.html', groups=groups)


@app.route('/answer_mcq_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def answer_mcq_question(question_id):
    question = MCQQuestion.query.get_or_404(question_id)
    if request.method == 'POST':
        selected_option = request.form['option']
        answer = MCQAnswer.query.filter_by(content=selected_option, question_id=question_id).first()

        if answer and answer.is_correct:
            points_entry = StudentPoints.query.filter_by(user_id=current_user.id, group_id=question.group_id).first()
            if not points_entry:
                points_entry = StudentPoints(user_id=current_user.id, group_id=question.group_id, points=0)
                db.session.add(points_entry)

            points_entry.points += 1
            db.session.commit()
            flash('Correct answer! You have been awarded a point.', 'success')
        else:
            flash('Incorrect answer. Try again.', 'danger')

    return render_template('answer_mcq_question.html', question=question, current_group_id=question_id)


@app.route('/view_points', methods=['GET'])
@login_required
def view_points():
    points = StudentPoints.query.filter_by(user_id=current_user.id).all()
    return render_template('view_points.html', points=points)


@app.route('/admin_question/<int:group_id>', methods=['GET', 'POST'])
@login_required
def admin_question(group_id):
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))

    current_question = MCQQuestion.query.filter_by(group_id=group_id).first()

    return render_template('admin_question.html', current_group_id=group_id,
                           current_question=current_question)


@socketio.on('change_question')
def handle_change_question(data):
    group_id = data['group_id']
    direction = data['direction']

    current_question_id = session.get('current_question_id')
    if current_question_id:
        current_question = MCQQuestion.query.filter(MCQQuestion.id ==current_question_id).first()
    else:
        current_question = MCQQuestion.query.filter_by(group_id=group_id).first()

    if current_question:
        if direction == 'next':
            next_question = MCQQuestion.query.filter(MCQQuestion.id > current_question.id,
                                                     MCQQuestion.group_id == group_id).order_by(MCQQuestion.id).first()
            if not next_question:
                next_question = MCQQuestion.query.filter(MCQQuestion.group_id == group_id).order_by(
                    MCQQuestion.id).first()
        elif direction == 'previous':
            next_question = MCQQuestion.query.filter(MCQQuestion.id < current_question.id,
                                                     MCQQuestion.group_id == group_id).order_by(
                MCQQuestion.id.desc()).first()
            if not next_question:
                next_question = MCQQuestion.query.filter(MCQQuestion.group_id == group_id).order_by(
                    MCQQuestion.id.desc()).first()

        if next_question:
            session['current_question_id'] = next_question.id
            socketio.emit('question_changed',
                          {'question_id': next_question.id, 'question_text': next_question.question_text},
                          room=group_id)

            options = [{'id': option.id, 'option_text': option.option_text} for option in next_question.options]
            socketio.emit('new_question',
                          {'question': next_question.question_text, 'id': next_question.id, 'options': options},
                          room=group_id)
        else:
            socketio.emit('status', {'msg': 'No more questions in this direction.'}, room=group_id)
    else:
        socketio.emit('status', {'msg': 'No current question found.'}, room=group_id)


@socketio.on('submit_answer')
def handle_submit_answer(data):
    answer_id = data['answer_id']
    group_id = data['group_id']
    question_id = data['question_id']
    current_user_id = current_user.id

    answer_option = MCQOption.query.filter(MCQOption.id ==answer_id).first()

    if not question_id:
        emit('answer_status', {'msg': 'No active question.', 'answer_id': answer_id}, room=current_user_id)
        return

    if answer_option:
        new_ans = MCQAnswer.query.filter(
            and_(MCQAnswer.user_id == current_user_id, MCQAnswer.question_id == question_id)
        ).first()

        if new_ans:
            answer_id = new_ans.id
        else:
            new_answer = MCQAnswer(user_id=current_user_id, question_id=question_id, answer_option_id=answer_option.id)
            db.session.add(new_answer)
            db.session.commit()
            answer_id = new_answer.id

        emit('answer_status', {'msg': 'Answer submitted successfully!', 'answer_id': answer_id}, room=group_id)
        emit_update_answers(question_id, group_id)

def emit_update_answers(question_id, group_id):
    question = MCQQuestion.query.filter(MCQQuestion.id ==question_id).filter()

    if not question:
        emit('user_answers', {'users': [], 'user_answers': []}, room=group_id)
        return

    answers = MCQAnswer.query.filter_by(question_id=question_id).all()

    users = User.query.all()

    user_answers = []

    for user in users:
        for answer in answers:
            if answer.user_id == user.id:
                option_text = answer.answer_option.option_text if answer.answer_option else 'No answer'
                is_correct = answer.answer_option.is_correct if answer.answer_option else False

                user_answer = {
                    'user_id': user.id,
                    'username': user.username,
                    'option': option_text,
                    'is_correct': is_correct
                }
                user_answers.append(user_answer)
                break

        # if not answer_found:
        #     user_answer = {
        #         'user_id': user.id,
        #         'username': user.username,
        #         'option': 'No answer',
        #         'is_correct': False
        #     }
        #     user_answers.append(user_answer)

    # users_dict = [{'id': user.id, 'username': user.username} for user in users]

    emit('user_answers', {'user_answers': user_answers}, room=group_id)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
