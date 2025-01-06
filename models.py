from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# Таблица пользователей
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # Связь с проектами, где пользователь является менеджером
    managed_projects = db.relationship('Project', back_populates='manager', lazy=True)
    tasks = db.relationship('Task', backref='assigned_user', lazy=True)

    @property
    def is_active(self):
        # Возвращает True, если пользователь активен
        return True  # Здесь вы можете использовать логику, основанную на ваших данных, например, проверять статус

    @property
    def is_authenticated(self):
        # Flask-Login автоматически добавляет этот метод через UserMixin
        return True

    @property
    def is_anonymous(self):
        # Flask-Login автоматически добавляет этот метод через UserMixin
        return False

    def get_id(self):
        return str(self.id)


# Таблица статусов проектов
class ProjectStatus(db.Model):
    __tablename__ = 'project_statuses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# Таблица проектов
class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.Date)
    manager_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    status_id = db.Column(db.Integer, db.ForeignKey('project_statuses.id'), nullable=False)

    # Связи
    tasks = db.relationship('Task', backref='project', lazy=True)
    participants = db.relationship('ProjectUser', backref='project', lazy=True)
    manager = db.relationship('User', back_populates='managed_projects', lazy=True)

# Таблица статусов задач
class TaskStatus(db.Model):
    __tablename__ = 'task_statuses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# Таблица задач
class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'))
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status_id = db.Column(db.Integer, db.ForeignKey('task_statuses.id'), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=1)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.Date)

    # Связь с комментариями
    status = db.relationship('TaskStatus', backref='tasks', lazy=True)
    comments = db.relationship('Comment', backref='task', lazy=True)

# Таблица участников проектов
class ProjectUser(db.Model):
    __tablename__ = 'project_users'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    role = db.Column(db.String(50), nullable=False)

# Таблица комментариев
class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Добавляем связь с пользователем
    user = db.relationship('User', backref='comments', lazy=True)  # Связь с User


# Функция для создания базы данных
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
