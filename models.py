from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# Таблица ролей
class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    users = db.relationship('User', back_populates='role', lazy=True)

# Таблица подразделений
class Department(db.Model):
    __tablename__ = 'departments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)

    users = db.relationship('User', back_populates='department', lazy=True)

# Таблица пользователей
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    position = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    profile_picture = db.Column(db.String(120), nullable=True, default=None)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    department = db.relationship('Department', back_populates='users', lazy=True)
    role = db.relationship('Role', back_populates='users', lazy=True)
    managed_projects = db.relationship('Project', back_populates='manager', lazy=True)
    tasks = db.relationship('TaskUser', back_populates='user', lazy=True)
    comments = db.relationship('Comment', back_populates='user', lazy=True)

    def get_id(self):
        return str(self.id)

# Таблица файлов
class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=True)
    subtask_id = db.Column(db.Integer, db.ForeignKey('subtasks.id', ondelete='CASCADE'), nullable=True)

    project = db.relationship('Project', backref='files', lazy=True)
    task = db.relationship('Task', backref='files', lazy=True)
    subtask = db.relationship('Subtask', backref='files', lazy=True)

# Таблица запросов на подтверждение
class ConfirmationRequest(db.Model):
    __tablename__ = 'confirmation_requests'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, approved, rejected
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=True)
    subtask_id = db.Column(db.Integer, db.ForeignKey('subtasks.id', ondelete='CASCADE'), nullable=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)

    task = db.relationship('Task', backref='confirmation_requests', lazy=True)
    subtask = db.relationship('Subtask', backref='confirmation_requests', lazy=True)
    requested_by = db.relationship('User', foreign_keys=[requested_by_id], lazy=True)
    resolved_by = db.relationship('User', foreign_keys=[resolved_by_id], lazy=True)

# Промежуточная таблица для задач и пользователей
class TaskUser(db.Model):
    __tablename__ = 'task_users'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))

    task = db.relationship('Task', back_populates='assigned_users', lazy=True)
    user = db.relationship('User', back_populates='tasks', lazy=True)

# Таблица задач
class Task(db.Model):
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'))
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status_id = db.Column(db.Integer, db.ForeignKey('task_statuses.id'), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.Date)

    status = db.relationship('TaskStatus', back_populates='tasks', lazy=True)
    comments = db.relationship('Comment', back_populates='task', lazy=True)
    assigned_users = db.relationship('TaskUser', back_populates='task', lazy=True)
    subtasks = db.relationship('Subtask', back_populates='parent_task', lazy=True)


# Таблица статусов задач
class TaskStatus(db.Model):
    __tablename__ = 'task_statuses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    tasks = db.relationship('Task', back_populates='status', lazy=True)
    subtasks = db.relationship('Subtask', back_populates='status', lazy=True)


# Таблица подзадач
class Subtask(db.Model):
    __tablename__ = 'subtasks'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id', ondelete='CASCADE'))
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status_id = db.Column(db.Integer, db.ForeignKey('task_statuses.id'), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.Date)

    status = db.relationship('TaskStatus', back_populates='subtasks', lazy=True)
    parent_task = db.relationship('Task', back_populates='subtasks', lazy=True)
    assigned_users = db.relationship('SubtaskUser', back_populates='subtask', lazy=True)

# Промежуточная таблица для подзадач и пользователей
class SubtaskUser(db.Model):
    __tablename__ = 'subtask_users'

    id = db.Column(db.Integer, primary_key=True)
    subtask_id = db.Column(db.Integer, db.ForeignKey('subtasks.id', ondelete='CASCADE'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))

    subtask = db.relationship('Subtask', back_populates='assigned_users', lazy=True)
    user = db.relationship('User', lazy=True)


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
    status = db.relationship('ProjectStatus', backref='projects', lazy='joined')  # Добавляем связь с таблицей project_statuses

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

    user = db.relationship('User', back_populates='comments')
    task = db.relationship('Task', back_populates='comments')


# Функция для создания базы данных
def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()
