import hashlib
from hashlib import sha256
from flask_login import login_user, logout_user
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from models import *
from functools import wraps

auth_routes = Blueprint('auth_routes', __name__)
main_routes = Blueprint('main_routes', __name__)

UPLOAD_FOLDER = 'static/projects'  # Папка для загрузки файлов проектов
USER_FOLDER = 'static/users'  # Папка для данных пользователей
os.makedirs(USER_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@auth_routes.route('/')
def root():
    return redirect(url_for('auth_routes.login'))


# Декоратор для проверки роли администратора
def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.role or current_user.role.name != 'admin':
            abort(403)  # Доступ запрещен
        return func(*args, **kwargs)
    return decorated_view


# Декоратор для проверки роли менеджера
def manager_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.role or current_user.role.name != 'manager':
            abort(403)  # Доступ запрещен
        return func(*args, **kwargs)
    return decorated_view


# Декоратор для проверки роли пользователя
def user_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.role or current_user.role.name != 'user':
            abort(403)  # Доступ запрещен
        return func(*args, **kwargs)
    return decorated_view


# Функции для хэширования и проверки пароля
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(stored_password_hash, provided_password):
    return stored_password_hash == hashlib.sha256(provided_password.encode('utf-8')).hexdigest()


# Маршрут для входа
@auth_routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.password_hash, password):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            if user.role.name == 'admin':
                return redirect(url_for('main_routes.admin_dashboard'))
            elif user.role.name == 'manager':
                return redirect(url_for('main_routes.manager_dashboard'))
            elif user.role.name == 'user':
                return redirect(url_for('main_routes.user_dashboard'))
        else:
            flash('Неверное имя пользователя или пароль.', 'danger')
    return render_template('login.html')


# Маршрут для выхода
@auth_routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('auth_routes.login'))


@main_routes.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create_user':
            # Создание пользователя
            username = request.form.get('username')
            full_name = request.form.get('full_name')
            password = request.form.get('password')
            department_id = request.form.get('department_id')
            role_id = request.form.get('role_id')

            # Проверка обязательных полей
            if not all([username, full_name, password, department_id, role_id]):
                flash('Заполните все обязательные поля!', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            # Хэширование пароля
            password_hash = sha256(password.encode('utf-8')).hexdigest()

            # Проверка на уникальность логина
            if User.query.filter_by(username=username).first():
                flash('Пользователь с таким логином уже существует.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            # Создание нового пользователя
            new_user = User(
                username=username,
                full_name=full_name,
                password_hash=password_hash,
                department_id=department_id,
                role_id=role_id
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан!', 'success')

        elif action == 'edit_user':
            # Редактирование пользователя
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)

            if not user:
                flash('Пользователь не найден.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            user.username = request.form.get('username') or user.username
            user.full_name = request.form.get('full_name') or user.full_name
            user.department_id = request.form.get('department_id') or user.department_id
            user.role_id = request.form.get('role_id') or user.role_id

            if request.form.get('password'):
                user.password_hash = sha256(request.form.get('password').encode('utf-8')).hexdigest()

            db.session.commit()
            flash('Пользователь успешно обновлен!', 'success')

        elif action == 'delete_user':
            # Удаление пользователя
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)

            if not user:
                flash('Пользователь не найден.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            db.session.delete(user)
            db.session.commit()
            flash('Пользователь успешно удален!', 'success')

        elif action == 'create_department':
            # Создание подразделения
            name = request.form.get('name')
            description = request.form.get('description')

            if not name:
                flash('Название подразделения обязательно!', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            if Department.query.filter_by(name=name).first():
                flash('Подразделение с таким названием уже существует.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_department = Department(name=name, description=description)
            db.session.add(new_department)
            db.session.commit()
            flash('Подразделение успешно создано!', 'success')

        elif action == 'edit_department':
            # Редактирование подразделения
            department_id = request.form.get('department_id')
            department = Department.query.get(department_id)

            if not department:
                flash('Подразделение не найдено.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            department.name = request.form.get('name') or department.name
            department.description = request.form.get('description') or department.description

            db.session.commit()
            flash('Подразделение успешно обновлено!', 'success')

        elif action == 'delete_department':
            # Удаление подразделения
            department_id = request.form.get('department_id')
            department = Department.query.get(department_id)

            if not department:
                flash('Подразделение не найдено.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            db.session.delete(department)
            db.session.commit()
            flash('Подразделение успешно удалено!', 'success')

        elif action == 'create_project':
            # Создание проекта
            name = request.form.get('name')
            description = request.form.get('description')
            manager_id = request.form.get('manager_id')
            status_id = request.form.get('status_id')
            deadline = request.form.get('deadline')

            if not all([name, description, manager_id, status_id, deadline]):
                flash('Заполните все обязательные поля для проекта!', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_project = Project(
                name=name,
                description=description,
                manager_id=manager_id,
                status_id=status_id,
                deadline=deadline
            )
            db.session.add(new_project)
            db.session.commit()
            flash('Проект успешно создан!', 'success')

        elif action == 'edit_project':
            # Редактирование проекта
            project_id = request.form.get('project_id')
            project = Project.query.get(project_id)

            if not project:
                flash('Проект не найден.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            project.name = request.form.get('name') or project.name
            project.description = request.form.get('description') or project.description
            project.manager_id = request.form.get('manager_id') or project.manager_id
            project.status_id = request.form.get('status_id') or project.status_id
            project.deadline = request.form.get('deadline') or project.deadline

            db.session.commit()
            flash('Проект успешно обновлен!', 'success')

        elif action == 'delete_project':
            # Удаление проекта
            project_id = request.form.get('project_id')
            project = Project.query.get(project_id)

            if not project:
                flash('Проект не найден.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            db.session.delete(project)
            db.session.commit()
            flash('Проект успешно удален!', 'success')

    # Получение списка пользователей, ролей, подразделений и проектов для отображения
    users = User.query.all()
    roles = Role.query.all()
    departments = Department.query.all()
    projects = Project.query.all()
    statuses = ProjectStatus.query.all()

    return render_template('admin_dashboard.html', users=users, roles=roles, departments=departments, projects=projects, statuses=statuses)
