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


#Основная страница
@main_routes.route('/main', methods=['GET'])
@login_required
def main():
    # Получение проектов для администратора
    if current_user.role.name == 'admin':
        projects = Project.query.all()

    # Получение проектов для менеджера
    elif current_user.role.name == 'manager':
        managed_projects = Project.query.filter_by(manager_id=current_user.id).all()
        assigned_tasks = Task.query.filter(Task.assigned_users.any(user_id=current_user.id)).all()
        assigned_projects = {task.project for task in assigned_tasks if task.project}
        projects = list(set(managed_projects).union(assigned_projects))

    # Получение проектов для пользователя
    elif current_user.role.name == 'user':
        assigned_tasks = Task.query.filter(Task.assigned_users.any(user_id=current_user.id)).all()
        projects = {task.project for task in assigned_tasks if task.project}

    else:
        projects = []

    return render_template('main.html', projects=projects)


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
            return redirect(url_for('main_routes.main'))
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

        if action == 'add_comment':
            # Добавление комментария администратором
            task_id = request.form.get('task_id')
            content = request.form.get('content')

            if not all([task_id, content]):
                flash('Необходимо указать задачу и текст комментария.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_comment = Comment(
                task_id=task_id,
                user_id=current_user.id,
                content=content
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий успешно добавлен!', 'success')

        if action == 'create_task':
            # Добавление задачи к проекту
            project_id = request.form.get('project_id')
            title = request.form.get('title')
            description = request.form.get('description')
            priority = request.form.get('priority', 1)
            deadline = request.form.get('deadline')
            assigned_user_ids = request.form.getlist('assigned_users')

            if not all([project_id, title]):
                flash('Необходимо указать проект и название задачи.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_task = Task(
                project_id=project_id,
                title=title,
                description=description,
                priority=priority,
                deadline=deadline,
                status_id=1  # Статус по умолчанию "Назначен"
            )
            db.session.add(new_task)
            db.session.flush()

            for user_id in assigned_user_ids:
                task_user = TaskUser(task_id=new_task.id, user_id=user_id)
                db.session.add(task_user)

            db.session.commit()
            flash('Задача успешно добавлена!', 'success')

        elif action == 'create_subtask':
            # Добавление подзадачи к задаче
            task_id = request.form.get('task_id')
            title = request.form.get('title')
            description = request.form.get('description')
            priority = request.form.get('priority', 1)
            deadline = request.form.get('deadline')
            assigned_user_ids = request.form.getlist('assigned_users')

            if not all([task_id, title]):
                flash('Необходимо указать задачу и название подзадачи.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_subtask = Subtask(
                task_id=task_id,
                title=title,
                description=description,
                priority=priority,
                deadline=deadline,
                status_id=1  # Статус по умолчанию "Назначен"
            )
            db.session.add(new_subtask)
            db.session.flush()

            for user_id in assigned_user_ids:
                subtask_user = SubtaskUser(subtask_id=new_subtask.id, user_id=user_id)
                db.session.add(subtask_user)

            db.session.commit()
            flash('Подзадача успешно добавлена!', 'success')

        elif action == 'add_comment':
            # Добавление комментария к задаче
            task_id = request.form.get('task_id')
            content = request.form.get('content')

            if not all([task_id, content]):
                flash('Необходимо указать задачу и текст комментария.', 'danger')
                return redirect(url_for('main_routes.admin_dashboard'))

            new_comment = Comment(
                task_id=task_id,
                user_id=current_user.id,
                content=content,
                created_at=datetime.utcnow()
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий успешно добавлен!', 'success')

        elif action == 'edit_comment':
            # Редактирование собственного комментария
            comment_id = request.form.get('comment_id')
            content = request.form.get('content')

            comment = Comment.query.filter_by(id=comment_id, user_id=current_user.id).first()

            if not comment:
                flash('Комментарий не найден или вы не можете его редактировать.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            if not content:
                flash('Текст комментария не может быть пустым.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            comment.content = content
            db.session.commit()
            flash('Комментарий успешно отредактирован!', 'success')

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

    return render_template('admin_dashboard.html', users=users, roles=roles, departments=departments,
                           projects=projects, statuses=statuses)


@main_routes.route('/manager/dashboard', methods=['GET', 'POST'])
@login_required
@manager_required
def manager_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_comment':
            # Добавление комментария менеджером
            task_id = request.form.get('task_id')
            content = request.form.get('content')

            task = Task.query.filter_by(id=task_id, project_id=current_user.id).first()

            if not task or not content:
                flash('Вы не можете комментировать эту задачу.', 'danger')
                return redirect(url_for('main_routes.manager_dashboard'))

            new_comment = Comment(
                task_id=task_id,
                user_id=current_user.id,
                content=content,
                created_at=datetime.utcnow()
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий успешно добавлен!', 'success')

        elif action == 'edit_comment':
            # Редактирование собственного комментария
            comment_id = request.form.get('comment_id')
            content = request.form.get('content')

            comment = Comment.query.filter_by(id=comment_id, user_id=current_user.id).first()

            if not comment:
                flash('Комментарий не найден или вы не можете его редактировать.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            if not content:
                flash('Текст комментария не может быть пустым.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            comment.content = content
            db.session.commit()
            flash('Комментарий успешно отредактирован!', 'success')

        if action == 'confirm_task':
            # Подтверждение выполнения задачи
            task_id = request.form.get('task_id')
            task = Task.query.get(task_id)

            if not task:
                flash('Задача не найдена.', 'danger')
                return redirect(url_for('main_routes.manager_dashboard'))

            task.status_id = 3  # Статус "Выполнено"
            db.session.commit()
            flash('Задача подтверждена как выполненная!', 'success')

        if action == 'create_project':
            # Создание проекта менеджером
            name = request.form.get('name')
            description = request.form.get('description')
            status_id = request.form.get('status_id')
            deadline = request.form.get('deadline')

            # Проверка обязательных полей
            if not all([name, description, status_id, deadline]):
                flash('Заполните все обязательные поля для проекта!', 'danger')
                return redirect(url_for('main_routes.manager_dashboard'))

            # Создание проекта с назначением текущего пользователя менеджером
            new_project = Project(
                name=name,
                description=description,
                manager_id=current_user.id,
                status_id=status_id,
                deadline=deadline
            )
            db.session.add(new_project)
            db.session.commit()
            flash('Проект успешно создан!', 'success')

    # Получение проектов, связанных с менеджером
    managed_projects = Project.query.filter_by(manager_id=current_user.id).all()
    assigned_tasks = Task.query.filter(Task.assigned_users.any(user_id=current_user.id)).all()

    # Получение уникальных проектов из задач, где менеджер участвует
    assigned_projects = {task.project for task in assigned_tasks if task.project}

    # Объединение всех доступных проектов
    visible_projects = list(set(managed_projects).union(assigned_projects))

    # Получение статусов для создания проектов
    statuses = ProjectStatus.query.all()

    # Получение данных о пользователях
    users = User.query.with_entities(User.full_name, User.email, User.position, User.phone_number).all()

    return render_template('manager_dashboard.html', projects=visible_projects, statuses=statuses, users=users)


@main_routes.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
@user_required
def user_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_comment':
            # Добавление комментария пользователем
            task_id = request.form.get('task_id')
            content = request.form.get('content')

            task = Task.query.filter(Task.assigned_users.any(user_id=current_user.id), Task.id == task_id).first()

            if not task or not content:
                flash('Вы не можете комментировать эту задачу.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            new_comment = Comment(
                task_id=task_id,
                user_id=current_user.id,
                content=content,
                created_at=datetime.utcnow()
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий успешно добавлен!', 'success')

        elif action == 'edit_comment':
            # Редактирование собственного комментария
            comment_id = request.form.get('comment_id')
            content = request.form.get('content')

            comment = Comment.query.filter_by(id=comment_id, user_id=current_user.id).first()

            if not comment:
                flash('Комментарий не найден или вы не можете его редактировать.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            if not content:
                flash('Текст комментария не может быть пустым.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            comment.content = content
            db.session.commit()
            flash('Комментарий успешно отредактирован!', 'success')

        if action == 'complete_subtask':
            # Завершение подзадачи пользователем
            subtask_id = request.form.get('subtask_id')
            subtask = Subtask.query.get(subtask_id)

            if not subtask:
                flash('Подзадача не найдена.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            subtask.status_id = 3  # Статус "Выполнено"
            db.session.commit()
            flash('Подзадача успешно завершена!', 'success')

        elif action == 'request_task_confirmation':
            # Запрос подтверждения выполнения задачи
            task_id = request.form.get('task_id')
            task = Task.query.get(task_id)

            if not task:
                flash('Задача не найдена.', 'danger')
                return redirect(url_for('main_routes.user_dashboard'))

            new_request = ConfirmationRequest(
                task_id=task_id,
                requested_by_id=current_user.id,
                status='pending'
            )
            db.session.add(new_request)
            db.session.commit()
            flash('Запрос на подтверждение отправлен!', 'success')

    # Доступные задачи и подзадачи для пользователя
    tasks = Task.query.filter(Task.assigned_users.any(user_id=current_user.id)).all()
    subtasks = Subtask.query.filter(Subtask.assigned_users.any(user_id=current_user.id)).all()

    # Получение задач, где пользователь назначен
    assigned_tasks = Task.query.filter(Task.assigned_users.any(user_id=current_user.id)).all()

    # Получение уникальных проектов из задач, где пользователь участвует
    user_projects = {task.project for task in assigned_tasks if task.project}

    # Получение данных о пользователях
    users = User.query.with_entities(User.full_name, User.email, User.position, User.phone_number).all()

    return render_template('user_dashboard.html', projects=user_projects, users=users)


# Профиль пользователя
@main_routes.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_folder = os.path.join(USER_FOLDER, str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)

    if request.method == 'POST':
        email = request.form.get('email')
        position = request.form.get('position')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        profile_picture = request.files.get('profile_picture')

        # Обновление почты
        if email:
            current_user.email = email

        # Обновление должности
        if position:
            current_user.position = position

        # Обновление телефона
        if phone_number:
            current_user.phone_number = phone_number

        # Обновление пароля
        if password:
            current_user.password_hash = sha256(password.encode('utf-8')).hexdigest()

        # Обновление фотографии профиля
        if profile_picture:
            filename = f"{str(current_user.id)}_{profile_picture.filename}"
            filepath = os.path.join(user_folder, filename)
            profile_picture.save(filepath)
            current_user.profile_picture = filepath

        db.session.commit()
        flash('Ваш профиль был успешно обновлен.', 'success')

    return render_template('profile_settings.html', user=current_user)
