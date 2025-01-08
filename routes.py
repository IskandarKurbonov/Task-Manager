import hashlib
from flask_login import login_user, logout_user
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory, abort
from flask_login import login_required, current_user
from models import *
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy.orm import joinedload
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

# Панель администратора
@main_routes.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    roles = Role.query.all()
    departments = Department.query.all()
    statuses = ProjectStatus.query.all()
    managers = User.query.filter_by(role_id=2).all()  # Role "Manager"
    return render_template('admin_dashboard.html', roles=roles, departments=departments, statuses=statuses, managers=managers)


# Панель пользователя
@main_routes.route('/user', methods=['GET'])
@login_required
@user_required
def user_dashboard():
    projects = Project.query.join(Task).join(TaskUser).filter(TaskUser.user_id == current_user.id).all()
    return render_template('user_dashboard.html', projects=projects)

# Создание пользователя
@main_routes.route('/admin/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username')
    full_name = request.form.get('full_name')  # Обязательное поле
    email = request.form.get('email')
    password = request.form.get('password')
    role_id = request.form.get('role_id')
    department_id = request.form.get('department_id')

    # Проверка обязательных полей
    if not (username and full_name and email and password and role_id and department_id):
        return {"success": False, "message": "Все обязательные поля должны быть заполнены."}, 400

    # Хеширование пароля
    password_hash = hash_password(password)

    # Создание нового пользователя
    new_user = User(
        username=username,
        full_name=full_name,
        email=email,
        password_hash=password_hash,
        role_id=role_id,
        department_id=department_id
    )
    db.session.add(new_user)
    db.session.commit()

    # Создание папки для пользователя
    user_folder = os.path.join(USER_FOLDER, str(new_user.id))
    os.makedirs(os.path.join(user_folder, 'profile'), exist_ok=True)

    return {"success": True, "message": "Пользователь успешно добавлен."}, 200


# Создание проекта менеджером
@main_routes.route('/manager/projects/create', methods=['GET', 'POST'])
@login_required
@manager_required
def create_project_manager():
    statuses = ProjectStatus.query.all()
    if request.method == 'POST':
        project_name = request.form.get('project_name')
        description = request.form.get('description')
        status_id = request.form.get('status_id')
        deadline = request.form.get('deadline')

        try:
            deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты дедлайна.', 'danger')
            return redirect(url_for('main_routes.create_project_manager'))

        # Создание проекта с текущим менеджером как ответственным
        new_project = Project(
            name=project_name,
            description=description,
            status_id=status_id,
            manager_id=current_user.id,
            deadline=deadline
        )
        db.session.add(new_project)
        db.session.commit()

        # Создание папки для проекта
        project_folder = os.path.join(UPLOAD_FOLDER, str(new_project.id))
        os.makedirs(project_folder, exist_ok=True)

        flash('Проект успешно создан.', 'success')
        return redirect(url_for('main_routes.manager_dashboard'))

    return render_template('create_project.html', statuses=statuses)


# Создание проекта администратором
@main_routes.route('/admin/projects/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_project_admin():
    statuses = ProjectStatus.query.all()
    managers = User.query.filter_by(role_id=2).all()  # Role "Manager"
    if request.method == 'POST':
        project_name = request.form.get('project_name')
        description = request.form.get('description')
        status_id = request.form.get('status_id')
        manager_id = request.form.get('manager_id')
        deadline = request.form.get('deadline')

        try:
            deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты дедлайна.', 'danger')
            return redirect(url_for('main_routes.create_project_admin'))

        new_project = Project(
            name=project_name,
            description=description,
            status_id=status_id,
            manager_id=manager_id,
            deadline=deadline
        )
        db.session.add(new_project)
        db.session.commit()

        # Создание папки для проекта
        project_folder = os.path.join(UPLOAD_FOLDER, str(new_project.id))
        os.makedirs(project_folder, exist_ok=True)

        flash('Проект успешно создан.', 'success')
        return redirect(url_for('main_routes.admin_dashboard'))
    return render_template('create_project.html', statuses=statuses, managers=managers)

# Просмотр проекта
@main_routes.route('/projects/<int:project_id>', methods=['GET'])
@login_required
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.role.name == 'manager' and project.manager_id != current_user.id:
        abort(403)
    if current_user.role.name == 'user':
        assigned_tasks = TaskUser.query.filter_by(user_id=current_user.id).all()
        if not any(task.task_id in [t.id for t in project.tasks] for task in assigned_tasks):
            abort(403)
    return render_template('project_details.html', project=project)

# Загрузка файлов в проект
@main_routes.route('/projects/<int:project_id>/upload', methods=['POST'])
@login_required
def upload_project_file(project_id):
    project_folder = os.path.join(UPLOAD_FOLDER, str(project_id))
    os.makedirs(project_folder, exist_ok=True)

    if 'file' not in request.files:
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    file = request.files['file']
    if file.filename == '':
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    file_path = os.path.join(project_folder, secure_filename(file.filename))
    file.save(file_path)
    flash(f'Файл "{file.filename}" успешно загружен.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=project_id))

# Создание задачи
@main_routes.route('/projects/<int:project_id>/tasks/create', methods=['GET', 'POST'])
@login_required
@manager_required
def create_task(project_id):
    project = Project.query.get_or_404(project_id)
    if project.manager_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        assigned_to = request.form.get('assigned_to')

        new_task = Task(
            project_id=project.id,
            title=title,
            description=description,
            status_id=1  # Default status "To Do"
        )
        db.session.add(new_task)
        db.session.commit()

        if assigned_to:
            task_user = TaskUser(task_id=new_task.id, user_id=assigned_to)
            db.session.add(task_user)
            db.session.commit()

        flash('Задача успешно создана.', 'success')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    users = User.query.filter_by(role_id=3).all()  # Role "User"
    return render_template('create_task.html', project=project, users=users)

# Загрузка файлов в задачу
@main_routes.route('/tasks/<int:task_id>/upload', methods=['POST'])
@login_required
def upload_task_file(task_id):
    task = Task.query.get_or_404(task_id)
    project_folder = os.path.join(UPLOAD_FOLDER, str(task.project_id))
    os.makedirs(project_folder, exist_ok=True)

    if 'file' not in request.files:
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=task.project_id))

    file = request.files['file']
    if file.filename == '':
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=task.project_id))

    file_path = os.path.join(project_folder, secure_filename(file.filename))
    file.save(file_path)
    flash(f'Файл "{file.filename}" успешно загружен.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))

# Принятие задачи ответственным
@main_routes.route('/tasks/<int:task_id>/accept', methods=['POST'])
@login_required
@user_required
def accept_task(task_id):
    task = Task.query.get_or_404(task_id)
    if not any(user.user_id == current_user.id for user in task.assigned_users):
        abort(403)

    task.status_id = TaskStatus.query.filter_by(name='В процессе').first().id
    db.session.commit()
    flash('Задача принята в работу.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))

# Подтверждение выполнения задачи менеджером
@main_routes.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
@manager_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.project.manager_id != current_user.id:
        abort(403)

    task.status_id = TaskStatus.query.filter_by(name='Выполнено').first().id
    db.session.commit()
    flash('Задача подтверждена как выполненная.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))

# Добавление комментария к задаче
@main_routes.route('/tasks/<int:task_id>/comments/add', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.role.name == 'user' and not any(user.user_id == current_user.id for user in task.assigned_users):
        abort(403)
    if current_user.role.name == 'manager' and task.project.manager_id != current_user.id and not any(user.user_id == current_user.id for user in task.assigned_users):
        abort(403)

    content = request.form.get('content')
    if not content:
        flash('Комментарий не может быть пустым.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=task.project_id))

    comment = Comment(content=content, task_id=task.id, user_id=current_user.id, created_at=datetime.utcnow())
    db.session.add(comment)
    db.session.commit()
    flash('Комментарий добавлен.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))


# Удаление ответственного из задачи
@main_routes.route('/tasks/<int:task_id>/assigned_users/<int:user_id>/remove', methods=['POST'])
@login_required
@manager_required
def remove_assigned_user(task_id, user_id):
    task = Task.query.get_or_404(task_id)
    if task.project.manager_id != current_user.id:
        abort(403)

    assigned_user = TaskUser.query.filter_by(task_id=task.id, user_id=user_id).first()
    if assigned_user:
        db.session.delete(assigned_user)
        db.session.commit()
        flash('Пользователь удален из списка ответственных.', 'success')
    else:
        flash('Пользователь не найден среди ответственных.', 'danger')
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))


@main_routes.route('/profile/settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    user = current_user
    if request.method == 'POST':
        # Проверка типа формы (загрузка фото или обновление данных)
        if request.form.get('form_type') == 'profile_picture':
            # Обработка загрузки фотографии профиля
            if 'profile_picture' not in request.files:
                flash('Файл не выбран.', 'danger')
                return redirect(url_for('main_routes.profile_settings'))

            file = request.files['profile_picture']
            if file.filename == '':
                flash('Файл не выбран.', 'danger')
                return redirect(url_for('main_routes.profile_settings'))

            # Проверка формата файла
            if not file.filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif')):
                flash('Неверный формат файла. Допустимые форматы: png, jpg, jpeg, gif.', 'danger')
                return redirect(url_for('main_routes.profile_settings'))

            # Создание директории пользователя
            user_folder = os.path.join(USER_FOLDER, str(user.id), 'profile')
            os.makedirs(user_folder, exist_ok=True)

            # Сохранение файла
            file_path = os.path.join(user_folder, secure_filename(file.filename))
            file.save(file_path)

            # Обновление пути к фотографии профиля в базе данных
            user.profile_picture = f'users/{user.id}/profile/{secure_filename(file.filename)}'
            db.session.commit()

            flash('Фотография профиля успешно обновлена.', 'success')
            return redirect(url_for('main_routes.profile_settings'))

        # Обновление данных пользователя
        user.full_name = request.form.get('full_name', user.full_name)
        user.email = request.form.get('email', user.email)
        user.phone_number = request.form.get('phone_number', user.phone_number)
        user.position = request.form.get('position', user.position)
        if request.form.get('password'):
            user.password_hash = hash_password(request.form.get('password'))
        db.session.commit()
        flash('Профиль успешно обновлен.', 'success')
        return redirect(url_for('main_routes.profile_settings'))

    return render_template('profile_settings.html', user=user)


@main_routes.route('/admin/departments/create', methods=['POST'])
@login_required
@admin_required
def create_department():
    department_name = request.form.get('department_name')
    description = request.form.get('description')
    new_department = Department(name=department_name, description=description)
    db.session.add(new_department)
    db.session.commit()
    flash('Подразделение успешно создано.', 'success')
    return redirect(url_for('main_routes.admin_dashboard'))

@main_routes.route('/manager', methods=['GET', 'POST'])
@login_required
@manager_required
def manager_dashboard():
    statuses = ProjectStatus.query.all()

    # Обработка создания проекта
    if request.method == 'POST':
        project_name = request.form.get('project_name')
        description = request.form.get('description')
        status_id = request.form.get('status_id')
        deadline = request.form.get('deadline')

        try:
            deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты дедлайна.', 'danger')
            return redirect(url_for('main_routes.manager_dashboard'))

        # Создание проекта
        new_project = Project(
            name=project_name,
            description=description,
            status_id=status_id,
            manager_id=current_user.id,
            deadline=deadline
        )
        db.session.add(new_project)
        db.session.commit()

        flash('Проект успешно создан.', 'success')

    # Проекты, где менеджер ответственен
    responsible_projects = Project.query.filter_by(manager_id=current_user.id).all()

    # Проекты, где менеджер участвует в задачах
    participating_projects = (
        Project.query
        .join(Task, Task.project_id == Project.id)
        .join(TaskUser, TaskUser.task_id == Task.id)
        .filter(TaskUser.user_id == current_user.id)
        .distinct()
        .all()
    )

    # Объединяем проекты без дублирования
    projects = list({project.id: project for project in responsible_projects + participating_projects}.values())

    return render_template('manager_dashboard.html', projects=projects, statuses=statuses)
