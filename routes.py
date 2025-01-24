from pathlib import Path
import hashlib
from datetime import timedelta
from hashlib import sha256
from flask_login import login_user, logout_user
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import login_required, current_user
from sqlalchemy.orm import joinedload

from app import logger
from models import *
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError

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


@main_routes.route('/main', methods=['GET'])
@login_required
def main():
    try:
        # Получение ID проекта из параметров запроса
        project_id = request.args.get('project_id', type=int)
        selected_project = None

        # Если ID проекта указан, находим соответствующий проект
        if project_id:
            selected_project = Project.query.get_or_404(project_id)

        # Получение всех проектов, доступных пользователю
        if current_user.role.name == 'admin':
            projects = Project.query.all()
        else:
            projects = (
                Project.query.join(ProjectUser)
                .filter(ProjectUser.user_id == current_user.id)
                .all()
            )

        # Получение всех статусов задач
        task_statuses = TaskStatus.query.all()

        # Получение всех пользователей (для назначения задач)
        all_users = User.query.all()

        # Передаем данные в шаблон
        return render_template(
            'main.html',
            projects=projects,  # Список проектов
            selected_project=selected_project,  # Текущий выбранный проект
            task_statuses=task_statuses,  # Список статусов задач
            all_users=all_users  # Все пользователи (для назначения задач)
        )

    except Exception as e:
        # Возвращаем сообщение об ошибке
        return f"Ошибка при загрузке страницы: {str(e)}", 500



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

        if action == 'return_task':
            task_id = request.form.get('task_id')
            comment_content = request.form.get('comment_content')

            task = Task.query.get(task_id)
            if not task:
                flash('Задача не найдена.', 'danger')
                return redirect(url_for('main_routes.manager_dashboard'))

            # Изменяем статус задачи на "На доработке"
            task.status_id = TaskStatus.query.filter_by(name='На доработке').first().id
            db.session.add(task)

            # Добавляем комментарий
            if comment_content:
                comment = Comment(
                    task_id=task.id,
                    user_id=current_user.id,
                    content=comment_content
                )
                db.session.add(comment)

            db.session.commit()
            flash('Задача успешно возвращена на доработку!', 'success')


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
    # Определяем путь к папке пользователя
    user_folder = Path(USER_FOLDER) / str(current_user.id)
    user_folder.mkdir(parents=True, exist_ok=True)  # Создаем папку пользователя, если её нет

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
            # Генерируем корректное имя файла
            filename = f"{current_user.id}_{profile_picture.filename}"
            filepath = user_folder / filename
            profile_picture.save(str(filepath))  # Сохраняем файл

            # Преобразуем абсолютный путь в относительный
            relative_path = str(filepath.relative_to(Path('static'))).replace("\\", "/")
            current_user.profile_picture = relative_path  # Сохраняем путь в формате users/1/1_photos.jpg

        # Сохраняем изменения в базе данных
        db.session.commit()
        flash('Ваш профиль был успешно обновлен.', 'success')

    return render_template('profile_settings.html', user=current_user)


@main_routes.route('/create_project', methods=['POST'])
@login_required
def create_project():
    # Получаем данные из формы
    name = request.form.get('name')
    description = request.form.get('description')
    deadline = request.form.get('deadline')
    manager_id = request.form.get('manager_id')

    if not name or not description:
        flash('Название и описание обязательны для заполнения', 'danger')
        return redirect(url_for('main_routes.main'))

    try:
        # Преобразование даты
        deadline_date = datetime.strptime(deadline, '%Y-%m-%d') if deadline else None

        # Создаём новый проект
        new_project = Project(
            name=name,
            description=description,
            created_at=datetime.utcnow(),
            deadline=deadline_date,
            manager_id=manager_id,
            status_id=1  # Укажите ID для статуса по умолчанию, например, "Новый"
        )
        db.session.add(new_project)
        db.session.commit()

        flash('Проект успешно создан!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при создании проекта: {str(e)}', 'danger')

    return redirect(url_for('main_routes.main'))

@main_routes.route('/create_task', methods=['POST'])
@login_required
def create_task():
    try:
        # Логирование данных для отладки
        print(f"Форма: {request.form}")
        print(f"Пользователь: {current_user.username}, Роль: {current_user.role.name}")

        # Получаем данные из формы
        title = request.form.get('title')
        description = request.form.get('description')
        project_id = request.form.get('project_id')
        status_id = request.form.get('status_id')
        priority = int(request.form.get('priority', 1))
        deadline = request.form.get('deadline')
        assigned_user_ids = request.form.getlist('assigned_user_ids')

        # Проверяем, что обязательные поля заполнены
        if not title or not project_id or not status_id:
            flash('Заполните все обязательные поля!', 'danger')
            return redirect(url_for('main_routes.main', project_id=project_id))

        # Проверяем существование проекта
        project = Project.query.get_or_404(project_id)
        print(f"Проект найден: {project.name}")

        # Проверяем права доступа
        if current_user.role.name == 'manager':
            # Менеджер может создавать задачи только в проектах, где он является ответственным
            if project.manager_id != current_user.id:
                flash('Вы можете создавать задачи только в проектах, где вы являетесь ответственным.', 'danger')
                return redirect(url_for('main_routes.main', project_id=project_id))

        # Проверяем статус задачи
        status = TaskStatus.query.get(status_id)
        if not status:
            flash('Некорректный статус задачи!', 'danger')
            return redirect(url_for('main_routes.main', project_id=project_id))

        # Создаем новую задачу
        new_task = Task(
            title=title,
            description=description,
            project_id=project_id,
            status_id=status_id,
            priority=priority,
            deadline=datetime.strptime(deadline, '%Y-%m-%d') if deadline else None
        )
        db.session.add(new_task)
        db.session.flush()  # Сохраняем задачу в базе для получения ID

        # Привязываем пользователей к задаче
        for user_id in assigned_user_ids:
            task_user = TaskUser(task_id=new_task.id, user_id=user_id)
            db.session.add(task_user)

        # Сохраняем изменения в базе данных
        db.session.commit()
        flash('Задача успешно создана!', 'success')
        return redirect(url_for('main_routes.main', project_id=project_id))

    except Exception as e:
        # В случае ошибки откатываем изменения и выводим сообщение
        db.session.rollback()
        print(f"Ошибка при создании задачи: {str(e)}")
        flash(f'Ошибка при создании задачи: {str(e)}', 'danger')
        return redirect(url_for('main_routes.main', project_id=project_id))

@main_routes.route('/add_comment', methods=['POST'])
@login_required
def add_comment():
    """
    Создание комментария к задаче.
    """
    try:
        # Получение данных из формы
        task_id = request.form.get('task_id')
        content = request.form.get('content')

        # Проверка входных данных
        if not task_id or not content:
            flash('Укажите задачу и содержимое комментария!', 'danger')
            return redirect(request.referrer)

        # Проверка существования задачи
        task = Task.query.get(task_id)
        if not task:
            flash('Задача не найдена!', 'danger')
            return redirect(request.referrer)

        # Проверка доступа (пользователь должен быть ответственным за задачу или администратором)
        if current_user.role.name != 'admin' and not any(user.user_id == current_user.id for user in task.assigned_users):
            flash('Вы не можете комментировать эту задачу!', 'danger')
            return redirect(request.referrer)

        # Создание нового комментария
        new_comment = Comment(
            task_id=task.id,
            user_id=current_user.id,
            content=content,
            created_at=datetime.utcnow()
        )
        db.session.add(new_comment)
        db.session.commit()

        flash('Комментарий успешно добавлен!', 'success')
        return redirect(request.referrer)

    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении комментария: {str(e)}', 'danger')
        return redirect(request.referrer)


@main_routes.route('/return_task', methods=['POST'])
@login_required
@manager_required
def return_task():
    task_id = request.form.get('task_id')
    comment_content = request.form.get('comment_content')

    task = Task.query.get(task_id)
    if not task:
        flash('Задача не найдена.', 'danger')
        return redirect(url_for('main_routes.manager_dashboard'))

    # Изменяем статус задачи на "На доработке"
    task.status_id = TaskStatus.query.filter_by(name='На доработке').first().id

    # Добавляем комментарий, если указан
    if comment_content:
        comment = Comment(
            task_id=task.id,
            user_id=current_user.id,
            content=comment_content
        )
        db.session.add(comment)

    db.session.commit()
    flash('Задача возвращена на доработку!', 'success')
    return redirect(url_for('main_routes.manager_dashboard'))
