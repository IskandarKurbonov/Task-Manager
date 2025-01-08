import hashlib
from flask_login import login_user, logout_user
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory
from flask_login import login_required, current_user
from models import *
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy.orm import joinedload
from PIL import Image, ImageDraw, ImageOps

auth_routes = Blueprint('auth_routes', __name__)
main_routes = Blueprint('main_routes', __name__)

UPLOAD_FOLDER = 'projects'  # Папка для загрузки файлов
USER_PROFILE_FOLDER = 'static/users_profile'  # Папка для загрузки фотографии пользователей
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(USER_PROFILE_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Функции для хэширования и проверки пароля
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(stored_password_hash, provided_password):
    return stored_password_hash == hashlib.sha256(provided_password.encode('utf-8')).hexdigest()


@auth_routes.route('/')
def index():
    # Если пользователь не авторизован, перенаправляем на страницу логина
    if not current_user.is_authenticated:
        return redirect(url_for('auth_routes.login'))
    # Перенаправляем на /projects для авторизованных пользователей
    return redirect(url_for('main_routes.projects'))


# @main_routes.route('/index')
# @login_required
# def index():
#     return redirect(url_for('main_routes.projects'))  # Перенаправляем на /projects


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
            return redirect(url_for('main_routes.projects'))  # Перенаправляем на /projects
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


# Конфигурация директории для загрузки файлов
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'projects')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@main_routes.route('/users_profile/<user_id>/<filename>')
def send_user_profile_image(user_id, filename):
    user_folder = os.path.join(USER_PROFILE_FOLDER, user_id)
    return send_from_directory(user_folder, filename)


# Создание директории для проекта
def create_project_directory(project_id):
    """Создаёт директорию для проекта, если она не существует."""
    project_path = os.path.join(UPLOAD_FOLDER, str(project_id))
    if not os.path.exists(project_path):
        os.makedirs(project_path)
    return project_path


# Маршрут для загрузки файла
@main_routes.route('/project/<int:project_id>/upload_file', methods=['POST'])
@login_required
def upload_file(project_id):
    project = Project.query.get_or_404(project_id)  # Проверяем наличие проекта

    # Проверка на наличие файла
    if 'file' not in request.files:
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    file = request.files['file']

    # Проверяем, был ли файл выбран
    if not file or file.filename.strip() == '':
        flash('Файл не выбран.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    # Получаем имя файла напрямую
    filename = file.filename.strip()

    # Если имя файла некорректное, выводим ошибку
    if not filename or filename == "-":
        flash('Некорректное имя файла.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    # Создаём директорию для проекта, если её нет
    project_path = os.path.join(UPLOAD_FOLDER, str(project_id))
    os.makedirs(project_path, exist_ok=True)

    # Сохраняем файл без модификации имени
    file_path = os.path.join(project_path, filename)
    try:
        file.save(file_path)
        flash(f'Файл "{filename}" успешно загружен.', 'success')
    except Exception as e:
        flash(f'Ошибка при сохранении файла: {str(e)}', 'danger')

    return redirect(url_for('main_routes.project_details', project_id=project_id))



# Маршрут для скачивания файла
@main_routes.route('/project/<int:project_id>/download_file/<filename>', methods=['GET'])
@login_required
def download_file(project_id, filename):
    project_path = os.path.join(UPLOAD_FOLDER, str(project_id))
    file_path = os.path.join(project_path, filename)

    # Проверка, существует ли файл
    if os.path.exists(file_path):
        return send_from_directory(project_path, filename, as_attachment=True)
    else:
        flash('Файл не найден.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

# Маршрут для создания пользователя
@main_routes.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        new_user = User(username=username, password_hash=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь успешно создан.', 'success')
        return redirect(url_for('main_routes.index'))
    return render_template('create_user.html')


# Маршрут для создания проекта
@main_routes.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    statuses = ProjectStatus.query.all()  # Получаем все статусы проектов
    users = User.query.all()  # Получаем всех пользователей

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        description = request.form.get('description')
        status_id = request.form.get('status_id')
        manager_id = request.form.get('manager_id')
        deadline = request.form.get('deadline')

        # Преобразование строки в объект даты
        try:
            deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты дедлайна.', 'danger')
            return redirect(url_for('main_routes.create_project'))

        new_project = Project(
            name=project_name,
            description=description,
            status_id=status_id,
            manager_id=manager_id,
            deadline=deadline
        )
        db.session.add(new_project)
        db.session.commit()

        create_project_directory(new_project.id)

        return redirect(url_for('main_routes.project_details', project_id=new_project.id))

    statuses = TaskStatus.query.all()
    users = User.query.all()  # Получаем всех пользователей для выбора ответственного
    return render_template('create_project.html', statuses=statuses, users=users)

# Маршрут для создания задачи
@main_routes.route('/project/<int:project_id>/create_task', methods=['GET', 'POST'])
@login_required
def create_task(project_id):
    task_title = request.form.get('title')
    task_description = request.form.get('description')
    status_id = request.form.get('status_id')
    priority = request.form.get('priority', 1)
    assigned_to = request.form.get('assigned_to')
    deadline = request.form.get('deadline')

    if not task_title:
        flash('Название задачи обязательно.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    try:
        new_task = Task(
            title=task_title,
            description=task_description,
            project_id=project_id,
            status_id=status_id,
            priority=priority,
            assigned_to=assigned_to,
            deadline=datetime.strptime(deadline, '%Y-%m-%d') if deadline else None
        )
        db.session.add(new_task)
        db.session.commit()
        flash('Задача успешно создана!', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка: {e}")
        flash('При создании задачи возникла ошибка.', 'danger')

    return redirect(url_for('main_routes.project_details', project_id=project_id))




# Маршрут для добавления комментария
@main_routes.route('/project/<int:project_id>/task/<int:task_id>/add_comment', methods=['POST'])
@login_required
def add_comment(project_id, task_id):
    task = Task.query.get_or_404(task_id)
    content = request.form.get('content')

    new_comment = Comment(content=content, task_id=task_id, user_id=current_user.id)
    db.session.add(new_comment)
    db.session.commit()
    flash('Комментарий успешно добавлен.', 'success')
    return redirect(url_for('main_routes.project_details', project_id=project_id))


@main_routes.route('/update_task_status/<int:task_id>', methods=['POST'])
def update_task_status(task_id):
    # Здесь должна быть логика для обновления статуса задачи
    task = Task.query.get(task_id)
    status_id = request.form['status_id']
    task.status_id = status_id
    db.session.commit()
    return redirect(url_for('main_routes.project_details', project_id=task.project_id))


@main_routes.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project_details(project_id):
    project = Project.query.get_or_404(project_id)  # Получаем проект
    tasks = Task.query.filter_by(project_id=project_id).all()  # Получаем задачи проекта
    comments = Comment.query.filter(Comment.task_id.in_([task.id for task in tasks])).all()  # Получаем комментарии
    users = User.query.all()  # Получаем всех пользователей
    statuses = TaskStatus.query.all()  # Получаем все статусы задач

    project_files_path = os.path.join(current_app.root_path, 'projects', str(project.id))  # Путь к файлам проекта

    if request.method == 'POST':
        # Обработка формы для изменения статуса задачи
        if 'status_id' in request.form:
            task_id = request.form.get('task_id')
            status_id = int(request.form.get('status_id'))  # Преобразуем в int
            task = Task.query.get_or_404(task_id)
            task.status_id = status_id  # Обновляем статус задачи
            db.session.commit()
            flash('Статус задачи обновлён.', 'success')
            return redirect(url_for('main_routes.project_details', project_id=project_id))

        # Загрузка файла
        elif 'file' in request.files:
            file = request.files['file']
            if not file or file.filename == '':  # Проверка, что файл выбран
                flash('Файл не выбран.', 'danger')
                return redirect(url_for('main_routes.project_details', project_id=project_id))
            if not allowed_file(file.filename):  # Проверка формата файла
                flash('Недопустимый формат файла.', 'danger')
                return redirect(url_for('main_routes.project_details', project_id=project_id))

            filename = secure_filename(file.filename)
            project_path = create_project_directory(project_id)
            file_path = os.path.join(project_path, filename)
            file.save(file_path)
            flash(f'Файл "{filename}" успешно загружен.', 'success')

        # Обновление проекта
        elif 'project_name' in request.form:
            project_name = request.form.get('project_name')
            description = request.form.get('description')
            status_id = int(request.form.get('status_id'))  # Преобразуем в int
            manager_id = int(request.form.get('manager_id'))  # Преобразуем в int
            deadline = request.form.get('deadline')

            # Проверка обязательных полей
            if not project_name or not status_id or not manager_id or not deadline:
                flash('Все поля должны быть заполнены.', 'danger')
                return redirect(url_for('main_routes.project_details', project_id=project_id))

            # Преобразование строки в объект даты
            try:
                deadline = datetime.strptime(deadline, '%Y-%m-%d').date()
            except ValueError:
                flash('Некорректный формат даты дедлайна.', 'danger')
                return redirect(url_for('main_routes.project_details', project_id=project_id))

            project.name = project_name
            project.description = description
            project.status_id = status_id
            project.manager_id = manager_id
            project.deadline = deadline
            db.session.commit()
            flash('Проект успешно обновлён.', 'success')

        # Добавление задачи
        elif 'task_name' in request.form:
            task_name = request.form.get('task_name')
            assigned_to = request.form.get('assigned_to')
            status_id = request.form.get('status_id')  # Статус задачи
            deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d')

            new_task = Task(
                title=task_name,
                project_id=project_id,
                assigned_to=assigned_to,
                status_id=status_id,  # Устанавливаем статус задачи
                deadline=deadline
            )
            db.session.add(new_task)
            db.session.commit()
            flash('Задача успешно добавлена.', 'success')

            # После добавления задачи перенаправляем обратно на страницу с GET-запросом
            return redirect(url_for('main_routes.project_details', project_id=project_id))

        # Добавление комментария
        elif 'content' in request.form:
            content = request.form.get('content')
            task_id = request.form.get('task_id')
            new_comment = Comment(content=content, task_id=task_id, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Комментарий успешно добавлен.', 'success')

        return redirect(url_for('main_routes.project_details', project_id=project_id))

    return render_template(
        'project_details.html',
        project=project,
        tasks=tasks,
        comments=comments,
        users=users,
        statuses=statuses,
        project_files_path=project_files_path,
        os=os  # Передаем модуль os в шаблон
    )


# Маршрут для редактирования проекта
@main_routes.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.created_by != current_user.id:
        flash('У вас нет прав на редактирование этого проекта.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    if request.method == 'POST':
        project.name = request.form.get('project_name')
        project.description = request.form.get('description')
        db.session.commit()

        flash('Проект успешно обновлён.', 'success')
        return redirect(url_for('main_routes.project_details', project_id=project.id))

    return render_template('edit_project.html', project=project)


# Маршрут для редактирования задачи
@main_routes.route('/project/<int:project_id>/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(project_id, task_id):
    task = Task.query.get_or_404(task_id)
    if task.project_id != project_id:
        flash('Задача не принадлежит этому проекту.', 'danger')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    if request.method == 'POST':
        task.name = request.form.get('task_name')
        task.assigned_to = request.form.get('assigned_to')
        task.deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d')
        db.session.commit()

        flash('Задача успешно обновлена.', 'success')
        return redirect(url_for('main_routes.project_details', project_id=project_id))

    return render_template('edit_task.html', task=task)


# Изменение пароли
@main_routes.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Проверяем, что все поля заполнены
        if not old_password or not new_password or not confirm_password:
            flash('Все поля обязательны для заполнения.', 'danger')
            return redirect(url_for('main_routes.change_password'))

        # Хэшируем старый пароль с использованием sha256
        old_password_hash = hashlib.sha256(old_password.encode('utf-8')).hexdigest()

        # Логирование старого пароля
        print(f"Old password hash (from input): {old_password_hash}")
        print(f"Stored password hash (in DB): {current_user.password_hash}")

        # Проверка старого пароля
        if old_password_hash != current_user.password_hash:
            flash('Неверный старый пароль.', 'danger')
            return redirect(url_for('main_routes.change_password'))

        # Проверка, что новый пароль совпадает с подтверждением
        if new_password != confirm_password:
            flash('Новый пароль и подтверждение пароля не совпадают.', 'danger')
            return redirect(url_for('main_routes.change_password'))

        # Проверка длины нового пароля (например, минимум 8 символов)
        if len(new_password) < 8:
            flash('Пароль должен быть не менее 8 символов.', 'danger')
            return redirect(url_for('main_routes.change_password'))

        # Хэшируем новый пароль
        new_password_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        # Логирование нового пароля
        print(f"New password hash (to store): {new_password_hash}")

        # Обновляем пароль в базе данных
        current_user.password_hash = new_password_hash
        db.session.commit()

        flash('Пароль успешно изменен.', 'success')
        return redirect(url_for('main_routes.index'))

    return render_template('change_password.html')


# Маршрут для загрузки и изменения фото профиля
@main_routes.route('/profile_settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    if request.method == 'POST':
        # Проверяем, был ли файл загружен
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']

            if file and allowed_file(file.filename):  # Проверка на разрешенные форматы
                filename = secure_filename(file.filename)

                # Создаем папку для пользователя, если ее нет
                user_folder = os.path.join(USER_PROFILE_FOLDER, str(current_user.id))
                os.makedirs(user_folder, exist_ok=True)

                # Путь для сохранения файла
                file_path = os.path.join(user_folder, filename)
                file.save(file_path)

                # Обработка фотографии (если нужно)
                try:
                    # Открываем изображение с помощью PIL
                    image = Image.open(file_path).convert("RGBA")
                    size = (200, 200)  # Размеры для обрезки
                    mask = Image.new("L", size, 0)
                    draw = ImageDraw.Draw(mask)
                    draw.ellipse((0, 0) + size, fill=255)
                    output = ImageOps.fit(image, size, centering=(0.5, 0.5))
                    output.putalpha(mask)

                    # Путь для сохранения обрезанной фотографии
                    rounded_path = os.path.join(user_folder, f"rounded_{filename}")
                    output.save(rounded_path, format="PNG")

                    # Обновление данных пользователя с новой фотографией
                    current_user.profile_picture = f"/users_profile/{current_user.id}/rounded_{filename}"
                    db.session.commit()

                    flash('Фотография успешно загружена и обработана.', 'success')
                except Exception as e:
                    flash(f'Ошибка обработки фотографии: {str(e)}', 'danger')
            else:
                flash('Некорректный формат файла для фотографии.', 'danger')

    # Передача данных в шаблон
    user_data = {
        "username": current_user.username,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "profile_picture": current_user.profile_picture if current_user.profile_picture else None
    }
    return render_template('profile_settings.html', user=user_data)


@main_routes.route('/projects', methods=['GET'])
@login_required
def projects():
    try:
        projects = Project.query.options(
            joinedload(Project.tasks).joinedload(Task.status)
        ).all()
        print(f"Projects loaded: {[project.name for project in projects]}")
        return render_template('projects.html', projects=projects)
    except Exception as e:
        print(f"Error loading projects: {e}")
        flash(f'Произошла ошибка при загрузке проектов: {str(e)}', 'danger')
        return render_template('projects.html')



