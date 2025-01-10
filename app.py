import logging
import random
import string
from flask import Flask
from flask_login import LoginManager, current_user
from models import db, User,  Role, ProjectStatus, TaskStatus
from hashlib import sha256

# Создание приложения Flask
app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

# Настройка менеджера входа
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth_routes.login'

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Функция загрузки пользователя
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Функция создания приложения
def create_app():
    with app.app_context():
        db.create_all()  # Создание всех таблиц
        initialize_roles()  # Инициализация ролей
        initialize_project_statuses()  # Инициализация статусов проектов
        initialize_task_statuses()  # Инициализация статусов задач
        initialize_admin_account()  # Инициализация учетной записи администратора

    from routes import main_routes, auth_routes
    app.register_blueprint(main_routes)
    app.register_blueprint(auth_routes)

    return app


# Инициализация ролей
def initialize_roles():
    roles = ['admin', 'manager', 'user']
    for role_name in roles:
        existing_role = Role.query.filter_by(name=role_name).first()
        if not existing_role:
            new_role = Role(name=role_name)
            db.session.add(new_role)
    db.session.commit()


# Инициализация статусов проектов
def initialize_project_statuses():
    project_statuses = ['Не начат', 'В процессе', 'Выполнено']
    for status in project_statuses:
        existing_status = ProjectStatus.query.filter_by(name=status).first()
        if not existing_status:
            new_status = ProjectStatus(name=status)
            db.session.add(new_status)
    db.session.commit()


# Инициализация статусов задач
def initialize_task_statuses():
    task_statuses = ['К выполнению', 'В процессе', 'Выполнено']
    for status in task_statuses:
        existing_status = TaskStatus.query.filter_by(name=status).first()
        if not existing_status:
            new_status = TaskStatus(name=status)
            db.session.add(new_status)
    db.session.commit()


@app.context_processor
def inject_user():
    return {'user': current_user}


# Инициализация учетной записи администратора
def initialize_admin_account():
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        logger.error("Роль 'admin' не найдена. Убедитесь, что роли инициализируются корректно.")
        return

    admin_username = 'administrator'
    admin_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))  # Генерация случайного пароля
    admin_password_hash = sha256(admin_password.encode('utf-8')).hexdigest()

    existing_admin = User.query.filter_by(username=admin_username).first()
    if not existing_admin:
        admin_account = User(
            username=admin_username,
            full_name='Администратор',
            password_hash=admin_password_hash,
            role_id=admin_role.id
        )
        db.session.add(admin_account)
        db.session.commit()
        logger.info(f"Учётная запись администратора создана: Логин: {admin_username}, Пароль: {admin_password}")
    else:
        logger.info("Учётная запись администратора уже существует.")


# Хук перед запросом
@app.before_request
def before_request():
    if current_user.is_authenticated:
        db.session.add(current_user)
        db.session.commit()


# Запуск приложения
if __name__ == '__main__':
    app = create_app()
    logger.info("Запуск Flask приложения")
    app.run(host='0.0.0.0', port=80)
