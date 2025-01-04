import logging
from flask import Flask
from flask_login import LoginManager, current_user
from config import Config
from models import db, User, ProjectStatus, TaskStatus
from datetime import datetime

# Создание приложения Flask
app = Flask(__name__)
app.config.from_object(Config)
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
        initialize_project_statuses()  # Инициализация статусов проектов
        initialize_task_statuses()  # Инициализация статусов задач

    from routes import main_routes, auth_routes
    app.register_blueprint(main_routes)
    app.register_blueprint(auth_routes)

    return app

# Инициализация статусов проектов
def initialize_project_statuses():
    project_statuses = ['Not Started', 'In Progress', 'Completed', 'On Hold']
    for status in project_statuses:
        existing_status = ProjectStatus.query.filter_by(name=status).first()
        if not existing_status:
            new_status = ProjectStatus(name=status)
            db.session.add(new_status)
    db.session.commit()

# Инициализация статусов задач
def initialize_task_statuses():
    task_statuses = ['To Do', 'In Progress', 'Done', 'Blocked']
    for status in task_statuses:
        existing_status = TaskStatus.query.filter_by(name=status).first()
        if not existing_status:
            new_status = TaskStatus(name=status)
            db.session.add(new_status)
    db.session.commit()

# Хук перед запросом
@app.before_request
def before_request():
    if current_user.is_authenticated:
        db.session.add(current_user)
        db.session.commit()

if __name__ == '__main__':

    app = create_app()
    logger.info("Запуск Flask приложения")
    app.run(host='0.0.0.0', port=80)
