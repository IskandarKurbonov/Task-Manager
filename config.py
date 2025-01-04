import os

class Config:
    # URI для подключения к базе данных PostgreSQL
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'postgresql://administrator:Z2xGhJ8RdsAq84X1ysKp9vCk@172.16.25.252/tasks'
    )
    # Отключение трекинга модификаций объектов SQLAlchemy (оптимизация)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Секретный ключ для приложения Flask (используется для подписи сессий и токенов)
    SECRET_KEY = os.getenv('SECRET_KEY', 'mysecretkey')

# Экземпляр конфигурации
app_config = Config()
