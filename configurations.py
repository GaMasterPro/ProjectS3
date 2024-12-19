import os
from datetime import timedelta

class Config:
    # Secret key and database URI from environment variables
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # Default for development
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///default.db')  # Default to SQLite if no env var
    DEBUG = True  # Change to False in production
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SAMESITE = 'Strict'  # Secure cookie settings

    # Flask-Mail configuration from environment variables
    MAIL_SERVER = 'smtp.gmail.com'  # Set Mail server to Gmail as per your settings
    MAIL_PORT = 587  # Default to 587 for TLS
    MAIL_USE_TLS = True  # TLS is enabled
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'armenking83@gmail.com')  # Load from .env
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'ybygvomttmomlyda')  # Load from .env
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'armenking83@gmail.com')  # Load from .env