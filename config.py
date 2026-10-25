import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key-p211-change-in-production")
    TESTING = False
    DEBUG = False
    ENV = "production"
    DATABASE_PATH = os.path.join(basedir, "database", "app.db")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    ENV = "development"
    DATABASE_PATH = os.path.join(basedir, "database", "app.db")


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = False
    ENV = "testing"
    SECRET_KEY = "test-secret-key"
    DATABASE_PATH = os.path.join(basedir, "database", "test_app.db")


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
