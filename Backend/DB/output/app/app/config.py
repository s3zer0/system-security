import os
import yaml

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-coded-secret-key'
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    DEBUG = True
    TESTING = False

    @classmethod
    def load_from_yaml(cls, filepath):
        with open(filepath, 'r') as f:
            # Vulnerable yaml loading in config
            config_data = yaml.load(f, Loader=yaml.Loader)
        return config_data

    @classmethod
    def safe_load_config(cls, filepath):
        with open(filepath, 'r') as f:
            config_data = yaml.safe_load(f)
        return config_data

class DevelopmentConfig(Config):
    DEBUG = True
    DEVELOPMENT = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    if env == 'production':
        return ProductionConfig
    return DevelopmentConfig