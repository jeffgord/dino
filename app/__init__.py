from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path, environ
from flask_login import LoginManager
from oauthlib.oauth2 import WebApplicationClient

db = SQLAlchemy()
DB_NAME = "database.db"

GOOGLE_CLIENT_ID = environ.get(
    "GOOGLE_CLIENT_ID", None
)  # todo: set this and other environment vars up
GOOGLE_CLIENT_SECRET = environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")  # todo: set this up
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"
    db.init_app(app)

    from .views.views import views
    from .views.auth import auth

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")

    from .models.models import User

    with app.app_context():
        db.create_all()

    client = WebApplicationClient(GOOGLE_CLIENT_ID)

    login_manager = LoginManager()
    login_manager.login_view = "sign_up.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists("website/" + DB_NAME):
        db.create_all(app=app)
        print("Created Database!")
