from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    flash,
    redirect,
    url_for,
)
from ..models.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from .. import db  ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
import re
from http import HTTPStatus


auth = Blueprint("auth", __name__)


@auth.route("/sign-up", methods=["GET"])
def sign_up():
    return render_template("sign_up.html", user=current_user)


@auth.route("/sign-up/check-email-exist/<email>", methods=["GET"])
def check_email_exists(email):
    exists = bool(User.query.filter_by(email=email).first())
    return jsonify({"exists": exists})


@auth.route("/sign-up/add-user", methods=["POST"])
def add_user():
    data = request.get_json()
    email = data.get("email")
    password1 = data.get("password1")
    password2 = data.get("password2")
    agree = data.get("agree")

    if (
        not is_valid_email(email)
        or User.query.filter_by(email=email).first()
        or not is_valid_password(password1)
        or password1 != password2
        or not agree
    ):
        return HTTPStatus.BAD_REQUEST

    new_user = User(
        email=email,
        password=generate_password_hash(password1),
    )

    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)

    return HTTPStatus.OK


def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None


def is_valid_password(password):
    pattern = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    )
    return re.match(pattern, password) is not None


@auth.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")


@auth.route("/login/login-account", methods=["POST"])
def login_account():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return HTTPStatus.BAD_REQUEST

    user = User.query.filter_by(email=email).first()
    if not user:
        return HTTPStatus.NOT_FOUND
    elif not check_password_hash(user.password, password):
        return HTTPStatus.UNAUTHORIZED

    login_user(user, remember=True)
    return HTTPStatus.OK


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
