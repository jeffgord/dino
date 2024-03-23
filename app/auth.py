from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    flash,
    redirect,
    url_for,
    abort,
)
from .models.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db  ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
import re
from .lib import ajax_requests


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password, try again.", category="error")
        else:
            flash("Email does not exist.", category="error")

    return render_template("login.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


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
        return ajax_requests.bad_request()

    new_user = User(
        email=email,
        password=generate_password_hash(password1),
    )

    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)

    return ajax_requests.success()


def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None


def is_valid_password(password):
    pattern = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    )
    return re.match(pattern, password) is not None
