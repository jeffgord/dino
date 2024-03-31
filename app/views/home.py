from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user

home = Blueprint("home", __name__)


@home.route("/", methods=["GET"])
def home_page():
    return render_template("home.html")
