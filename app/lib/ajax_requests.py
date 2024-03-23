from flask import jsonify
from http import HTTPStatus


def success(message=""):
    return message, HTTPStatus.OK


def bad_request(message=""):
    return message, HTTPStatus.BAD_REQUEST
