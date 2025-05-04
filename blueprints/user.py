from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, session

from db import DB

user_bp = Blueprint('user', __name__, url_prefix='/user')


@user_bp.route('/')
def login():
    return render_template('index.html')






