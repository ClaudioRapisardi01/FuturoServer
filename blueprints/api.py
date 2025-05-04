from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, session


api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/')
def index():
    return render_template('index.html')