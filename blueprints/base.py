from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, session


base_bp = Blueprint('base', __name__, url_prefix='/')


@base_bp.route('/')
def index():
    return render_template('index.html')

@base_bp.route('/login')
def login():
    return render_template('login.html')

@base_bp.route('/register')
def register():
    return render_template('register.html')