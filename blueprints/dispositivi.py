from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, session


dispositivi_bp = Blueprint('dispositivi', __name__, url_prefix='/dispositivi')