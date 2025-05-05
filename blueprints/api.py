from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, session


api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/sendInfo/')
def sendInfo():
    print("info")

@api_bp.route('/sendInfoFull/')
def sendInfoFull():
    print("info full")

@api_bp.route('/sendSpeedTest/')
def sendSpeedTest():
    print("speed Test")


