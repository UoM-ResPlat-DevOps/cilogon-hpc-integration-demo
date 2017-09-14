import os


class Auth:
    CLIENT_ID = os.environ['CLIENT_ID']
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
    REDIRECT_URI = "https://" + os.environ['CLIENT_URL'] + "/callback"
    AUTH_URI = "https://cilogon.org/authorize"
    TOKEN_URI = 'https://cilogon.org/oauth2/token'
    USER_INFO = 'https://cilogon.org/oauth2/userinfo'
    CERT_URL = 'https://cilogon.org/oauth2/getcert'
    SCOPE = ['openid', 'email', 'profile', 'org.cilogon.userinfo','edu.uiuc.ncsa.myproxy.getcert']


class Config:
    APP_NAME = "CILogon Demo App"
    SECRET_KEY = os.environ['SECRET_KEY']
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:////var/db/database.db'


config = Config