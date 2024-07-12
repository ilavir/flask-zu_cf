from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class ApiTokenForm(FlaskForm):
    api_token = StringField('API Token', validators=[DataRequired()])
    submit = SubmitField('Save')


class Ipv4ToIpv6Form(FlaskForm):
    ipv6_address = StringField('IPv6 Address', validators=[DataRequired()])
    submit = SubmitField('COPY IPv4 to IPv6')
