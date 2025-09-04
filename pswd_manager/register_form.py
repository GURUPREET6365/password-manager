from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegisterForm(FlaskForm):
    username = StringField(label='Username:' , validators=[DataRequired(), Length(min=2, max=30)])
    email = StringField(label='Email Address:', validators=[DataRequired(), Email()])
    password1 = PasswordField(label='Password:', validators=[DataRequired(), Length(min=6, max=20)])
    password2 = PasswordField(label='Confirm Password:', validators=[DataRequired(), EqualTo('password1', message='Passwords must match.')])
    submit = SubmitField(label='Create Account')
