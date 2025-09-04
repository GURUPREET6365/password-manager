from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

class StorePasswordForm(FlaskForm):
    address = StringField(label='Address:', validators=[DataRequired()])
    name = StringField(label='Username / Email:' , validators=[DataRequired(), Length(min=2, max=30)])
    password1 = PasswordField(label='Password:', validators=[DataRequired(), Length(min=6, max=20)])
    password2 = PasswordField(label='Confirm Password:', validators=[DataRequired(), EqualTo('password1', message='Passwords must match.')])
    submit = SubmitField(label='Save Password')
