from flask.ext.wtf import Form
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired


class ActivateForm(Form):
    user_code = StringField('user_code', validators=[DataRequired()])
