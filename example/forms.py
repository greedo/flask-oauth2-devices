from flask.ext.wtf import Form
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired

class ActivateForm(Form):
    auth_code = StringField('code', validators=[DataRequired()])
    #choices = [('', '')]
    #stock = SelectField('stock', choices=choices)

class AuthorizeForm(Form):
    choices = [('', '')]
    scopes = SelectField('stock', choices=choices)
