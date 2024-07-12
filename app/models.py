from flask_login import UserMixin
from app import login

users = {'test': {'password': 'test'}}


class User(UserMixin):
    pass


@login.user_loader
def load_user(username):
    if username not in users:
        return

    user = User()
    user.id = username
    return user
