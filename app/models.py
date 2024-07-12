from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, user_id, user_name, password):
        self.id = user_id
        self.user_name = user_name
        self.password = password
