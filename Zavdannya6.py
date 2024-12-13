from flask import Flask, render_template_string, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, RoleNeed

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
principal = Principal(app)

ROLE_USER = RoleNeed('user')
ROLE_ADMIN = RoleNeed('admin')

class User(UserMixin):
    def __init__(self, id, roles):
        self.id = id
        self.roles = roles

    def has_role(self, role):
        return role in self.roles

users = {
    'user': User(id='user', roles=['user']),
    'admin': User(id='admin', roles=['user', 'admin'])
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def home():
    return render_template_string("""
        <h1>Welcome to the Flask RBAC App</h1>
        {% if current_user.is_authenticated %}
            <p>Hello, {{ current_user.id }}!</p>
            <p><a href="{{ url_for('logout') }}">Logout</a></p>
        {% else %}
            <p><a href="{{ url_for('login') }}">Login</a></p>
        {% endif %}
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = users.get(username)
        if user:
            login_user(user)
            return redirect(url_for('home'))
    return render_template_string("""
        <h1>Login</h1>
        <form method="post">
            Username: <input type="text" name="username"><br>
            <input type="submit" value="Login">
        </form>
    """)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/user_page')
@login_required
def user_page():
    if ROLE_USER not in current_user.roles:
        return "Access Denied"
    return "Welcome to the user page!"

@app.route('/admin_page')
@login_required
def admin_page():
    if ROLE_ADMIN not in current_user.roles:
        return "Access Denied"
    return "Welcome to the admin page!"

@app.before_request
def before_request():
    if request.endpoint in ['user_page', 'admin_page']:
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

