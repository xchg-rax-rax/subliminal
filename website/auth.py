from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, User
# blueprints allow us to split up our views across multiple files
auth = Blueprint('auth', __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db.read_user(username=username)
        if user:
            if check_password_hash(user['password'], password):
                flash('Logged in Successfully!', category='success')
                login_user(User(user), remember=True)
                return redirect(url_for('views.dashboard')) 
            else:
                flash('Email or password was invalid. Please try again.', category='error')
        else:
            flash('Email or password was invalid. Please try again.', category='error')
    return  render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        password_1 = request.form.get('password1')
        password_2 = request.form.get('password2')
        # should be a proper email validity check here
        user = db.read_user(username=username)
        if user:
            flash('Username already exists.', category='error')
        elif len(username) < 4:
            flash('Username must greater than 4 characters in length.', category='error')
        elif len(password_1) < 8:
            flash('Password must be at last 8 characters in length.', category='error')
        elif password_1 != password_2:
            flash('Passwords must match.', category='error')
        else:
            user_id = db.create_user(username, generate_password_hash(password_1))
            if user_id:
                flash('Account Created.', category='success')
                user = User(db.read_user(user_id=user_id))
                login_user(user, remember=True)
                return redirect(url_for('views.dashboard'))
            else:
                flash('Server Error. Could not create user.', category='error')
    return render_template("sign_up.html", user=current_user) 
