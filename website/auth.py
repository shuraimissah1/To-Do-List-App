from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
 

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        #first method deleted
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successful', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
                                
            else:
                flash('incorrect password', category='error')
        else:
            flash('email do not exist', category='error')
   
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form['email']
        first_name = request.form['firstName']
        password1 = request.form['password1']
        password2 = request.form['password2']
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('email already exist', category='error')
        elif len(email) < 4:
            flash("email is short", category='error')
        #elif len(first_name) < 2:
            #flash('It should be more', category='error')
        elif password1 != password2:
            flash('passwords do not match', category='error')
        elif len(password1) < 7:
            flash('password is short', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha512'))
            #print user deleted
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('ACCOUNT CREATED', category='success')
            return redirect(url_for('views.home'))
    
    return render_template("sign_up.html", user=current_user)

        
        
    #password1=generate_password_hash(password1, method='md5' )
       