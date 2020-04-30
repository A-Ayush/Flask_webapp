from webpage import app,db, bcrypt
from flask import Flask, render_template, url_for, flash, redirect ,session, request
from webpage.forms import RegistrationForm, LoginForm, add_details
from webpage.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required


@app.route("/home2")
def home2():
    username = session[ "username" ]
    return render_template("view.html", values = User.query.filter_by(username = username), click='login')

@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
    form = RegistrationForm()
    if "username" in session:
        username = session["username"]
        return render_template("view.html", values = User.query.filter_by(username = username), click='login')
    else:
        if form.validate_on_submit():
            if request.method == "POST":
                username = request.form[ "username" ]
                session[ "username" ] = username
                email = request.form[ "email" ]
                session[ "email" ] = email
                password = request.form[ "password" ]
                session[ "password" ] = password

                found_user=User.query.filter_by(username = username).first()
                if found_user:
                    flash(f'Account Already exist {form.username.data}!', 'success')
                    return redirect(url_for('register'))
                else:
                    flash(f'Account created for {form.username.data}!', 'success')
                    user = User(username,email,password)
                    db.session.add(user)
                    db.session.commit()

            return redirect(url_for('home2'))
        return render_template('home.html', click= 'home', form=form)



@app.route("/about")
def about():
    click = 'About'
    if "username" in session:
        usr = session[ "username" ]
        if usr :
            click = 'login'
    return render_template('about.html', title='About' , click=click)


@app.route("/reg", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if "username" in session:
        username = session["username"]
        return render_template("view.html", values = User.query.filter_by(username = username), click='login')
    else:
        if form.validate_on_submit():
            if request.method == "POST":
                username = request.form[ "username" ]
                session[ "username" ] = username
                email = request.form[ "email" ]
                session[ "email" ] = email
                password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  

                found_user=User.query.filter_by(username = username).first()
                if found_user:
                    flash(f'Username {form.username.data}! Already taken', 'success')
                    return redirect(url_for('register'))
                else:
                    flash(f'Account created for {form.username.data}!', 'success')
                    user = User(username,email,password)
                    db.session.add(user)
                    db.session.commit()

            return redirect(url_for('home2'))
        return render_template('register.html', title='Register', form=form)

@app.route("/view")
def view():
    return render_template("database.html", values = User.query.all())


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if "username" in session:
        print("username")
        username = session["username"]
        return render_template("view.html", values = User.query.filter_by(username = username), click='login')
    else:
        if form.validate_on_submit():
            if request.method == "POST":
                email = request.form[ "email" ]
                found_user=User.query.filter_by(email = form.email.data).first()
                print(found_user)
                if found_user:
                    if found_user.email == email and bcrypt.check_password_hash(found_user.password, form.password.data):
                        click = 'login'
                        session[ "username" ] = found_user.username
                        flash('You have been logged in!', 'success')
                        return redirect(url_for('home2'))
                    else:
                        flash('Login Unsuccessful. Please check username and password', 'danger')
                else:
                     flash('User doesn not exists', 'info')
            else:
                flash('Logged in!')
        return render_template('login.html', click = 'loginhome' ,title='Login', form=form)

@app.route("/details")
def details():
    form = add_details()
    return render_template('details.html',form=form)


@app.route("/logout")
def logout():
    session.pop("username",None)
    return redirect(url_for("home"))
