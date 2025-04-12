from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import InputRequired, Length, Email, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uptrack.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class ChildData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    milestone = db.Column(db.String(200))
    user = db.relationship('User', backref=db.backref('children', lazy=True))

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class ChildForm(FlaskForm):
    name = StringField('Child Name', validators=[InputRequired(), Length(max=100)])
    age = IntegerField('Age', validators=[InputRequired(), NumberRange(min=0, max=18)])
    height = FloatField('Height (cm)')
    weight = FloatField('Weight (kg)')
    milestone = StringField('Recent Milestone')
    submit = SubmitField('Add Child')

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    children = ChildData.query.filter_by(user_id=session["user_id"]).all()
    def get_height_status(age, height):
        if age <= 1 and height >= 75: return "On Track"
        elif age == 2 and height >= 85: return "On Track"
        elif age == 3 and height >= 95: return "On Track"
        return "Needs Attention"
    def get_weight_status(age, weight):
        if age <= 1 and weight >= 10: return "On Track"
        elif age == 2 and weight >= 12: return "On Track"
        elif age == 3 and weight >= 14: return "On Track"
        return "Needs Attention"
    for child in children:
        child.height_status = get_height_status(child.age, child.height)
        child.weight_status = get_weight_status(child.age, child.weight)
    return render_template("dashboard.html", children=children)

@app.route("/add_child", methods=["GET", "POST"])
def add_child():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == 'POST':
        name = request.form["name"]
        age = request.form["age"]
        height = request.form["height"]
        weight = request.form["weight"]
        milestone = request.form["milestone"]
        new_child = ChildData(name=name, age=age, height=height, weight=weight, milestone=milestone, user_id=session["user_id"])
        db.session.add(new_child)
        db.session.commit()
        flash("Child added successfully!", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_child.html")

@app.route("/edit_child/<int:child_id>", methods=["GET", "POST"])
def edit_child(child_id):
    child = ChildData.query.get_or_404(child_id)
    if child.user_id != session["user_id"]:
        return "Unauthorized", 403
    if request.method == 'POST':
        child.name = request.form["name"]
        child.age = request.form["age"]
        child.height = request.form["height"]
        child.weight = request.form["weight"]
        child.milestone = request.form["milestone"]
        db.session.commit()
        flash("Child updated successfully!", "info")
        return redirect(url_for("dashboard"))
    return render_template("edit_child.html", child=child)

@app.route("/delete_child/<int:child_id>")
def delete_child(child_id):
    child = ChildData.query.get_or_404(child_id)
    if child.user_id != session["user_id"]:
        return "Unauthorized", 403
    db.session.delete(child)
    db.session.commit()
    flash("Child deleted successfully!", "warning")
    return redirect(url_for("dashboard"))

@app.route("/development")
def development():
    return render_template("development.html")

@app.route("/health")
def health():
    return render_template("health.html")

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html")


@app.route("/safety")
def safety():
    return render_template("safety.html")

@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/home')
def home_page():
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=True)
