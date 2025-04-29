from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import InputRequired, Length, Email, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------
# App Configurations
# -------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uptrack.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # redirects if user not logged in

# -------------------------------------------
# Models
# -------------------------------------------
class User(db.Model, UserMixin):
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

# -------------------------------------------
# Forms
# -------------------------------------------
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

# -------------------------------------------
# Login Manager
# -------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------
# Routes
# -------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")  # home page (accessible without login)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("This email is already registered. Please login.", "warning")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    form = ChildForm()

    if form.validate_on_submit():
        new_child = ChildData(
            user_id=current_user.id,
            name=form.name.data,
            age=form.age.data,
            height=form.height.data,
            weight=form.weight.data,
            milestone=form.milestone.data
        )
        db.session.add(new_child)
        db.session.commit()
        flash("Child added successfully!", "success")
        return redirect(url_for("dashboard"))

    children = ChildData.query.filter_by(user_id=current_user.id).all()

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

    return render_template("dashboard.html", children=children, form=form)

@app.route("/edit_child/<int:child_id>", methods=["GET", "POST"])
@login_required
def edit_child(child_id):
    child = ChildData.query.get_or_404(child_id)
    if child.user_id != current_user.id:
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
@login_required
def delete_child(child_id):
    child = ChildData.query.get_or_404(child_id)
    if child.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(child)
    db.session.commit()
    flash("Child deleted successfully!", "warning")
    return redirect(url_for("dashboard"))

# -------------------------------------------
# Pages accessible after login
# -------------------------------------------
@app.route("/development")
@login_required
def development():
    return render_template("development.html")

@app.route("/health")
@login_required
def health():
    return render_template("health.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/safety")
@login_required
def safety():
    return render_template("safety.html")

# -------------------------------------------
# Pages accessible without login
# -------------------------------------------
@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/about")
def about():
    return render_template("about.html")

# -------------------------------------------
# Run the app
# -------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
