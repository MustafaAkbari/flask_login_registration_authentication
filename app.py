from flask import Flask, render_template, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, LoginManager, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import exc

# create our flask app
app = Flask(__name__)
# create a secret key for Cross-Site Request Forgery (CSRF)
app.config["SECRET_KEY"] = "this is programming with python and flask"
# database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:rose@localhost/website_users"
# initialize the database
db = SQLAlchemy(app)
app.app_context().push()
# flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# create a model or a table for our database
class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(65), nullable=Flask)
    username = db.Column(db.String(65), nullable=Flask, unique=True)
    email = db.Column(db.String(130), nullable=Flask, unique=True)
    password_hash = db.Column(db.String(130), nullable=Flask)

    # define a getter decorator to show an error message for AttributeError
    @property
    def password(self):
        raise AttributeError("password is not a readable attribute!")

    # define setter decorator to generate a hash password and check or verify hashed_password
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"Student Id: {self.id}" \
               f"Student Name: {self.name}" \
               f"Student Email: {self.email}"


# creating a form for registration
class RegistrationForm(FlaskForm):
    fullname = StringField("FullName: ", validators=[DataRequired()], render_kw={"placeholder": "FullName"})
    username = StringField("UserName: ", validators=[DataRequired()], render_kw={"placeholder": "UserName"})
    email = EmailField("Email: ", validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField("Password: ", validators=[DataRequired(), EqualTo("confirm_password",
                                                                               message="Password must match!")],
                             render_kw={"placeholder": "Password"})
    confirm_password = PasswordField("Confirm Password: ", validators=[DataRequired()],
                                     render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")


# creating a form for login
class LoginForm(FlaskForm):
    username = StringField("UserName: ", validators=[DataRequired()], render_kw={"placeholder": "UserName"})
    password = PasswordField("Password: ", validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


# creating a route for home page
@app.route("/")
def home():
    users = Users.query.order_by(Users.id)
    return render_template("home.html", users=users)


# creating a route for registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data, email=form.email.data).first()
        try:
            if user is None:
                hashed_password = generate_password_hash(form.password.data)
                new_user = Users(fullname=form.fullname.data.title(),
                                 username=form.username.data,
                                 email=form.email.data.capitalize(),
                                 password_hash=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                flash("User added successfully", "success")
                return redirect(url_for("login"))
        except exc.IntegrityError as e:
            db.session.rollback()
            flash("The Email or Username already exist, please try another email or username!", "danger")
            return redirect(url_for("register"))
    return render_template("register.html", form=form)


# creating a route for login page
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Logged in successfully", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Password is not correct, try again!", "danger")
                return redirect(url_for("login"))
        else:
            flash(f"The username: {form.username.data} you want to login with, does not exist!", "warning")
    return render_template("login.html", form=form)


# creating a route for logout functions
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out from your dashboard!")
    return redirect(url_for("login"))


# creating a route for students dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True)
