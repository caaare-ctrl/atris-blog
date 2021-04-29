import os
from dotenv import load_dotenv
import smtplib
from datetime import date
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import current_user, UserMixin, LoginManager, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from psycopg2 import
load_dotenv(".env")
secret_key = os.getenv("secret_key")
email = os.getenv("email")
password = os.getenv("password")
sent_email = os.getenv("sent_email")

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES relationall database one to many
#Changed from post.author as post.author is now a User object.
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments =relationship("Comment",back_populates="parent_post")

# parents , posts is link to author
class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=False, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")

    comments = relationship("Comment",back_populates="comment_author")
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer,primary_key=True)
    text = db.Column(db.Text,unique=False, nullable=False)

    comment_author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, ForeignKey('users.id'))

    post_id = db.Column(db.Integer,ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost",back_populates = "comments")

db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    # register
    if form.validate_on_submit():
        # check if exist email
        if User.query.filter_by(email=form.email.data).first():
            flash("This email is registered already, please try again.")
            # not exist ok
            return redirect(url_for("login"))
        else:
            hashed_pw = generate_password_hash(password=form.password.data,
                                               method="pbkdf2:sha256:2000",
                                               salt_length=8)
            new_user = User(name=form.name.data,
                            email=form.email.data,
                            password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            #in order to make the current_user_is_autheticated return true
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form,gravatar=gravatar)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        # exist user
        if user:
            if check_password_hash(user.password,password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            flash("Incorrect Password")
            return redirect(url_for('login'))
        else:
            flash("Invalid Email")
            return redirect(url_for('login'))
    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login first to comment")
            return redirect(url_for("login"))
        new_comment = Comment(text = form.body.data,
                              comment_author = current_user,
                              parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post,form = form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=["GET","POST"])
def contact():
    if request.method == "POST":
        with smtplib.SMTP("smtp.mail.yahoo.com") as connection:
            connection.starttls()
            connection.login(user=email, password=password)
            connection.sendmail(from_addr=email, to_addrs=sent_email,
                                msg=f"Subject:Message from viewer \n\nName: {request.form['name']}\n"
                                    f"Email: {request.form['email']}\n"
                                    f"Message: {request.form['message']}")
        print("sent")
        return render_template("contact.html", message="Successfully sent your message!")
    return render_template("contact.html", message="Contact Me")

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
