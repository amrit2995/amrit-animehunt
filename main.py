from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime as dt
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar

password_encrypt_method = 'pbkdf2:sha256'
saltlength = 8

## Delete this code:
# import requests
# posts = requests.get("https://api.npoint.io/43644ec4f0013682fc0d").json()


#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.user_priveledge != 'root':
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


def super_users(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.user_priveledge not in ['root', 'super_user']:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


def blog_author_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = request.args.get('index')
        blog = BlogPost.query.get(post_id)
        if current_user.user_priveledge == 'root' or current_user.name == blog.author.name :
            return f(*args, **kwargs)
        return abort(403)
    return decorated_function


def comment_author_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        comment_id = request.args.get('comment_id')
        comment = Comment.query.get(comment_id)
        if current_user.user_priveledge == 'root' or current_user.name == comment.author.name :
            return f(*args, **kwargs)
        return abort(403)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blogposts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Login initianlise
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("Users", back_populates='posts')
    comments = relationship("Comment", back_populates='post')


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(90), nullable=False)
    email = db.Column(db.String(90), nullable=False)
    password = db.Column(db.String(90), nullable=False)
    user_priveledge = db.Column(db.String(90), nullable=False)
    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comment", back_populates='author')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    text = db.Column(db.Text, nullable=False)
    author = relationship("Users", back_populates='comments')
    post = relationship("BlogPost", back_populates='comments')



# db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CommentForm(FlaskForm):
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    # body = StringField('Add Comment', validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Submit Post")


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route("/post", methods=['GET', 'POST'])
def show_post():
    form = CommentForm()
    index = request.args.get('index')
    requested_post = BlogPost.query.get(index)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.body.data,
            author=current_user,
            post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', index=requested_post.id))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route('/edit-post/<post_id>', methods=['GET', 'POST'])
@blog_author_only
def edit(post_id):
    post = BlogPost.query.get(post_id)
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.date = dt.now().strftime('%B %d, %Y')
        post.body = form.body.data
        post.author = current_user
        post.img_url = form.img_url.data
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', index=post_id, is_edit=True, form=form)


@app.route('/make-post', methods=['GET', 'POST'])
@super_users
def make_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        blog = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=dt.now().strftime('%B %d, %Y'),
            body=form.body.data,
            author=current_user,
            img_url=form.img_url.data
        )
        db.session.add(blog)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form=form)


@app.route('/delete/<id>')
@admin_only
def delete(id):
    blog = BlogPost.query.get(id)
    db.session.delete(blog)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/delete-comment')
@comment_author_only
def delete_comment():
    comment_id = request.args.get('comment_id')
    print(comment_id)
    comment = Comment.query.get(comment_id)
    print(comment)
    post = comment.post
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('show_post', index=post.id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email_entered = request.form.get('email')
        registered_password = request.form.get('password')
        password = generate_password_hash(registered_password,
                                          method=password_encrypt_method,
                                          salt_length=saltlength)
        print(current_user)
        if current_user.is_authenticated:
            priveledge = 'super_user'
        else:
            priveledge = 'basic' if Users.query.all() else 'root'
        user = Users(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=password,
            user_priveledge=priveledge
        )
        if Users.query.filter_by(email=email_entered).first():
            flash('This email-id already exists. Kindly login via the login page. ')
            return redirect(url_for('register'))
        else:
            db.session.add(user)
            db.session.commit()
            if not current_user.is_authenticated:
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                return redirect(url_for('register'))
    return render_template('register.html', form=form, registered=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email_id = request.form.get('email')
        raw_password = request.form.get('password')
        user = Users.query.filter_by(email=email_id).first()
        if not user:
            flash('This email-id does not exist. Please Register yourself if not already done . ')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, raw_password):
            flash('Password is incorrect')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template('register.html', form=form, registered=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/add-user')
@admin_only
def add_users():
    return redirect(url_for('register'))


if __name__ == "__main__":
    app.run(debug=True)
