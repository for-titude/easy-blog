from flask_bcrypt import Bcrypt  # 用于密码加密
from flask import Flask, session, redirect, url_for, request, render_template  # Flask核心组件
from flask_sqlalchemy import SQLAlchemy  # 数据库ORM
import os
import secrets  # 用于生成安全的随机密钥
from datetime import datetime, timedelta, timezone
from flask_migrate import Migrate  # 数据库迁移工具
from flask_mail import Mail, Message
import random
import string


def load_or_generate_secret_key(key_file='secret_key.txt'):
    """加载或生成密钥
    Args:
        key_file: 存储密钥的文件路径
    Returns:
        str: 密钥字符串
    """
    if not os.path.exists(key_file):
        # 如果文件不存在，生成一个新密钥并保存到文件
        key = secrets.token_hex(32)  # 生成一个 64 字节的强密钥
        with open(key_file, 'w') as f:
            f.write(key)
    else:
        # 如果文件存在，从文件中读取密钥
        with open(key_file, 'r') as f:
            key = f.read()
    return key


app = Flask(__name__)
app.secret_key = load_or_generate_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 设置会话有效期为7天
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'  # 使用 SQLite 数据库
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.qq.com'  # QQ邮箱SMTP服务器
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'admin@admin.com'  # 实际QQ邮箱
app.config['MAIL_PASSWORD'] = 'abcdfefiafn'  # QQ邮箱授权码
app.config['MAIL_DEFAULT_SENDER'] = ('我的博客', 'admin@admin.com')  # 替换为您的QQ邮箱
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
mail = Mail(app)


class User(db.Model):
    """用户数据模型"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # 用户名
    email = db.Column(db.String(120), unique=True, nullable=False)  # 邮箱
    password = db.Column(db.String(120), nullable=False)  # 密码哈希
    reset_code = db.Column(db.String(6), nullable=True)  # 重置密码验证码
    reset_code_expires = db.Column(db.DateTime, nullable=True)  # 验证码过期时间

    def set_password(self, password):
        """设置密码并生成哈希值"""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """验证密码
        Args:
            password: 待验证的密码
        Returns:
            bool: 密码是否正确
        """
        return bcrypt.check_password_hash(self.password, password)

    def generate_reset_code(self):
        """生成6位数字验证码并设置过期时间（10分钟）"""
        self.reset_code = ''.join(random.choices(string.digits, k=6))
        self.reset_code_expires = datetime.now() + timedelta(minutes=10)
        return self.reset_code

    def verify_reset_code(self, code):
        """验证重置密码的验证码"""
        if not self.reset_code or not self.reset_code_expires:
            return False
        if datetime.now() > self.reset_code_expires:
            return False
        return self.reset_code == code

    def clear_reset_code(self):
        """清除重置密码的验证码"""
        self.reset_code = None
        self.reset_code_expires = None

    def __repr__(self):
        return f'<User {self.username}>'


class Post(db.Model):
    """博客文章数据模型"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # 文章标题
    content = db.Column(db.Text, nullable=False)  # 文章内容
    publish = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))  # 发布时间
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 作者ID
    author = db.Column(db.String(80), nullable=False)  # 作者用户名

    # 建立与User模型的关系
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

    def __repr__(self):
        return f'<Post {self.title} - {self.publish}>'


# with app.app_context():
#     db.create_all()  # 创建数据库和表
#
# with app.app_context():
#     # 创建新用户
#     new_user = User(username='admin', email='admin@admin.com')
#     new_user.set_password('123456')  # 设置密码
#     db.session.add(new_user)
#     db.session.commit()
#     print(f'新用户 {new_user.username} 创建成功!')
#
# with app.app_context():
#     user = User.query.filter_by(username='admin').first()
#     if user and user.check_password('123456'):
#         print("密码正确!")
#     else:
#         print("密码错误!")

# with app.app_context():
#     user = User.query.get(1)  # 假设获取用户ID为1的用户
#     post = Post(title='第一天', content='helloworld')
#     post.author = user.username
#     post.user = user  # 将帖子与用户关联
#     db.session.add(post)
#     db.session.commit()


# 使用中间件进行认证
def login_user(username, remember=False):
    if remember:
        session.permanent = True  # 设置7天过期
    else:
        session.permanent = False  # 浏览器关闭即过期
    session["logged_in"] = True
    session["username"] = username


def logout_user():
    session.pop("logged_in", None)
    session.pop("username", None)


# 中间件：检查登录状态
class LoginRequiredMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # 获取请求路径
        path = environ["PATH_INFO"]

        # 定义需要登录才能访问的路径
        protected_paths = [
            "/",  # 首页
            "/post/create",  # 创建文章
            "/post/",  # 文章相关的所有路径
        ]

        # 定义不需要保护的路径（更完整的列表）
        public_paths = [
            "/login",
            "/error",
            "/logout",
            "/static",  # 添加静态文件路径
            "/register",
            "/forgot-password",
            "/reset-password"
        ]

        # 检查当前路径是否需要保护
        current_path = path.rstrip('/')  # 去掉路径末尾的斜杠，确保路径一致性（例如：/post/ 和 /post 都会被处理为 /post）。

        # 如果是公开路径，直接通过
        if current_path in public_paths:
            return self.app(environ, start_response)

        # 检查是否是受保护的路径
        needs_protection = False
        for protected_path in protected_paths:
            if current_path.startswith(protected_path):
                needs_protection = True
                break

        if not needs_protection and current_path == "":
            needs_protection = True

        if needs_protection:
            with app.request_context(environ):
                if not session.get("logged_in"):
                    response = redirect(url_for("login"))
                    return response(environ, start_response)

        return self.app(environ, start_response)


app.wsgi_app = LoginRequiredMiddleware(app.wsgi_app)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember") == "on"  # 获取记住我选项
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(username, remember)  # 传入记住我选项
                return redirect(url_for("index"))
            else:
                return redirect(url_for('error', message='用户名或密码不正确，请重试！'))
        except Exception as e:
            return redirect(url_for('error', message='系统错误，请稍后重试！'))
    return render_template("blog/login.html")


# 需要登录才能访问的页面
@app.route("/")
def index():
    user = User.query.filter_by(username=session.get("username")).first()
    if not user:
        # 只保留用户存在性检查，因为可能存在session有效但用户被删除的情况
        logout_user()  # 清除无效的会话
        return redirect(url_for('error', message="用户不存在"))

    posts = user.posts
    return render_template('blog/index.html', posts=posts)


@app.route("/error")
def error():
    message = request.args.get('message', '系统遇到了一些问题，请稍后重试。')
    return render_template('blog/errors.html', errors=message)


@app.route("/post/<int:post_id>", methods=["GET", ])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('blog/post.html', post=post)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/create", methods=["GET", "POST"])
def create_post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            return redirect(url_for('error', message="标题和内容不能为空"))

        user = User.query.filter_by(username=session.get("username")).first()
        if not user:
            return redirect(url_for('error', message="用户不存在"))

        try:
            post = Post(title=title, content=content, author=user.username, user=user)
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('post', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('error', message="创建文章失败，请重试"))

    return render_template("blog/create_post.html")


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
def edit_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        if post.author != session.get("username"):
            return redirect(url_for('error', message="没有权限编辑此文章"))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            content = request.form.get("content", "").strip()

            if not title or not content:
                return redirect(url_for('error', message="标题和内容不能为空"))

            post.title = title
            post.content = content
            db.session.commit()
            return redirect(url_for('post', post_id=post.id))

        # GET 请求时返回编辑表单
        return render_template('blog/edit_post.html', post=post)
    except Exception as e:
        db.session.rollback()
        return redirect(url_for('error', message=f"编辑文章失败，请重试: {str(e)}"))


@app.route("/post/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        if post.author != session.get("username"):
            return redirect(url_for('error', message="没有权限删除此文章"))

        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        return redirect(url_for('error', message=f"删除文章失败，请重试: {str(e)}"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # 表单验证
        if not username or not email or not password or not confirm_password:
            return redirect(url_for('error', message="所有字段都必须填写"))

        if password != confirm_password:
            return redirect(url_for('error', message="两次输入的密码不一致"))

        # 检查用户名和邮箱是否已存在
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            if existing_user.username == username:
                return redirect(url_for('error', message="用户名已被使用"))
            else:
                return redirect(url_for('error', message="邮箱已被注册"))

        try:
            # 创建新用户
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # 自动登录
            login_user(username)
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('error', message="注册失败，请稍后重试"))

    return render_template("blog/register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            return redirect(url_for('error', message="请输入邮箱地址"))

        user = User.query.filter_by(email=email).first()
        if not user:
            # 为了安全，即使用户不存在也显示成功信息
            return render_template("blog/forgot_password_confirm.html", email=email)

        # 生成验证码并保存
        reset_code = user.generate_reset_code()
        db.session.commit()

        # 发送验证码邮件
        try:
            msg = Message(
                subject="重置您的博客密码",
                recipients=[user.email],
                html=render_template("blog/reset_email.html",
                                     username=user.username,
                                     reset_code=reset_code)
            )
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"发送邮件失败: {str(e)}")
            return redirect(url_for('error', message="发送验证码失败，请稍后重试"))

        return render_template("blog/forgot_password_confirm.html", email=email)

    return render_template("blog/forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.args.get("email", "")

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        code = request.form.get("code", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not email or not code or not new_password or not confirm_password:
            return redirect(url_for('error', message="所有字段都必须填写"))

        if new_password != confirm_password:
            return redirect(url_for('error', message="两次输入的密码不一致"))

        user = User.query.filter_by(email=email).first()
        if not user:
            return redirect(url_for('error', message="用户不存在"))

        # 验证验证码
        if not user.verify_reset_code(code):
            return redirect(url_for('error', message="验证码无效或已过期"))

        # 检查新密码是否与旧密码相同
        if user.check_password(new_password):
            return redirect(url_for('error', message="新密码不能与旧密码相同"))

        # 更新密码
        user.set_password(new_password)
        user.clear_reset_code()
        db.session.commit()

        # 显示成功信息
        return render_template("blog/reset_success.html")

    return render_template("blog/reset_password.html", email=email)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
