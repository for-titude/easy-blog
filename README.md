
# Flask 博客系统

## 项目概述

这是一个基于 Flask 框架的简单博客系统开发项目，支持用户注册、登录、发布博客文章、重置密码等功能。项目使用 SQLite 数据库存储数据，Flask-Mail 负责处理邮件发送，数据库迁移通过 Flask-Migrate 管理。

## 安装与运行

### 系统需求

- Python 3.6+

- Flask

- Flask-SQLAlchemy

- Flask-Migrate

- Flask-BCrypt

- Flask-Mail

- python-dotenv (用于环境变量管理)

### 安装依赖

1. 确保 Python 已安装。

2. 使用 pip 安装项目依赖：

```bash
pip install -r requirements.txt
```

### 环境配置

1. 创建一个 `.env` 文件，用于存储项目的环境变量：

```env
SECRET_KEY=your_secret_key_here
MAIL_SERVER=smtp.qq.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_qq_email@example.com
MAIL_PASSWORD=your_qq_email_authorization_code
```

2. 确保 `.env` 文件中的值与你的实际环境一致：
   
   - `SECRET_KEY`：一个安全的密钥，用于会话加密。
   
   - `MAIL_USERNAME`：你的 QQ 邮箱地址。
   
   - `MAIL_PASSWORD`：QQ 邮箱的授权码（不是你的邮箱密码）。

### 数据库初始化

运行以下命令以创建数据库和表：

```bash
flask db init
flask db migrate
flask db upgrade
```

### 项目配置

确保项目树结构正确，例如：

```
blog-system/
├── app.py
├── .env
├── blog/
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── forgot_password.html
│   │   ├── reset_password.html
│   │   ├── index.html
│   │   ├── post.html
│   │   ├── create_post.html
│   │   └── edit_post.html
│   └── static/
├── requirements.txt
├── secret_key.txt
└── blog.db
```

### 运行项目

1. 启动 Flask 应用：

```bash
python app.py
```

2. 访问应用：
   打开浏览器，访问 `http://127.0.0.1:5000`。

## 功能总览

### 用户注册

- 访问 `/register` 路由。

- 填写用户名、邮箱、密码和确认密码。

- 如果邮箱或用户名已被注册，会提示用户。

### 用户登录与注销

- 访问 `/login` 路由，使用用户名和密码登录。

- 登录后，可以通过点击 “Logout” 按钮注销。

### 发布博客文章

- 登录后，访问 `/post/create` 路由。

- 填写文章标题和内容。

- 点击 “发布” 按钮提交文章。

### 查看文章

- 文章会显示在首页 `/`。

- 点击文章标题，可查看文章详情。

### 编辑或删除文章

- 登录后，访问文章详情页面 `/post/<post_id>`。

- 点击 “编辑” 按钮修改文章。

- 点击 “删除” 按钮删除文章。

### 密码重置

- 访问 `/forgot-password` 路由。

- 输入注册时的邮箱，系统会发送验证码。

- 收到验证码后，访问 `/reset-password` 路由。

- 输入验证码、新密码和确认密码进行密码重置。

## 技术栈

### 后端

- **Flask**：Web 框架，用于处理请求和响应。

- **Flask-SQLAlchemy**：ORM 工具，用于数据库操作。

- **Flask-Migrate**：数据库迁移工具，管理数据表结构变更。

- **Flask-BCrypt**：用于密码加密。

- **Flask-Mail**：邮件发送模块。

- **python-dotenv**：用于加载环境变量。

### 前端

- **HTML/CSS**：用于构建页面结构和样式。

- **Jinja2**：Flask 的模板引擎，用于动态生成 HTML 页面。

### 数据库

- **SQLite**：默认使用的轻量级关系型数据库。

## 数据模型

### 用户模型

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    reset_code = db.Column(db.String(6), nullable=True)
    reset_code_expires = db.Column(db.DateTime, nullable=True)
    posts = db.relationship('Post', backref='user', lazy=True)
```

### 文章模型

```python
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    publish = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.Column(db.String(80), nullable=False)
```

## 开发指南

### 路由结构

- 用户注册：`/register`

- 用户登录：`/login`

- 用户注销：`/logout`

- 首页：`/`

- 查看文章：`/post/<post_id>`

- 创建文章：`/post/create`

- 编辑文章：`/post/<post_id>/edit`

- 删除文章：`/post/<post_id>/delete`

- 忘记密码：`/forgot-password`

- 重置密码：`/reset-password`

### 路由实现示例

#### 注册路由

```python
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

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            if existing_user.username == username:
                return redirect(url_for('error', message="用户名已被使用"))
            else:
                return redirect(url_for('error', message="邮箱已被注册"))

        # 创建新用户
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # 登录用户
        login_user(username)
        return redirect(url_for('index'))

    return render_template("blog/register.html")
```

### 模板文件

模板文件位于 `blog/templates` 目录中，主要包括以下页面：

- 基础页面：`base.html`

- 登录页面：`login.html`

- 注册页面：`register.html`

- 忘记密码页面：`forgot_password.html`

- 重置密码页面：`reset_password.html`

- 首页：`index.html`

- 文章页面：`post.html`

- 创建文章页面：`create_post.html`

- 编辑文章页面：`edit_post.html`

## 测试

### 单元测试

建议使用 `pytest` 或 `unittest` 编写单元测试，覆盖关键功能，如用户注册、登录、文章创建、编辑和删除等。

### 集成测试

通过 Postman 或其他工具模拟 API 请求，测试路由和功能的完整性。

## 贡献指南

1. **Fork** 仓库到你的个人账户。

2. 创建新分支：
   
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. 提交你的更改：
   
   ```bash
   git commit -m "Add new feature: your-feature-name"
   ```

4. 推送到你的分支：
   
   ```bash
   git push origin feature/your-feature-name
   ```

5. 提交 Pull Request，描述你的修改和新功能。

## 问题反馈

如果你在使用过程中遇到任何问题，可以通过以下方式向我们反馈：

- **GitHub Issues**：在项目仓库中创建一个新问题。

- **邮箱**：2650359040@qq.com

## 开源协议

本项目采用 [MIT License](https://opensource.org/licenses/MIT) 许可证。
