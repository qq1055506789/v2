from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json, os, subprocess, uuid, datetime, pyotp, bcrypt, redis, logging

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
login_manager = LoginManager(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="redis://localhost:6379", default_limits=["5 per minute"])
logging.basicConfig(filename='/var/log/v2ray/panel.log', level=logging.INFO)

CONFIG_DIR = "/usr/local/etc/xray"
USER_CONFIG = os.path.join(CONFIG_DIR, "users.json")
LINKS_FILE = os.path.join(CONFIG_DIR, "links.txt")
API_PORT = 10085
r = redis.Redis(host='localhost', port=6379, db=0)
users = {"admin": bcrypt.hashpw(os.environ.get("WEB_ADMIN_PASS", "default_pass").encode(), bcrypt.gensalt()).decode()}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id == "admin" else None

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp = request.form['totp']
        if username == "admin" and bcrypt.checkpw(password.encode(), users[username].encode()):
            if pyotp.TOTP('JBSWY3DPEHPK3PXP').verify(totp):
                login_user(User(username))
                logging.info(f"用户 {username} 登录成功")
                return redirect(url_for('index'))
            else:
                flash("双因素认证失败")
                logging.warning(f"用户 {username} TOTP 验证失败")
        else:
            flash("用户名或密码错误")
            logging.warning(f"用户 {username} 登录失败")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        with open(USER_CONFIG, 'r') as f:
            users_data = json.load(f)
        users = []
        for user in users_data:
            traffic = json.loads(r.get(f"traffic:{user['email']}") or b'{"uplink": 0, "downlink": 0, "total": 0}')
            users.append({
                'email': user['email'], 'traffic_limit': user['traffic_limit'], 'expire_date': user['expire_date'],
                'auto_renew': user['auto_renew'], 'disabled': user.get('disabled', False),
                'uplink': traffic['uplink'], 'downlink': traffic['downlink'], 'total': traffic['total']
            })
        links = open(LINKS_FILE).readlines() if os.path.exists(LINKS_FILE) else []
        return render_template('index.html', users=users, links=links)
    except Exception as e:
        logging.error(f"加载面板失败: {str(e)}")
        flash(f"加载失败: {str(e)}")
        return render_template('index.html', users=[], links=[])

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    try:
        email = request.form['email']
        with open(USER_CONFIG, 'r') as f:
            users_data = json.load(f)
        if any(u['email'] == email for u in users_data):
            flash("用户已存在")
            return redirect(url_for('index'))
        new_user = {
            "id": str(uuid.uuid4()), "alterId": 0, "email": email,
            "traffic_limit": request.form['traffic_limit'], "expire_date": request.form['expire_date'],
            "auto_renew": request.form.get('auto_renew') == 'on', "disabled": False
        }
        users_data.append(new_user)
        with open(USER_CONFIG, 'w') as f:
            json.dump(users_data, f, indent=2)
        subprocess.run(["/root/v2ray-install/v2ray_user.sh", "add", email])
        logging.info(f"添加用户 {email}")
        flash("用户添加成功")
    except Exception as e:
        logging.error(f"添加用户失败: {str(e)}")
        flash(f"添加用户失败: {str(e)}")
    return redirect(url_for('index'))

@app.route('/edit_user/<email>', methods=['GET', 'POST'])
@login_required
def edit_user(email):
    try:
        with open(USER_CONFIG, 'r') as f:
            users_data = json.load(f)
        user = next((u for u in users_data if u['email'] == email), None)
        if not user:
            flash("用户不存在")
            return redirect(url_for('index'))
        if request.method == 'POST':
            user['email'] = request.form['email']
            user['traffic_limit'] = request.form['traffic_limit']
            user['expire_date'] = request.form['expire_date']
            user['auto_renew'] = request.form.get('auto_renew') == 'on'
            with open(USER_CONFIG, 'w') as f:
                json.dump(users_data, f, indent=2)
            subprocess.run(["/root/v2ray-install/v2ray_user.sh", "edit", email, "email", user['email']])
            subprocess.run(["/root/v2ray-install/v2ray_user.sh", "edit", email, "traffic_limit", user['traffic_limit']])
            subprocess.run(["/root/v2ray-install/v2ray_user.sh", "edit", email, "expire_date", user['expire_date']])
            subprocess.run(["/root/v2ray-install/v2ray_user.sh", "edit", email, "auto_renew", str(user['auto_renew']).lower()])
            logging.info(f"编辑用户 {email}")
            flash("用户更新成功")
            return redirect(url_for('index'))
        return render_template('edit_user.html', user=user)
    except Exception as e:
        logging.error(f"编辑用户失败: {str(e)}")
        flash(f"编辑用户失败: {str(e)}")
        return redirect(url_for('index'))

@app.route('/delete_user/<email>')
@login_required
def delete_user(email):
    try:
        subprocess.run(["/root/v2ray-install/v2ray_user.sh", "delete", email])
        logging.info(f"删除用户 {email}")
        flash("用户删除成功")
    except Exception as e:
        logging.error(f"删除用户失败: {str(e)}")
        flash(f"删除用户失败: {str(e)}")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
