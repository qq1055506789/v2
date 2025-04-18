#!/bin/bash

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    echo "此脚本必须以 root 权限运行"
    exit 1
fi

# 定义变量
DOMAIN=""
V2RAY_PORT=10000
WEBSOCKET_PATH="/ray"
NGINX_CONF="/etc/nginx/sites-available/v2ray"
WEBSITE_DIR="/var/www/html"
WEB_PANEL_DIR="/var/www/panel"
XRAY_VERSION="1.8.4"
CONFIG_DIR="/usr/local/etc/xray"
USER_CONFIG="$CONFIG_DIR/users.json"
LINKS_FILE="$CONFIG_DIR/links.txt"
TRAFFIC_LOG="$CONFIG_DIR/traffic.log"
TRAFFIC_LIMIT="100GB"
API_PORT=10085
WEB_PANEL_PORT=8080
WEB_ADMIN_USER="admin"
WEB_ADMIN_PASS=$(openssl rand -base64 12)
INSTALL_DIR="/root/v2ray-install"
VENV_DIR="$WEB_PANEL_DIR/venv"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[信息] $1${NC}"; }
error() { echo -e "${RED}[错误] $1${NC}"; exit 1; }

# 检查系统
check_system() {
    if [[ -f /etc/lsb-release || -f /etc/debian_version ]]; then
        log "检测到 Debian/Ubuntu 系统"
    else
        error "仅支持 Debian/Ubuntu 系统"
    fi
}

# 获取用户输入
get_user_input() {
    read -p "请输入域名（例如 example.com）： " DOMAIN
    [[ -z "$DOMAIN" ]] && error "域名不能为空"
    read -p "请输入 WebSocket 路径（默认 /ray）： " input_path
    [[ ! -z "$input_path" ]] && WEBSOCKET_PATH="$input_path"
    read -p "请输入初始用户数量（默认 1）： " user_count
    [[ -z "$user_count" || ! "$user_count" =~ ^[0-9]+$ ]] && user_count=1
    read -p "请输入每个用户的总流量限制（默认 100GB，格式如 50GB）： " input_traffic
    [[ ! -z "$input_traffic" ]] && TRAFFIC_LIMIT="$input_traffic"
}

# 安装依赖
install_dependencies() {
    log "安装依赖"
    apt update -y && apt upgrade -y || error "APT 更新失败"
    apt install -y curl wget unzip nginx certbot python3-certbot-nginx socat jq python3-pip python3-venv apache2-utils redis logrotate net-tools ufw dnsutils || error "依赖安装失败"
    systemctl start redis
    systemctl enable redis
    mkdir -p $VENV_DIR
    python3 -m venv $VENV_DIR || error "虚拟环境创建失败"
    source $VENV_DIR/bin/activate
    pip install flask flask-login flask-limiter==3.7.0 pyotp bcrypt redis || {
        deactivate
        error "Python 依赖安装失败"
    }
    deactivate
}

# 安装 Xray
install_xray() {
    log "安装 Xray $XRAY_VERSION"
    wget "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip" || error "Xray 下载失败"
    unzip -o Xray-linux-64.zip -d /usr/local/bin/ || error "Xray 解压失败"
    mv /usr/local/bin/xray /usr/local/bin/xray-core
    chmod +x /usr/local/bin/xray-core
    rm Xray-linux-64.zip
    mkdir -p $CONFIG_DIR
}

# 生成多用户配置
generate_users() {
    log "生成 $user_count 个用户配置"
    USERS=()
    expire_date=$(date -d "+30 days" +%Y-%m-%d)
    for ((i=1; i<=user_count; i++)); do
        UUID=$(cat /proc/sys/kernel/random/uuid)
        USERS+=("{\"id\": \"$UUID\", \"alterId\": 0, \"email\": \"user$i@$DOMAIN\", \"traffic_limit\": \"$TRAFFIC_LIMIT\", \"expire_date\": \"$expire_date\", \"auto_renew\": true, \"disabled\": false}")
    done
    echo "["$(IFS=,; echo "${USERS[*]}")"]" > $USER_CONFIG
}

# 配置 Xray
configure_xray() {
    log "配置 Xray"
    USERS_JSON=$(cat $USER_CONFIG | jq '[.[] | {id: .id, alterId: .alterId, email: .email, disabled: .disabled}]')
    cat > $CONFIG_DIR/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "api": {
    "enabled": true,
    "listen": "127.0.0.1:$API_PORT",
    "services": ["StatsService"]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "port": $V2RAY_PORT,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": $USERS_JSON,
        "default": {"alterId": 0}
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "$WEBSOCKET_PATH"}
      }
    },
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": $USERS_JSON,
        "decryption": "none",
        "fallbacks": [{"dest": 80}]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "www.microsoft.com:443",
          "serverNames": ["www.microsoft.com"],
          "privateKey": "$(/usr/local/bin/xray-core x25519 | grep Private | awk '{print $3}')",
          "publicKey": "$(/usr/local/bin/xray-core x25519 | grep Public | awk '{print $3}')"
        }
      }
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
}

# 创建 Xray 服务
create_xray_service() {
    log "创建 Xray 服务"
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray-core -c $CONFIG_DIR/config.json
Restart=on-failure
User=nobody
Environment="XRAY_VMESS_AEAD_FORCED=false"
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray || error "Xray 服务启动失败"
}

# 配置 Nginx
configure_nginx() {
    log "配置 Nginx"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    htpasswd -bc /etc/nginx/.htpasswd $WEB_ADMIN_USER $WEB_ADMIN_PASS
    cat > $NGINX_CONF << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    access_log /var/log/v2ray/nginx_access.log;
    error_log /var/log/v2ray/nginx_error.log;
    root $WEBSITE_DIR;
    index index.html;
    location $WEBSOCKET_PATH {
        proxy_pass http://127.0.0.1:$V2RAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    location /panel {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://127.0.0.1:$WEB_PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
    ln -sf $NGINX_CONF /etc/nginx/sites-enabled/v2ray
    mkdir -p /var/log/v2ray
    nginx -t || {
        log "Nginx 配置测试失败，查看日志 /var/log/v2ray/nginx_error.log"
        cat /var/log/v2ray/nginx_error.log
        error "Nginx 配置错误"
    }
    systemctl restart nginx || error "Nginx 重启失败"
}

# 创建伪装网站
create_website() {
    log "创建伪装网站"
    mkdir -p $WEBSITE_DIR
    echo "<html><head><title>欢迎</title></head><body><h1>欢迎访问 $DOMAIN</h1></body></html>" > $WEBSITE_DIR/index.html
    chown -R www-data:www-data $WEBSITE_DIR
}

# 检查域名解析
check_domain() {
    log "检查域名解析"
    if ! command -v dig >/dev/null; then
        apt install -y dnsutils || log "无法安装 dig，请手动验证域名解析"
    fi
    if command -v dig >/dev/null; then
        ip=$(dig +short $DOMAIN | tail -n 1)
        local_ip=$(ip addr show | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
        if [[ -z "$ip" || "$ip" != "$local_ip" ]]; then
            log "警告：域名 $DOMAIN 未正确解析到本机 IP ($local_ip)"
            error "请确保域名解析正确"
        fi
    fi
}

# 获取 SSL 证书
get_ssl_certificate() {
    log "获取 SSL 证书"
    systemctl stop nginx
    certbot certonly --standalone --preferred-challenges http --agree-tos --register-unsafely-without-email -d "$DOMAIN" --non-interactive --force-renewal || {
        log "证书申请失败，查看日志 /var/log/letsencrypt/letsencrypt.log"
        cat /var/log/letsencrypt/letsencrypt.log
        error "证书申请失败"
    }
    [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]] || error "证书文件未生成"
    systemctl start nginx
}

# 配置 logrotate
configure_logrotate() {
    log "配置 logrotate"
    cat > /etc/logrotate.d/v2ray << EOF
$TRAFFIC_LOG /var/log/xray/*.log /var/log/v2ray/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0644 www-data www-data
}
EOF
}

# 配置防火墙
configure_firewall() {
    log "配置防火墙"
    if command -v ufw >/dev/null; then
        ufw --force enable
        ufw allow 80
        ufw allow 443
        ufw status
    else
        log "未安装 ufw，请手动开放 80 和 443 端口"
    fi
}

# 创建流量监控脚本
create_traffic_monitor() {
    log "创建流量监控脚本"
    cat > $INSTALL_DIR/v2ray_traffic_monitor.sh << EOF
#!/bin/bash
CONFIG_DIR="$CONFIG_DIR"
USER_CONFIG="\$CONFIG_DIR/users.json"
TRAFFIC_LOG="\$CONFIG_DIR/traffic.log"
API_PORT=$API_PORT
$VENV_DIR/bin/python - << 'PYTHON'
import asyncio
import aiohttp
import json
import redis
import logging
import datetime
logging.basicConfig(filename='/var/log/v2ray/monitor.log', level=logging.INFO)
r = redis.Redis(host='localhost', port=6379, db=0)
async def check_user(email, limit_bytes, expire_date):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:$API_PORT/stats/user/uplink?email={email}") as resp:
                uplink = int((await resp.json())['value'])
            async with session.get(f"http://127.0.0.1:$API_PORT/stats/user/downlink?email={email}") as resp:
                downlink = int((await resp.json())['value'])
            total = uplink + downlink
            with open("$TRAFFIC_LOG", "a") as f:
                f.write(f"[{datetime.datetime.now()}] {email} - 上行: {uplink}, 下行: {downlink}, 总计: {total}\n")
            r.set(f"traffic:{email}", json.dumps({"uplink": uplink, "downlink": downlink, "total": total}))
            if total >= limit_bytes:
                with open("$USER_CONFIG", "r") as f:
                    users = json.load(f)
                for user in users:
                    if user["email"] == email:
                        user["disabled"] = True
                with open("$USER_CONFIG", "w") as f:
                    json.dump(users, f, indent=2)
            expiry = datetime.datetime.strptime(expire_date, "%Y-%m-%d").timestamp()
            if expiry < datetime.datetime.now().timestamp():
                with open("$USER_CONFIG", "r") as f:
                    users = json.load(f)
                for user in users:
                    if user["email"] == email:
                        user["disabled"] = True
                with open("$USER_CONFIG", "w") as f:
                    json.dump(users, f, indent=2)
    except Exception as e:
        logging.error(f"流量检查失败 ({email}): {str(e)}")
async def main():
    try:
        with open("$USER_CONFIG") as f:
            users = json.load(f)
        tasks = []
        for user in users:
            limit = int(user["traffic_limit"].replace("GB", "")) * 1024**3
            tasks.append(check_user(user["email"], limit, user["expire_date"]))
        await asyncio.gather(*tasks)
        subprocess.run(["systemctl", "restart", "xray"])
    except Exception as e:
        logging.error(f"流量监控主程序失败: {str(e)}")
asyncio.run(main())
PYTHON
EOF
    chmod +x $INSTALL_DIR/v2ray_traffic_monitor.sh
    echo "* * * * * $INSTALL_DIR/v2ray_traffic_monitor.sh" >> /etc/crontab
}

# 创建健康检查脚本
create_health_check() {
    log "创建健康检查脚本"
    cat > $INSTALL_DIR/v2ray_health_check.sh << EOF
#!/bin/bash
LOG="/var/log/v2ray/health.log"
check_service() {
    local service=\$1
    systemctl is-active --quiet \$service || {
        echo "[$(date)] \$service 未运行，尝试重启" >> \$LOG
        systemctl restart \$service
    }
}
check_service xray
check_service nginx
check_service redis
curl -s http://127.0.0.1:$WEB_PANEL_PORT >/dev/null || {
    echo "[$(date)] Web 面板不可用，尝试重启" >> \$LOG
    systemctl restart v2ray-panel
}
curl -s http://127.0.0.1:$API_PORT/stats >/dev/null || {
    echo "[$(date)] Xray API 不可用，尝试重启 xray" >> \$LOG
    systemctl restart xray
}
EOF
    chmod +x $INSTALL_DIR/v2ray_health_check.sh
    echo "*/5 * * * * $INSTALL_DIR/v2ray_health_check.sh" >> /etc/crontab
}

# 创建用户管理工具
create_user_manager() {
    log "创建用户管理工具"
    cat > $INSTALL_DIR/v2ray_user.sh << EOF
#!/bin/bash
CONFIG_DIR="$CONFIG_DIR"
USER_CONFIG="\$CONFIG_DIR/users.json"
LINKS_FILE="\$CONFIG_DIR/links.txt"
DOMAIN="$DOMAIN"
WEBSOCKET_PATH="$WEBSOCKET_PATH"
TRAFFIC_LIMIT="$TRAFFIC_LIMIT"
add_user() {
    local email=\$1
    if jq -e ".[] | select(.email == \"\$email\")" \$USER_CONFIG > /dev/null; then
        echo "用户 \$email 已存在"
        exit 1
    fi
    local uuid=\$(cat /proc/sys/kernel/random/uuid)
    local expire_date=\$(date -d "+30 days" +%Y-%m-%d)
    local new_user="{\"id\": \"\$uuid\", \"alterId\": 0, \"email\": \"\$email\", \"traffic_limit\": \"\$TRAFFIC_LIMIT\", \"expire_date\": \"\$expire_date\", \"auto_renew\": true, \"disabled\": false}"
    jq ". += [\$new_user]" \$USER_CONFIG > \$CONFIG_DIR/users_temp.json
    mv \$CONFIG_DIR/users_temp.json \$USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 \$email 已添加"
}
delete_user() {
    local email=\$1
    if ! jq -e ".[] | select(.email == \"\$email\")" \$USER_CONFIG > /dev/null; then
        echo "用户 \$email 不存在"
        exit 1
    fi
    jq "del(.[] | select(.email == \"\$email\"))" \$USER_CONFIG > \$CONFIG_DIR/users_temp.json
    mv \$CONFIG_DIR/users_temp.json \$USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 \$email 已删除"
}
edit_user() {
    local email=\$1
    local field=\$2
    local value=\$3
    if ! jq -e ".[] | select(.email == \"\$email\")" \$USER_CONFIG > /dev/null; then
        echo "用户 \$email 不存在"
        exit 1
    fi
    jq "(.[] | select(.email == \"\$email\") | .\$field) = \"\$value\"" \$USER_CONFIG > \$CONFIG_DIR/users_temp.json
    mv \$CONFIG_DIR/users_temp.json \$USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 \$email 已更新"
}
list_users() {
    jq -r '.[] | "\(.email) \(.traffic_limit) \(.expire_date) \(.auto_renew)"' \$USER_CONFIG
}
import_users() {
    local csv_file=\$1
    while IFS=, read -r email traffic_limit expire_date auto_renew; do
        add_user \$email
        edit_user \$email traffic_limit \$traffic_limit
        edit_user \$email expire_date \$expire_date
        edit_user \$email auto_renew \$auto_renew
    done < \$csv_file
}
export_users() {
    jq -r '.[] | "\(.email),\(.traffic_limit),\(.expire_date),\(.auto_renew)"' \$USER_CONFIG > users.csv
    echo "用户已导出到 users.csv"
}
update_links() {
    rm -f \$LINKS_FILE
    users=\$(jq -c '.[]' \$USER_CONFIG)
    while read -r user; do
        local uuid=\$(echo "\$user" | jq -r '.id')
        local email=\$(echo "\$user" | jq -r '.email')
        VMESS_JSON="{\"v\": \"2\", \"ps\": \"VMess_WS_${DOMAIN}_\${email}\", \"add\": \"$DOMAIN\", \"port\": \"443\", \"id\": \"\$uuid\", \"aid\": \"0\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$DOMAIN\", \"path\": \"$WEBSOCKET_PATH\", \"tls\": \"tls\"}"
        echo "\${email} VMess: vmess://\$(echo -n \$VMESS_JSON | base64 -w 0)" >> \$LINKS_FILE
        VLESS_LINK="vless://\$uuid@$DOMAIN:443?security=reality&encryption=none&pbk=\$(/usr/local/bin/xray-core x25519 | grep Public | awk '{print \$3}')&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&remark=VLESS_Reality_${DOMAIN}_\${email}"
        echo "\${email} VLESS Reality: \$VLESS_LINK" >> \$LINKS_FILE
    done <<< "\$users"
}
case "\$1" in
    add) add_user "\$2";;
    delete) delete_user "\$2";;
    edit) edit_user "\$2" "\$3" "\$4";;
    list) list_users;;
    import) import_users "\$2";;
    export) export_users;;
    *) echo "用法: v2ray-user [add|delete|edit|list|import|export]"; exit 1;;
esac
EOF
    chmod +x $INSTALL_DIR/v2ray_user.sh
}

# 创建 Web 面板
create_web_panel() {
    log "创建 Web 面板"
    mkdir -p $WEB_PANEL_DIR/templates $WEB_PANEL_DIR/static
    [[ -f "$VENV_DIR/bin/python" ]] || error "虚拟环境 Python 未找到"
    cat > $WEB_PANEL_DIR/app.py << EOF
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
CONFIG_DIR = "$CONFIG_DIR"
USER_CONFIG = os.path.join(CONFIG_DIR, "users.json")
LINKS_FILE = os.path.join(CONFIG_DIR, "links.txt")
API_PORT = $API_PORT
r = redis.Redis(host='localhost', port=6379, db=0)
users = {"$WEB_ADMIN_USER": bcrypt.hashpw("$WEB_ADMIN_PASS".encode(), bcrypt.gensalt()).decode()}
class User(UserMixin):
    def __init__(self, id):
        self.id = id
@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id == "$WEB_ADMIN_USER" else None
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp = request.form['totp']
        if username == "$WEB_ADMIN_USER" and bcrypt.checkpw(password.encode(), users[username].encode()):
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
        subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "add", email])
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
            subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "edit", email, "email", user['email']])
            subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "edit", email, "traffic_limit", user['traffic_limit']])
            subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "edit", email, "expire_date", user['expire_date']])
            subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "edit", email, "auto_renew", str(user['auto_renew']).lower()])
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
        subprocess.run(["$INSTALL_DIR/v2ray_user.sh", "delete", email])
        logging.info(f"删除用户 {email}")
        flash("用户删除成功")
    except Exception as e:
        logging.error(f"删除用户失败: {str(e)}")
        flash(f"删除用户失败: {str(e)}")
    return redirect(url_for('index'))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=$WEB_PANEL_PORT)
EOF
    cat > $WEB_PANEL_DIR/templates/login.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>登录</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>登录 V2Ray 面板</h1>
    {% for message in get_flashed_messages() %}
        <p style="color: red;">{{ message }}</p>
    {% endfor %}
    <form method="post">
        <label>用户名: <input type="text" name="username" required></label><br>
        <label>密码: <input type="password" name="password" required></label><br>
        <label>TOTP: <input type="text" name="totp" required></label><br>
        <button type="submit">登录</button>
    </form>
</body>
</html>
EOF
    cat > $WEB_PANEL_DIR/templates/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>V2Ray 管理面板</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>V2Ray 管理面板</h1>
    <p><a href="/logout">登出</a></p>
    {% for message in get_flashed_messages() %}
        <p style="color: red;">{{ message }}</p>
    {% endfor %}
    <h2>添加用户</h2>
    <form method="post" action="/add_user">
        <label>邮箱: <input type="email" name="email" required></label><br>
        <label>流量限制: <input type="text" name="traffic_limit" value="$TRAFFIC_LIMIT" required></label><br>
        <label>到期日期: <input type="date" name="expire_date" required></label><br>
        <label>自动续期: <input type="checkbox" name="auto_renew" checked></label><br>
        <button type="submit">添加</button>
    </form>
    <h2>用户信息</h2>
    <table>
        <tr>
            <th>邮箱</th>
            <th>流量限制</th>
            <th>到期日期</th>
            <th>自动续期</th>
            <th>上行流量 (GB)</th>
            <th>下行流量 (GB)</th>
            <th>总流量 (GB)</th>
            <th>状态</th>
            <th>操作</th>
        </tr>
        {% for user in users %}
        <tr>
            <td>{{ user.email }}</td>
            <td>{{ user.traffic_limit }}</td>
            <td>{{ user.expire_date }}</td>
            <td>{{ '是' if user.auto_renew else '否' }}</td>
            <td>{{ '%.2f' % (user.uplink / (1024**3)) }}</td>
            <td>{{ '%.2f' % (user.downlink / (1024**3)) }}</td>
            <td>{{ '%.2f' % (user.total / (1024**3)) }}</td>
            <td>{{ '禁用' if user.disabled else '启用' }}</td>
            <td>
                <a href="/edit_user/{{ user.email }}">编辑</a>
                <a href="/delete_user/{{ user.email }}">删除</a>
            </td>
        </tr>
        {% endfor %}
    </table>
    <h2>V2RayN 链接</h2>
    <pre>{{ links | join('') }}</pre>
</body>
</html>
EOF
    cat > $WEB_PANEL_DIR/templates/edit_user.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>编辑用户</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <h1>编辑用户</h1>
    {% for message in get_flashed_messages() %}
        <p style="color: red;">{{ message }}</p>
    {% endfor %}
    <form method="post">
        <label>邮箱: <input type="email" name="email" value="{{ user.email }}" required></label><br>
        <label>流量限制: <input type="text" name="traffic_limit" value="{{ user.traffic_limit }}" required></label><br>
        <label>到期日期: <input type="date" name="expire_date" value="{{ user.expire_date }}" required></label><br>
        <label>自动续期: <input type="checkbox" name="auto_renew" {{ 'checked' if user.auto_renew else '' }}></label><br>
        <button type="submit">保存</button>
    </form>
    <p><a href="/">返回</a></p>
</body>
</html>
EOF
    cat > $WEB_PANEL_DIR/static/style.css << EOF
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
form { margin: 20px 0; }
pre { background-color: #f9f9f9; padding: 10px; }
EOF
    chown -R www-data:www-data $WEB_PANEL_DIR
    chmod -R 755 $WEB_PANEL_DIR
    if netstat -tuln | grep ":$WEB_PANEL_PORT " >/dev/null; then
        log "端口 $WEB_PANEL_PORT 被占用，释放端口"
        fuser -k $WEB_PANEL_PORT/tcp
    fi
    log "测试 Flask 应用"
    timeout 10 $VENV_DIR/bin/python $WEB_PANEL_DIR/app.py &>/var/log/v2ray/panel_test.log &
    sleep 2
    if ! netstat -tuln | grep ":$WEB_PANEL_PORT " >/dev/null; then
        log "Flask 启动测试失败，查看 /var/log/v2ray/panel_test.log"
        cat /var/log/v2ray/panel_test.log
        error "Flask 应用无法启动"
    fi
    killall python3 2>/dev/null
    cat > /etc/systemd/system/v2ray-panel.service << EOF
[Unit]
Description=V2Ray Web Panel
After=network.target
[Service]
Type=simple
ExecStart=$VENV_DIR/bin/python $WEB_PANEL_DIR/app.py
Restart=on-failure
User=www-data
WorkingDirectory=$WEB_PANEL_DIR
StandardOutput=append:/var/log/v2ray/panel.log
StandardError=append:/var/log/v2ray/panel.log
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable v2ray-panel
    systemctl start v2ray-panel
    sleep 2
    systemctl is-active v2ray-panel >/dev/null || {
        log "Web 面板服务启动失败，查看日志 /var/log/v2ray/panel.log"
        cat /var/log/v2ray/panel.log
        systemctl status v2ray-panel
        error "Web 面板服务无法启动"
    }
    netstat -tuln | grep ":$WEB_PANEL_PORT " >/dev/null || {
        log "端口 $WEB_PANEL_PORT 未监听，检查服务状态"
        systemctl status v2ray-panel
        error "Web 面板未正确运行"
    }
}

# 主函数
main() {
    check_system
    get_user_input
    check_domain
    mkdir -p $INSTALL_DIR
    install_dependencies
    install_xray
    generate_users
    configure_xray
    create_xray_service
    get_ssl_certificate
    configure_nginx
    create_website
    configure_logrotate
    configure_firewall
    create_traffic_monitor
    create_health_check
    create_user_manager
    create_web_panel
    systemctl restart nginx
    log "安装完成！"
    echo -e "${YELLOW}配置信息："
    echo "域名: $DOMAIN"
    echo "Web 面板: https://$DOMAIN/panel"
    echo "用户名: $WEB_ADMIN_USER"
    echo "密码: $WEB_ADMIN_PASS"
    echo "TOTP 密钥: JBSWY3DPEHPK3PXP (请使用如 Google Authenticator 扫描)"
    echo "用户管理: v2ray-user [add|delete|edit|list|import|export]"
    echo "链接: $LINKS_FILE"
    echo "日志: $TRAFFIC_LOG, /var/log/v2ray/*"
    echo -e "${NC}"
}

main
