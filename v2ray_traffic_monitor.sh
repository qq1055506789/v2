#!/bin/bash
CONFIG_DIR="/usr/local/etc/xray"
USER_CONFIG="$CONFIG_DIR/users.json"
TRAFFIC_LOG="$CONFIG_DIR/traffic.log"
API_PORT=10085
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
