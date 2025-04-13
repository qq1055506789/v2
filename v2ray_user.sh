#!/bin/bash
CONFIG_DIR="/usr/local/etc/xray"
USER_CONFIG="$CONFIG_DIR/users.json"
LINKS_FILE="$CONFIG_DIR/links.txt"
DOMAIN=""
WEBSOCKET_PATH="/ray"
TRAFFIC_LIMIT="100GB"
add_user() {
    local email=$1
    if jq -e ".[] | select(.email == \"$email\")" $USER_CONFIG > /dev/null; then
        echo "用户 $email 已存在"
        exit 1
    fi
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local expire_date=$(date -d "+30 days" +%Y-%m-%d)
    local new_user="{\"id\": \"$uuid\", \"alterId\": 0, \"email\": \"$email\", \"traffic_limit\": \"$TRAFFIC_LIMIT\", \"expire_date\": \"$expire_date\", \"auto_renew\": true, \"disabled\": false}"
    jq ". += [$new_user]" $USER_CONFIG > $CONFIG_DIR/users_temp.json
    mv $CONFIG_DIR/users_temp.json $USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 $email 已添加"
}
delete_user() {
    local email=$1
    if ! jq -e ".[] | select(.email == \"$email\")" $USER_CONFIG > /dev/null; then
        echo "用户 $email 不存在"
        exit 1
    fi
    jq "del(.[] | select(.email == \"$email\"))" $USER_CONFIG > $CONFIG_DIR/users_temp.json
    mv $CONFIG_DIR/users_temp.json $USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 $email 已删除"
}
edit_user() {
    local email=$1
    local field=$2
    local value=$3
    if ! jq -e ".[] | select(.email == \"$email\")" $USER_CONFIG > /dev/null; then
        echo "用户 $email 不存在"
        exit 1
    fi
    jq "(.[] | select(.email == \"$email\") | .$field) = \"$value\"" $USER_CONFIG > $CONFIG_DIR/users_temp.json
    mv $CONFIG_DIR/users_temp.json $USER_CONFIG
    update_links
    systemctl restart xray
    echo "用户 $email 已更新"
}
list_users() {
    jq -r '.[] | "\(.email) \(.traffic_limit) \(.expire_date) \(.auto_renew)"' $USER_CONFIG
}
import_users() {
    local csv_file=$1
    while IFS=, read -r email traffic_limit expire_date auto_renew; do
        add_user $email
        edit_user $email traffic_limit $traffic_limit
        edit_user $email expire_date $expire_date
        edit_user $email auto_renew $auto_renew
    done < $csv_file
}
export_users() {
    jq -r '.[] | "\(.email),\(.traffic_limit),\(.expire_date),\(.auto_renew)"' $USER_CONFIG > users.csv
    echo "用户已导出到 users.csv"
}
update_links() {
    rm -f $LINKS_FILE
    users=$(jq -c '.[]' $USER_CONFIG)
    while read -r user; do
        local uuid=$(echo "$user" | jq -r '.id')
        local email=$(echo "$user" | jq -r '.email')
        VMESS_JSON="{\"v\": \"2\", \"ps\": \"VMess_WS_${DOMAIN}_${email}\", \"add\": \"$DOMAIN\", \"port\": \"443\", \"id\": \"$uuid\", \"aid\": \"0\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$DOMAIN\", \"path\": \"$WEBSOCKET_PATH\", \"tls\": \"tls\"}"
        echo "${email} VMess: vmess://$(echo -n $VMESS_JSON | base64 -w 0)" >> $LINKS_FILE
        VLESS_LINK="vless://$uuid@$DOMAIN:443?security=reality&encryption=none&pbk=$(/usr/local/bin/xray-core x25519 | grep Public | awk '{print $3}')&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&remark=VLESS_Reality_${DOMAIN}_${email}"
        echo "${email} VLESS Reality: $VLESS_LINK" >> $LINKS_FILE
    done <<< "$users"
}
case "$1" in
    add) add_user "$2";;
    delete) delete_user "$2";;
    edit) edit_user "$2" "$3" "$4";;
    list) list_users;;
    import) import_users "$2";;
    export) export_users;;
    *) echo "用法: v2ray-user [add|delete|edit|list|import|export]"; exit 1;;
esac
