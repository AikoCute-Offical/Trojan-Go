#!/bin/bash

#MIT License
#Copyright (c) 2020 h31105

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

#====================================================
# System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
# Author: Miroku/h31105
# Dscription: TLS-Shunt-Proxy&Trojan-Go&V2Ray Script
# Official document:
# https://www.v2ray.com/
# https://github.com/p4gefau1t/trojan-go
# https://github.com/liberal-boy/tls-shunt-proxy
# https://www.docker.com/
# https://github.com/containrrr/watchtower
# https://github.com/portainer/portainer
# https://github.com/wulabing/V2Ray_ws-tls_bash_onekey
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#Fonts Color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
Font="\033[0m"

#Notification Information
OK="${Green}[OK]${Font}"
WARN="${Yellow}[Cảnh báo]${Font}"
Error="${Red}[Lỗi]${Font}"

#版本、初始化变量
shell_version="1.183"
tsp_cfg_version="0.61.1"
#install_mode="docker"
upgrade_mode="none"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
tsp_conf_dir="/etc/tls-shunt-proxy"
trojan_conf_dir="/etc/trojan-go"
v2ray_conf_dir="/etc/v2ray"
tsp_conf="${tsp_conf_dir}/config.yaml"
tsp_cert_dir="/etc/ssl/tls-shunt-proxy/certificates/acme-v02.api.letsencrypt.org-directory"
trojan_conf="${trojan_conf_dir}/config.json"
v2ray_conf="${v2ray_conf_dir}/config.json"
web_dir="/home/wwwroot"
random_num=$((RANDOM % 3 + 7))

#shellcheck disable=SC1091
source '/etc/os-release'

#Trích xuất tên tiếng Anh của hệ thống phân phối từ PHIÊN BẢN
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -eq 7 ]]; then
        echo -e "${OK} ${GreenBG} Hệ thống hiện tại là Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum -y -q"
    elif [[ "${ID}" == "centos" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} Hệ thống hiện tại là Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="dnf -y"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} Hệ thống hiện tại là Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt -y -qq"
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} Hệ thống hiện tại là Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt -y -qq"
    else
        echo -e "${Error} ${RedBG} Hệ thống hiện tại là ${ID} ${VERSION_ID} Không có trong danh sách các hệ thống được hỗ trợ, quá trình cài đặt đã bị hủy bỏ ${Font}"
        exit 1
    fi
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} Người dùng hiện tại là người dùng root, hãy tiếp tục thực thi ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} Người dùng hiện tại không phải là người dùng root, vui lòng chuyển sang người dùng root và thực thi lại tập lệnh ${Font}"
        exit 1
    fi
}

judge() {
    #shellcheck disable=SC2181
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 Hoàn thành ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 Thất bại ${Font}"
        exit 1
    fi
}

urlEncode() {
    jq -R -r @uri <<<"$1"
}

chrony_install() {
    ${INS} install chrony
    judge "Cài đặt dịch vụ đồng bộ hóa thời gian Chrony"
    timedatectl set-ntp true
    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi
    judge "Chrony khởi động"
    timedatectl set-timezone Asia/Ho_Chi_Minh
    echo -e "${OK} ${GreenBG} Chờ đồng bộ hóa thời gian ${Font}"
    sleep 10
    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -rp "Vui lòng xác nhận xem thời gian có chính xác hay không, phạm vi sai số là ± 3 phút (Y/N) [Y]: " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} Tiếp tục ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} Dừng lại ${Font}"
        exit 2
        ;;
    esac
}

dependency_install() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -eq 7 ]]; then
        yum install epel-release -y -q
    elif [[ "${ID}" == "centos" && ${VERSION_ID} -ge 8 ]]; then
        dnf install epel-release -y -q
        dnf config-manager --set-enabled PowerTools
        dnf upgrade libseccomp
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        $INS update
    fi
    $INS install dbus
    ${INS} install git lsof unzip
    judge "Cài đặt phần phụ thuộc git lsof unzip"
    ${INS} install haveged
    systemctl start haveged && systemctl enable haveged
    command -v bc >/dev/null 2>&1 || ${INS} install bc
    judge "Cài đặt phần phụ thuộc bc"
    command -v jq >/dev/null 2>&1 || ${INS} install jq
    judge "Cài đặt phần phụ thuộc jq"
    command -v sponge >/dev/null 2>&1 || ${INS} install moreutils
    judge "Cài đặt phần phụ thuộc moreutils"
    command -v qrencode >/dev/null 2>&1 || ${INS} install qrencode
    judge "Cài đặt phần phụ thuộc qrencode"
}

basic_optimization() {
    # Số tệp mở tối đa
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
    # Đóng Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

config_exist_check() {
    if [[ -f "$1" ]]; then
        echo -e "${OK} ${GreenBG} Các tệp cấu hình cũ được phát hiện và cấu hình tệp cũ được tự động sao lưu ${Font}"
        cp "$1" "$1.$(date +%Y%m%d%H)"
        echo -e "${OK} ${GreenBG} Cấu hình cũ được sao lưu ${Font}"
    fi
}

domain_port_check() {
    read -rp "Vui lòng nhập cổng TLS (mặc định 443):" tspport
    [[ -z ${tspport} ]] && tspport="443"
    read -rp "Vui lòng nhập thông tin tên miền của bạn (ví dụ: test.aikocute.com):" domain
    domain=$(echo "${domain}" | tr '[:upper:]' '[:lower:]')
    domain_ip=$(ping -q -c 1 -t 1 "${domain}" | grep PING | sed -e "s/).*//" | sed -e "s/.*(//")
    echo -e "${OK} ${GreenBG} Nhận thông tin IP công khai, vui lòng kiên nhẫn chờ đợi ${Font}"
    local_ip=$(curl -s https://api64.ipify.org)
    echo -e "IP phân giải DNS của tên miền:${domain_ip}"
    echo -e "IP gốc: ${local_ip}"
    sleep 2
    if [[ "${local_ip}" = "${domain_ip}" ]]; then
        echo -e "${OK} ${GreenBG} IP phân giải DNS của tên miền khớp với IP cục bộ ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} Hãy đảm bảo rằng bản ghi A / AAAA chính xác được thêm vào tên miền, nếu không kết nối sẽ không hoạt động ${Font}"
        echo -e "${Error} ${RedBG} Nếu IP phân giải DNS của tên miền không khớp với IP cục bộ, ứng dụng cho chứng chỉ SSL sẽ không thành công. Bạn có muốn tiếp tục cài đặt không?（Y/N）[N]${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} Tiếp tục cài đặt ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} Cài đặt đã kết thúc ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 Cổng không được sử dụng ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} Phát hiện $1 Cổng bị chiếm dụng, sau đây là $1 Thông tin về việc sử dụng cổng ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} Sau 5 giây, nó sẽ cố gắng kết thúc quá trình bị chiếm đóng một cách tự động ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill Xong ${Font}"
        sleep 1
    fi
}

service_status_check() {
    if systemctl is-active "$1" &>/dev/null; then
        echo -e "${OK} ${GreenBG} $1 Đã được kích hoạt ${Font}"
        if systemctl is-enabled "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 Nó là một mục tự khởi động ${Font}"
        else
            echo -e "${WARN} ${Yellow} $1 Không phải là một mục tự khởi động ${Font}"
            systemctl enable "$1"
            judge "Thiết lập $1 tự bắt đầu"
        fi
    else
        echo -e "${Error} ${RedBG} Phát hiện $1 Dịch vụ chưa bắt đầu, đang cố gắng bắt đầu ... ${Font}"
        systemctl restart "$1" && systemctl enable "$1"
        judge "Cố gắng bắt đầu $1 "
        sleep 5
        if systemctl is-active "$1" &>/dev/null; then
            echo -e "${OK} ${GreenBG} $1 Đã được kích hoạt ${Font}"
        else
            echo -e "${WARN} ${Yellow} Vui lòng thử cài đặt lại sửa chữa $1 thử lại ${Font}"
            exit 4
        fi
    fi
}

prereqcheck() {
    service_status_check docker
    if [[ -f ${tsp_conf} ]]; then
        service_status_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} Cấu hình TLS-Shunt-Proxy không bình thường, vui lòng thử cài đặt lại ${Font}"
        exit 4
    fi
}

trojan_reset() {
    config_exist_check ${trojan_conf}
    [[ -f ${trojan_conf} ]] && rm -rf ${trojan_conf}
    if [[ -f ${tsp_conf} ]]; then
        TSP_Domain=$(grep '#TSP_Domain' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') && echo -e "Miền TLS được phát hiện là: ${TSP_Domain}"
    else
        echo -e "${Error} ${RedBG} Cấu hình của TLS-Shunt-Proxy không bình thường, không thể phát hiện thông tin tên miền TLS, vui lòng cài đặt lại và thử lại ${Font}"
        exit 4
    fi
    read -rp "Vui lòng nhập mật khẩu (Trojan-Go), mặc định là ngẫu nhiên :" tjpasswd
    [[ -z ${tjpasswd} ]] && tjpasswd=$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})
    echo -e "${OK} ${GreenBG} Mật khẩu Trojan-Go: ${tjpasswd} ${Font}"
    read -rp "Có bật hỗ trợ chế độ WebSocket hay không (Y/N) [N]:" trojan_ws_mode
    [[ -z ${trojan_ws_mode} ]] && trojan_ws_mode=false
    case $trojan_ws_mode in
    [yY][eE][sS] | [yY])
        tjwspath="/trojan/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} Chế độ Trojan-Go WebSocket đang bật, WSPATH: ${tjwspath} ${Font}"
        trojan_ws_mode=true
        ;;
    *)
        trojan_ws_mode=false
        ;;
    esac
    trojan_tcp_mode=true
    tjport=$((RANDOM % 6666 + 10000)) && echo -e "${OK} ${GreenBG} Cổng lắng nghe Trojan-Go là: $tjport ${Font}"
    mkdir -p $trojan_conf_dir
    cat >$trojan_conf <<-EOF
{
    "run_type": "server",
    "disable_http_check": true,
    "local_addr": "127.0.0.1",
    "local_port": ${tjport},
    "remote_addr": "1.1.1.1",
    "remote_port": 80,
    "fallback_addr": "1.1.1.1",
    "fallback_port": 443,
    "password": ["${tjpasswd}"],
    "transport_plugin": {
        "enabled": true,
        "type": "plaintext"
    },
    "websocket": {
        "enabled": ${trojan_ws_mode},
        "path": "${tjwspath}",
        "host": "${TSP_Domain}"
    }
}
EOF
    judge "tạo cấu hình trojan-Go"
    port_exist_check $tjport
    trojan_sync
    judge "Đồng bộ hóa cài đặt cấu hình Trojan-Go"
    systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
    judge "Cài đặt ứng dụng TLS-Shunt-Proxy"
}

modify_trojan() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} Sửa đổi cấu hình Trojan-Go sẽ đặt lại thông tin cấu hình proxy hiện có, bạn có muốn tiếp tục không (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        trojan_reset
        docker restart Trojan-Go
        ;;
    *) ;;
    esac
}

trojan_sync() {
    [[ -z $tjport ]] && tjport=40001
    [[ -z $tjwspath ]] && tjwspath=/trojan/none
    [[ -z $trojan_tcp_mode ]] && trojan_tcp_mode=none
    [[ -z $trojan_ws_mode ]] && trojan_ws_mode=none
    if [[ ${trojan_tcp_mode} = true ]]; then
        sed -i "/trojan: #Trojan_TCP/c \\    trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    else
        sed -i "/trojan: #Trojan_TCP/c \\    #trojan: #Trojan_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_TCP/c \\      #handler: proxyPass #Trojan_TCP" ${tsp_conf}
        sed -i "/#Trojan_TCP_Port/c \\      #args: 127.0.0.1:${tjport} #Trojan_TCP_Port:${trojan_tcp_mode}" ${tsp_conf}
    fi
    if [[ ${trojan_ws_mode} = true ]]; then
        sed -i "/#Trojan_WS_Path/c \\      - path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    else
        sed -i "/#Trojan_WS_Path/c \\      #- path: ${tjwspath} #Trojan_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #Trojan_WS/c \\        #handler: proxyPass #Trojan_WS" ${tsp_conf}
        sed -i "/#Trojan_WS_Port/c \\        #args: 127.0.0.1:${tjport} #Trojan_WS_Port:${trojan_ws_mode}" ${tsp_conf}
    fi
}

v2ray_mode_type() {
    read -rp "Vui lòng chọn loại giao thức chế độ V2Ray TCP: VMess(M)/VLESS(L), bỏ qua theo mặc định, (M/L) [Skip]:" v2ray_tcp_mode
    [[ -z ${v2ray_tcp_mode} ]] && v2ray_tcp_mode="none"
    case $v2ray_tcp_mode in
    [mM])
        echo -e "${GreenBG} Đã chọn giao thức chế độ TCP VMess ${Font}"
        v2ray_tcp_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} Đã chọn giao thức chế độ TCP VLESS ${Font}"
        v2ray_tcp_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} Bỏ qua triển khai chế độ TCP ${Font}"
        v2ray_tcp_mode="none"
        ;;
    *)
        echo -e "${RedBG} Vui lòng nhập đúng ký tự (M/L) ${Font}"
        ;;
    esac
    read -rp "Vui lòng chọn loại giao thức chế độ V2Ray WebSocket: VMess (M) / VLESS (L), bỏ qua theo mặc định, (M / L) [SKIP]:" v2ray_ws_mode
    [[ -z ${v2ray_ws_mode} ]] && v2ray_ws_mode="none"
    case $v2ray_ws_mode in
    [mM])
        echo -e "${GreenBG} Chế độ WS đã chọn VMess ${Font}"
        v2ray_ws_mode="vmess"
        ;;
    [lL])
        echo -e "${GreenBG} Chế độ WS đã chọn VLESS ${Font}"
        v2ray_ws_mode="vless"
        ;;
    none)
        echo -e "${GreenBG} Bỏ qua triển khai chế độ WS ${Font}"
        v2ray_ws_mode="none"
        ;;
    *)
        echo -e "${RedBG} Vui lòng nhập đúng chữ cái (M/L) ${Font}"
        ;;
    esac
}

v2ray_reset() {
    config_exist_check ${v2ray_conf}
    [[ -f ${v2ray_conf} ]] && rm -rf ${v2ray_conf}
    mkdir -p $v2ray_conf_dir
    cat >$v2ray_conf <<-EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds":[
    ], 
    "outbounds": [
      {
        "protocol": "freedom", 
        "settings": {}, 
        "tag": "direct"
      }, 
      {
        "protocol": "blackhole", 
        "settings": {}, 
        "tag": "blocked"
      }
    ], 
    "dns": {
      "servers": [
        "https+local://1.1.1.1/dns-query",
	    "1.1.1.1",
	    "1.0.0.1",
	    "8.8.8.8",
	    "8.8.4.4",
	    "localhost"
      ]
    },
    "routing": {
      "rules": [
        {
            "ip": [
            "geoip:private"
            ],
            "outboundTag": "blocked",
            "type": "field"
        },
        {
          "type": "field",
          "outboundTag": "blocked",
          "protocol": ["bittorrent"]
        },
        {
          "type": "field",
          "inboundTag": [
          ],
          "outboundTag": "direct"
        }
      ]
    }
}
EOF
    if [[ "${v2ray_ws_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2wspath="/v2ray/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"
        echo -e "${OK} ${GreenBG} Bật chế độ V2Ray WS, WSPATH: ${v2wspath} ${Font}"
        v2wsport=$((RANDOM % 6666 + 30000))
        echo -e "${OK} ${GreenBG} Cổng nghe V2Ray WS là ${v2wsport} ${Font}"
        if [[ "${v2ray_ws_mode}" = "vmess" ]]; then
            #read -rp "请输入 WS 模式 AlterID（默认:10 仅允许填非0数字）:" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vmess-ws-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "Thế hệ cấu hình V2Ray VMess WS"
        fi
        if [[ "${v2ray_ws_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2wsport}',"listen":"127.0.0.1","tag":"vless-ws-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"'"${v2wspath}"'"}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-ws-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "Tạo cấu hình V2Ray VLESS WS"
        fi
        port_exist_check ${v2wsport}
    fi
    if [[ "${v2ray_tcp_mode}" = v*ess ]]; then
        UUID=$(cat /proc/sys/kernel/random/uuid)
        echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
        v2port=$((RANDOM % 6666 + 20000))
        echo -e "${OK} ${GreenBG} Cổng lắng nghe V2Ray TCP là ${v2port} ${Font}"
        if [[ "${v2ray_tcp_mode}" = "vmess" ]]; then
            #read -rp "请输入 TCP 模式 AlterID（默认:10 仅允许填非0数字）:" alterID
            [[ -z ${alterID} ]] && alterID="10"
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vmess-tcp-in","protocol":"vmess","settings":{"clients":[{"id":"'"${UUID}"'","alterId":'${alterID}'}]},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vmess-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VMess tạo cấu hình TCP"
        fi
        if [[ "${v2ray_tcp_mode}" = "vless" ]]; then
            jq '.inbounds += [{"sniffing":{"enabled":true,"destOverride":["http","tls"]},"port":'${v2port}',"listen":"127.0.0.1","tag":"vless-tcp-in","protocol":"vless","settings":{"clients":[{"id":"'"${UUID}"'","level":0}],"decryption":"none"},"streamSettings":{"network":"tcp","tcpSettings":{"acceptProxyProtocol":true}}}]' ${v2ray_conf} | sponge ${v2ray_conf} &&
                jq '.routing.rules[2].inboundTag += ["vless-tcp-in"]' ${v2ray_conf} | sponge ${v2ray_conf}
            judge "V2Ray VLESS Tạo cấu hình TCP"
        fi
        port_exist_check ${v2port}
    fi
    if [[ -f ${tsp_conf} ]]; then
        v2ray_sync
        judge "Đồng bộ hóa cấu hình V2Ray"
        systemctl restart tls-shunt-proxy && service_status_check tls-shunt-proxy
        judge "Cài đặt ứng dụng TLS-Shunt-Proxy"
    else
        echo -e "${Error} ${RedBG} Cấu hình TLS-Shunt-Proxy không bình thường, vui lòng cài đặt lại và thử lại ${Font}"
        exit 4
    fi
}

modify_v2ray() {
    deployed_status_check
    echo -e "${WARN} ${Yellow} Sửa đổi cấu hình V2Ray sẽ đặt lại thông tin cấu hình proxy hiện có, bạn có muốn tiếp tục không (Y/N) [N]? ${Font}"
    read -r modify_confirm
    [[ -z ${modify_confirm} ]] && modify_confirm="No"
    case $modify_confirm in
    [yY][eE][sS] | [yY])
        prereqcheck
        v2ray_mode_type
        [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]] && v2ray_reset
        docker restart V2Ray
        ;;
    *) ;;
    esac
}

v2ray_sync() {
    [[ -z $v2port ]] && v2port=40003
    [[ -z $v2wsport ]] && v2wsport=40002
    [[ -z $v2wspath ]] && v2wspath=/v2ray/none
    [[ -z $v2ray_tcp_mode ]] && v2ray_tcp_mode=none
    [[ -z $v2ray_ws_mode ]] && v2ray_ws_mode=none
    if [[ ${v2ray_tcp_mode} = v*ess ]]; then
        sed -i "/default: #V2Ray_TCP/c \\    default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    else
        sed -i "/default: #V2Ray_TCP/c \\    #default: #V2Ray_TCP" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_TCP/c \\      #handler: proxyPass #V2Ray_TCP" ${tsp_conf}
        sed -i "/#V2Ray_TCP_Port/c \\      #args: 127.0.0.1:${v2port};proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}" ${tsp_conf}
    fi
    if [[ ${v2ray_ws_mode} = v*ess ]]; then
        sed -i "/#V2Ray_WS_Path/c \\      - path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    else
        sed -i "/#V2Ray_WS_Path/c \\      #- path: ${v2wspath} #V2Ray_WS_Path" ${tsp_conf}
        sed -i "/handler: proxyPass #V2Ray_WS/c \\        #handler: proxyPass #V2Ray_WS" ${tsp_conf}
        sed -i "/#V2Ray_WS_Port/c \\        #args: 127.0.0.1:${v2wsport};proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}" ${tsp_conf}
    fi
}

web_camouflage() {
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    rm -rf $web_dir
    mkdir -p $web_dir
    cd $web_dir || exit
    websites[0]="https://github.com/h31105/LodeRunner_TotalRecall.git"
    websites[1]="https://github.com/h31105/adarkroom.git"
    websites[2]="https://github.com/h31105/webosu"
    selectedwebsite=${websites[$RANDOM % ${#websites[@]}]}
    git clone ${selectedwebsite} web_camouflage
    judge "WebSite giả mạo"
}

install_docker() {
    echo -e "${GreenBG} Bắt đầu cài đặt phiên bản Docker mới nhất ... ${Font}"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    judge "Cài đặt Docker "
    systemctl daemon-reload
    systemctl enable docker && systemctl restart docker
    judge "Docker khởi động"
}

install_tsp() {
    bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
    judge "Cài đặt TLS-Shunt-Proxy"
    chown -R tls-shunt-proxy:tls-shunt-proxy /etc/ssl/tls-shunt-proxy
    command -v setcap >/dev/null 2>&1 && setcap "cap_net_bind_service=+ep" /usr/local/bin/tls-shunt-proxy
    config_exist_check ${tsp_conf}
    [[ -f ${tsp_conf} ]] && rm -rf ${tsp_conf}
    mkdir -p $tsp_conf_dir
    cat >$tsp_conf <<-EOF
#TSP_CFG_Ver:${tsp_cfg_version}
listen: 0.0.0.0:${tspport} #TSP_Port
redirecthttps: 0.0.0.0:80
inboundbuffersize: 4
outboundbuffersize: 32
vhosts:
  - name: ${domain} #TSP_Domain
    tlsoffloading: true
    managedcert: true
    keytype: p256
    alpn: h2,http/1.1
    protocols: tls12,tls13
    http:
      paths:
      #- path: /trojan/none #Trojan_WS_Path
        #handler: proxyPass #Trojan_WS
        #args: 127.0.0.1:40000 #Trojan_WS_Port:${trojan_ws_mode}
      #- path: /v2ray/none #V2Ray_WS_Path
        #handler: proxyPass #V2Ray_WS
        #args: 127.0.0.1:40002;proxyProtocol #V2Ray_WS_Port:${v2ray_ws_mode}
      handler: fileServer
      args: ${web_dir}/web_camouflage #Website_camouflage
    #trojan: #Trojan_TCP
      #handler: proxyPass #Trojan_TCP
      #args: 127.0.0.1:40001 #Trojan_TCP_Port:${trojan_tcp_mode}
    #default: #V2Ray_TCP
      #handler: proxyPass #V2Ray_TCP
      #args: 127.0.0.1:40003;proxyProtocol #V2Ray_TCP_Port:${v2ray_tcp_mode}
EOF
    judge "Cấu hình TLS-Shunt-Proxy"
    systemctl daemon-reload && systemctl reset-failed
    systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
    judge "Khởi động TLS-Shunt-Proxy"
}

modify_tsp() {
    domain_port_check
    sed -i "/#TSP_Port/c \\listen: 0.0.0.0:${tspport} #TSP_Port" ${tsp_conf}
    sed -i "/#TSP_Domain/c \\  - name: ${domain} #TSP_Domain" ${tsp_conf}
    tsp_sync
}

tsp_sync() {
    echo -e "${OK} ${GreenBG} Phát hiện và đồng bộ hóa cấu hình proxy hiện có... ${Font}"
    if [[ $trojan_stat = "installed" && -f ${trojan_conf} ]]; then
        tjport="$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')" && trojan_tcp_mode=true &&
            tjwspath="$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}')" && trojan_ws_mode="$(jq -r '.websocket.enabled' ${trojan_conf})"
        judge "Phát hiện cấu hình Trojan-Go"
        [[ -z $tjport ]] && trojan_tcp_mode=false
        [[ $trojan_ws_mode = null ]] && trojan_ws_mode=false
        [[ -z $tjwspath ]] && tjwspath=/trojan/none
        echo -e "Đã phát hiện: Trojan-Go Proxy: TCP：${Green}${trojan_tcp_mode}${Font} / WebSocket：${Green}${trojan_ws_mode}${Font} / 端口：${Green}${tjport}${Font} / WebSocket Path：${Green}${tjwspath}${Font}"
    fi

    if [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]]; then
        sed -i '/\#\"/d' ${v2ray_conf}
        v2port="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf})" &&
            v2wsport="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf})" &&
            v2ray_tcp_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="tcp") | .protocol][0]' ${v2ray_conf})" &&
            v2ray_ws_mode="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .protocol][0]' ${v2ray_conf})" &&
            v2wspath="$(jq -r '[.inbounds[] | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf})"
        judge "Phát hiện cấu hình V2Ray"
        [[ $v2port = null ]] && v2port=40003
        [[ $v2wsport = null ]] && v2wsport=40002
        [[ $v2ray_tcp_mode = null ]] && v2ray_tcp_mode=none
        [[ $v2ray_ws_mode = null ]] && v2ray_ws_mode=none
        [[ $v2wspath = null ]] && v2wspath=/v2ray/none
        echo -e "Đã phát hiện: V2Ray Proxy: TCP${Green}${v2ray_tcp_mode}${Font} Cổng :${Green}${v2port}${Font} / WebSocket：${Green}${v2ray_ws_mode}${Font} 端口：${Green}${v2wsport}${Font} / WebSocket Path：${Green}${v2wspath}${Font}"
    fi

    if [[ -f ${tsp_conf} ]]; then
        trojan_sync
        v2ray_sync
        tsp_config_stat="synchronized"
        systemctl restart tls-shunt-proxy
        judge "Đồng bộ hóa cấu hình tách"
        menu_req_check tls-shunt-proxy
    else
        echo -e "${Error} ${RedBG} Cấu hình TLS-Shunt-Proxy không bình thường, vui lòng cài đặt lại và thử lại ${Font}"
        exit 4
    fi
}

install_trojan() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    trojan_reset
    docker pull teddysun/trojan-go
    docker run -d --network host --name Trojan-Go --restart=always -v /etc/trojan-go:/etc/trojan-go teddysun/trojan-go
    judge "Cài đặt vùng chứa Trojan-Go"
}

install_v2ray() {
    systemctl is-active "docker" &>/dev/null || install_docker
    prereqcheck
    v2ray_mode_type
    [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]] && check_system && chrony_install
    if [[ $v2ray_tcp_mode != "none" || $v2ray_ws_mode != "none" ]]; then
        v2ray_reset
        docker pull teddysun/v2ray
        docker run -d --network host --name V2Ray --restart=always -v /etc/v2ray:/etc/v2ray teddysun/v2ray
        judge "V2Ray lắp đặt thùng chứa"
    fi
}

install_watchtower() {
    docker pull containrrr/watchtower
    docker run -d --name WatchTower --restart=always -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --cleanup
    judge "WatchTower lắp đặt thùng chứa"
}

install_portainer() {
    docker volume create portainer_data
    docker pull portainer/portainer-ce
    docker run -d -p 9080:9000 --name Portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce
    judge "Portainer lắp đặt thùng chứa"
    echo -e "${OK} ${GreenBG} Portainer Địa chỉ quản lý là http://$TSP_Domain:9080 Hãy tự mở cổng tường lửa! ${Font}"
}

install_tls_shunt_proxy() {
    check_system
    systemctl is-active "firewalld" &>/dev/null && systemctl stop firewalld && echo -e "${OK} ${GreenBG} Firewalld đã ngừng hoạt động ${Font}"
    systemctl is-active "ufw" &>/dev/null && systemctl stop ufw && echo -e "${OK} ${GreenBG} UFW không hoạt động ${Font}"
    dependency_install
    basic_optimization
    domain_port_check
    port_exist_check "${tspport}"
    port_exist_check 80
    config_exist_check "${tsp_conf}"
    web_camouflage
    install_tsp
}

uninstall_all() {
    echo -e "${RedBG} !!!Hành động này sẽ xóa TLS-Shunt-Proxy、Docker Dữ liệu nền tảng và vùng chứa được cài đặt bởi tập lệnh này!!! ${Font}"
    read -rp "Vui lòng nhập CÓ sau khi xác nhận (phân biệt chữ hoa chữ thường):" uninstall
    [[ -z ${uninstall} ]] && uninstall="No"
    case $uninstall in
    YES)
        echo -e "${GreenBG} bắt đầu gỡ cài đặt ${Font}"
        sleep 2
        ;;
    *)
        echo -e "${RedBG} để tôi nghĩ lại ${Font}"
        exit 1
        ;;
    esac
    check_system
    uninstall_proxy_server
    uninstall_watchtower
    uninstall_portainer
    systemctl stop docker && systemctl disable docker
    if [[ "${ID}" == "centos" ]]; then
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
    else
        ${INS} remove docker-ce docker-ce-cli containerd.io docker docker-engine docker.io containerd runc
    fi
    #rm -rf /var/lib/docker #Removes all docker data
    rm -rf /etc/systemd/system/docker.service
    uninstall_tsp
    echo -e "${OK} ${GreenBG} Tất cả các thành phần đã được gỡ cài đặt, chào mừng bạn sử dụng lại tập lệnh này! ${Font}"
    exit 0
}

uninstall_tsp() {
    systemctl stop tls-shunt-proxy && systemctl disable tls-shunt-proxy
    rm -rf /etc/systemd/system/tls-shunt-proxy.service
    rm -rf /usr/local/bin/tls-shunt-proxy
    rm -rf $tsp_conf_dir
    userdel -rf tls-shunt-proxy
    tsp_stat="none"
    rm -rf ${web_dir}/web_camouflage
    echo -e "${OK} ${GreenBG} Quá trình gỡ cài đặt TLS-Shunt-Proxy đã hoàn tất！${Font}"
    sleep 3
}

uninstall_proxy_server() {
    uninstall_trojan
    uninstall_v2ray
    echo -e "${OK} ${GreenBG} Đã thực hiện xong việc giảm tải (Trojan-Go / V2Ray) TCP / WS proxy！ ${Font}"
    sleep 3
}

uninstall_trojan() {
    rm -rf $trojan_conf_dir
    trojan_ws_mode="none" && trojan_tcp_mode="none"
    [ -f ${tsp_conf} ] && trojan_sync
    systemctl start docker
    [[ $trojan_stat = "installed" ]] && docker stop Trojan-Go && docker rm -f Trojan-Go &&
        echo -e "${OK} ${GreenBG} Gỡ cài đặt xong proxy Trojan-Go TCP / WS！ ${Font}"
}

uninstall_v2ray() {
    rm -rf $v2ray_conf_dir
    v2ray_ws_mode="none" && v2ray_tcp_mode="none"
    [ -f ${tsp_conf} ] && v2ray_sync
    systemctl start docker
    [[ $v2ray_stat = "installed" ]] && docker stop V2Ray && docker rm -f V2Ray &&
        echo -e "${OK} ${GreenBG} Hoàn tất gỡ cài đặt proxy V2Ray TCP / WS！ ${Font}"
}
uninstall_watchtower() {
    docker stop WatchTower && docker rm -f WatchTower && watchtower_stat="none" &&
        echo -e "${OK} ${GreenBG} Gỡ cài đặt WatchTower xong！ ${Font}"
    sleep 3
}

uninstall_portainer() {
    docker stop Portainer && docker rm -fv Portainer && portainer_stat="none" &&
        echo -e "${OK} ${GreenBG} Gỡ cài đặt xong Portainer！ ${Font}"
    sleep 3
}

upgrade_tsp() {
    current_version="$(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')"
    echo -e "${GreenBG} TLS-Shunt-Proxy phiên bản hiện tại: ${current_version}，Bắt đầu phát hiện phiên bản mới nhất ... ${Font}"
    latest_version="$(wget --no-check-certificate -qO- https://api.github.com/repos/liberal-boy/tls-shunt-proxy/tags | grep 'name' | cut -d\" -f4 | head -1)"
    [[ -z ${latest_version} ]] && echo -e "${Error} Không phát hiện được phiên bản mới nhất ! ${Font}" && menu
    if [[ ${latest_version} != "${current_version}" ]]; then
        echo -e "${OK} ${GreenBG} Phiên bản hiện tại: ${current_version} Phiên bản mới nhất của: ${latest_version}，Có cập nhật không (Y/N) [N]? ${Font}"
        read -r update_confirm
        [[ -z ${update_confirm} ]] && update_confirm="No"
        case $update_confirm in
        [yY][eE][sS] | [yY])
            config_exist_check "${tsp_conf}"
            bash <(curl -L -s https://raw.githubusercontent.com/liberal-boy/tls-shunt-proxy/master/dist/install.sh)
            judge "Cập nhật TLS-Shunt-Proxy"
            systemctl daemon-reload && systemctl reset-failed
            systemctl enable tls-shunt-proxy && systemctl restart tls-shunt-proxy
            judge "Khởi động lại TLS-Shunt-Proxy"
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} TLS-Shunt-Proxy hiện tại là phiên bản mới nhất ${current_version} ${Font}"
    fi
}

update_sh() {
    command -v curl >/dev/null 2>&1 || ${INS} install curl
    judge "Cài đặt phần phụ thuộc curl"
    ol_version=$(curl -L -s https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} Cập nhật nội dung：${Font}"
        echo -e "${Yellow}$(curl --silent https://api.github.com/repos/h31105/trojan_v2_docker_onekey/releases/latest | grep body | head -n 1 | awk -F '"' '{print $4}')${Font}"
        echo -e "${OK} ${GreenBG} Có phiên bản mới, có cập nhật không    (Y/N) [N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate https://raw.githubusercontent.com/h31105/trojan_v2_docker_onekey/${github_branch}/deploy.sh
            echo -e "${OK} ${GreenBG} Cập nhật hoàn tất, vui lòng chạy lại tập lệnh：\n#./deploy.sh ${Font}"
            exit 0
            ;;
        *) ;;
        esac
    else
        echo -e "${OK} ${GreenBG} Phiên bản hiện tại là phiên bản mới nhất ${Font}"
    fi
}

list() {
    case $1 in
    uninstall)
        deployed_status_check
        uninstall_all
        ;;
    sync)
        deployed_status_check
        tsp_sync
        ;;
    debug)
        debug="enable"
        #set -xv
        menu
        ;;
    *)
        menu
        ;;
    esac
}

deployed_status_check() {
    tsp_stat="none" && trojan_stat="none" && v2ray_stat="none" && watchtower_stat="none" && portainer_stat="none"
    trojan_tcp_mode="none" && v2ray_tcp_mode="none" && trojan_ws_mode="none" && v2ray_ws_mode="none"
    tsp_config_stat="synchronized" && chrony_stat="none"

    echo -e "${OK} ${GreenBG} Phát hiện thông tin cấu hình shunt ... ${Font}"
    [[ -f ${tsp_conf} || -f '/usr/local/bin/tls-shunt-proxy' ]] &&
        tsp_template_version=$(grep '#TSP_CFG_Ver' ${tsp_conf} | sed -r 's/.*TSP_CFG_Ver:(.*) */\1/') && tsp_stat="installed" &&
        TSP_Port=$(grep '#TSP_Port' ${tsp_conf} | sed -r 's/.*0:(.*) #.*/\1/') && TSP_Domain=$(grep '#TSP_Domain' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        trojan_tcp_port=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_tcp_mode=$(grep '#Trojan_TCP_Port' ${tsp_conf} | sed -r 's/.*Trojan_TCP_Port:(.*) */\1/') &&
        trojan_ws_port=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*) #.*/\1/') &&
        trojan_ws_mode=$(grep '#Trojan_WS_Port' ${tsp_conf} | sed -r 's/.*Trojan_WS_Port:(.*) */\1/') &&
        trojan_ws_path=$(grep '#Trojan_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        v2ray_tcp_port=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_tcp_mode=$(grep '#V2Ray_TCP_Port' ${tsp_conf} | sed -r 's/.*V2Ray_TCP_Port:(.*) */\1/') &&
        v2ray_ws_port=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*:(.*);.*/\1/') &&
        v2ray_ws_mode=$(grep '#V2Ray_WS_Port' ${tsp_conf} | sed -r 's/.*V2Ray_WS_Port:(.*) */\1/') &&
        v2ray_ws_path=$(grep '#V2Ray_WS_Path' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/') &&
        menu_req_check tls-shunt-proxy

    echo -e "${OK} ${GreenBG} Phát hiện trạng thái triển khai thành phần ... ${Font}"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Trojan-Go &>/dev/null && trojan_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep V2Ray &>/dev/null && v2ray_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep WatchTower &>/dev/null && watchtower_stat="installed"
    systemctl is-active "docker" &>/dev/null && docker ps -a | grep Portainer &>/dev/null && portainer_stat="installed"

    echo -e "${OK} ${GreenBG} Đang phát hiện thông tin cấu hình tác nhân ... ${Font}"

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        tjport=$(grep '"local_port"' ${trojan_conf} | sed -r 's/.*: (.*),.*/\1/')
        tjpassword=$(grep '"password"' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_ws_mode = true ]] && tjwspath=$(grep '"path":' ${trojan_conf} | awk -F '"' '{print $4}') &&
            tjwshost=$(grep '"host":' ${trojan_conf} | awk -F '"' '{print $4}')
        [[ $trojan_tcp_mode = true && $tjport != "$trojan_tcp_port" ]] && echo -e "${Error} ${RedBG} Phát hiện bất thường cấu hình tải xuống cổng TCP Trojan-Go ${Font}" && tsp_config_stat="mismatched"
        [[ $trojan_ws_mode = true && $tjport != "$trojan_ws_port" ]] && echo -e "${Error} ${RedBG} Phát hiện bất thường cấu hình tải xuống cổng WS của Trojan-Go ${Font}" && tsp_config_stat="mismatched"
        [[ $trojan_ws_mode = true && $tjwspath != "$trojan_ws_path" ]] && echo -e "${Error} ${RedBG} Đã phát hiện ngoại lệ cấu hình giảm tải đường dẫn WS của Trojan-Go ${Font}" && tsp_config_stat="mismatched"
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} Đã phát hiện cấu hình shunt không nhất quán, sẽ cố gắng tự động sửa chữa đồng bộ hóa ... ${Font}" && tsp_sync
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VMTID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="tcp") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = "vless" ]] &&
            v2port=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .port][0]' ${v2ray_conf}) &&
            VLTID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="tcp") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vmess" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VMWSID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf}) &&
            VMWSAID=$(jq -r '[.inbounds[] | select(.protocol=="vmess") | select(.streamSettings.network=="ws") | .settings.clients[].alterId][0]' ${v2ray_conf})
        [[ $v2ray_ws_mode = "vless" ]] &&
            v2wsport=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .port][0]' ${v2ray_conf}) &&
            v2wspath=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .streamSettings.wsSettings.path][0]' ${v2ray_conf}) &&
            VLWSID=$(jq -r '[.inbounds[] | select(.protocol=="vless") | select(.streamSettings.network=="ws") | .settings.clients[].id][0]' ${v2ray_conf})
        [[ $v2ray_tcp_mode = v*ess && $v2port != "$v2ray_tcp_port" ]] && echo -e "${Error} ${RedBG} Đã phát hiện thấy cấu hình giảm tải cổng V2Ray TCP bất thường ${Font}" && tsp_config_stat="mismatched"
        [[ $v2ray_ws_mode = v*ess && $v2wsport != "$v2ray_ws_port" ]] && echo -e "${Error} ${RedBG} Đã phát hiện cấu hình bất thường của việc giảm tải cổng V2Ray WS ${Font}" && tsp_config_stat="mismatched"
        [[ $v2ray_ws_mode = v*ess && $v2wspath != "$v2ray_ws_path" ]] && echo -e "${Error} ${RedBG} Đã phát hiện cấu hình giảm tải đường dẫn V2Ray WS bất thường ${Font}" && tsp_config_stat="mismatched"
        [[ $tsp_config_stat = "mismatched" ]] && echo -e "${Error} ${RedBG} Đã phát hiện cấu hình shunt không nhất quán, sẽ cố gắng tự động sửa chữa đồng bộ hóa ... ${Font}" && tsp_sync
        if [[ $v2ray_tcp_mode = "vmess" || $v2ray_ws_mode = "vmess" ]]; then
            if [[ "${ID}" == "centos" ]]; then
                systemctl is-active "chronyd" &>/dev/null || chrony_stat=inactive
            else
                systemctl is-active "chrony" &>/dev/null || chrony_stat=inactive
            fi
            if [[ $chrony_stat = inactive ]]; then
                echo -e "${Error} ${RedBG} Nó được phát hiện rằng dịch vụ đồng bộ thời gian Chrony không được khởi động, nếu thời gian hệ thống không chính xác, nó sẽ ảnh hưởng nghiêm trọng đến tính khả dụng của giao thức V2Ray VMess. ${Font}\n${WARN} ${Yellow} Giờ hệ thống hiện tại: ${date}, vui lòng xác nhận xem thời gian có chính xác không, phạm vi lỗi nằm trong khoảng ± 3 phút (Y) hoặc cố gắng sửa chữa dịch vụ đồng bộ hóa thời gian (R) [R]: ${Font}"
                read -r chrony_confirm
                [[ -z ${chrony_confirm} ]] && chrony_confirm="R"
                case $chrony_confirm in
                [rR])
                    echo -e "${GreenBG} Cài đặt dịch vụ đồng bộ hóa thời gian Chrony ${Font}"
                    check_system
                    chrony_install
                    ;;
                *) ;;
                esac
            fi
        fi
    fi

    [[ -f ${trojan_conf} || -f ${v2ray_conf} || $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && menu_req_check docker
    [[ $trojan_stat = "installed" && ! -f $trojan_conf ]] && echo -e "\n${Error} ${RedBG} Đã phát hiện cấu hình bất thường của proxy Trojan-Go, các tùy chọn sau sẽ bị chặn, vui lòng thử cài đặt lại và sửa chữa và thử lại ... ${Font}" &&
        echo -e "${WARN} ${Yellow}[Chặn] Sửa đổi cấu hình Trojan-Go${Font}"
    [[ $v2ray_stat = "installed" && ! -f $v2ray_conf ]] && echo -e "\n${Error} ${RedBG} Phát hiện cấu hình bất thường của tác nhân V2Ray, các tùy chọn và chức năng sau sẽ bị chặn, vui lòng thử cài đặt lại và sửa chữa và thử lại ... ${Font}" &&
        echo -e "${WARN} ${Yellow}[Shield] Sửa đổi cấu hình V2Ray${Font}"

    if [[ $tsp_stat = "installed" && $tsp_template_version != "${tsp_cfg_version}" ]]; then
        echo -e "${WARN} ${Yellow}Đã phát hiện một bản cập nhật quan trọng cho TLS-Shunt-Proxy, để đảm bảo tập lệnh hoạt động bình thường, vui lòng xác nhận rằng thao tác cập nhật được thực hiện ngay lập tức（Y/N）[Y] ${Font}"
        read -r upgrade_confirm
        [[ -z ${upgrade_confirm} ]] && upgrade_confirm="Yes"
        case $upgrade_confirm in
        [yY][eE][sS] | [yY])
            uninstall_tsp
            install_tls_shunt_proxy
            tsp_sync
            deployed_status_check
            ;;
        *) ;;
        esac
    fi

    [[ $debug = "enable" ]] && echo -e "\n Proxy Trojan-Go：TCP：${Green}${trojan_tcp_mode}${Font} / WebSocket：${Green}${trojan_ws_mode}${Font}\n     V2Ray Proxy：TCP：${Green}${v2ray_tcp_mode}${Font} / WebSocket：${Green}${v2ray_ws_mode}${Font}" &&
        echo -e "\n Vùng chứa proxy: Trojan-Go：${Green}${trojan_stat}${Font} / V2Ray：${Green}${v2ray_stat}${Font}" &&
        echo -e " Các thùng chứa khác: WatchTower：${Green}${watchtower_stat}${Font} / Portainer：${Green}${portainer_stat}${Font}\n"
}

info_config() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    echo -e "\n————————————————————Thông tin cấu hình Shunt————————————————————"
    if [ -f ${tsp_conf} ]; then
        echo -e "TLS-Shunt-Proxy $(/usr/local/bin/tls-shunt-proxy --version 2>&1 | awk 'NR==1{gsub(/"/,"");print $3}')" &&
            echo -e "Cổng TLS của máy chủ: ${TSP_Port}" && echo -e "Tên miền TLS của máy chủ: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Cổng Trojan-Go TCP Shunt: $trojan_tcp_port" && echo -e "Cổng nghe Trojan-Go: $tjport"
        [[ $trojan_ws_mode = true ]] && echo -e "Cổng giảm tải Trojan-Go WebSocket: $trojan_ws_port" &&
            echo -e "Đường dẫn tải xuống Trojan-Go WebSocket: $trojan_ws_path"
        [[ $v2ray_tcp_mode = v*ess ]] && echo -e "V2Ray TCP cổng giảm tải: $v2ray_tcp_port" && echo -e "Cổng nghe V2Ray TCP: $v2port"
        [[ $v2ray_ws_mode = v*ess ]] && echo -e "Cổng giảm tải V2Ray WebSocket: $v2ray_ws_port" && echo -e "Cổng nghe V2Ray WS: $v2wsport" &&
            echo -e "Đường dẫn giảm tải V2Ray WebSocket: $v2ray_ws_path"
    fi

    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "—————————————————— Cấu hình Trojan-Go ——————————————————" &&
            echo -e "$(docker exec Trojan-Go sh -c 'trojan-go --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "Cổng máy chủ: ${TSP_Port}" && echo -e "IP máy chủ: ${TSP_Domain}"
        [[ $trojan_tcp_mode = true ]] && echo -e "Mật khẩu Trojan-Go: ${tjpassword}"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "Trojan-Go WebSocket Path: ${tjwspath}" && echo -e "Trojan-Go WebSocket Host: ${tjwshost}"
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n———————————————————— Cấu hình V2Ray ————————————————————" &&
            echo -e "$(docker exec V2Ray sh -c 'v2ray --version' 2>&1 | awk 'NR==1{gsub(/"/,"");print}')" &&
            echo -e "cổng máy chủ: ${TSP_Port}" && echo -e "IP máy chủ: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\nVMess TCP UUID: ${VMTID}" &&
            echo -e "VMess AlterID: ${VMAID}" && echo -e "Phương pháp mã hóa VMess: Auto" && echo -e "VMess Host: ${TSP_Domain}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\nVLESS TCP UUID: ${VLTID}" &&
            echo -e "Phương pháp mã hóa VLESS: none" && echo -e "VLESS Host: ${TSP_Domain}"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\nVMess WS UUID: ${VMWSID}" && echo -e "VMess AlterID: $VMWSAID" &&
            echo -e "Phương pháp mã hóa VMess: Auto" && echo -e "VMess WebSocket Host: ${TSP_Domain}" && echo -e "VMess WebSocket Path: ${v2wspath}"
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\nVLESS WS UUID: ${VLWSID}" &&
            echo -e "Phương pháp mã hóa VLESS: none" && echo -e "VLESS WebSocket Host: ${TSP_Domain}" && echo -e "VLESS WebSocket Path: ${v2wspath}"
    fi

    echo -e "————————————————————————————————————————————————————\n"
    read -t 60 -n 1 -s -rp "Nhấn phím bất kỳ để tiếp tục (60 giây)..."
    clear
}

info_links() {
    deployed_status_check
    cert_stat_check tls-shunt-proxy
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        echo -e "————————————————Liên kết chia sẻ Trojan-Go————————————————" &&
            [[ $trojan_tcp_mode = true ]] && echo -e "\n Trojan-Go TCP TLS 分享链接：" &&
            echo -e " Ứng dụng khách Trojan：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e " Ứng dụng khách Qv2ray (Cần cài đặt plugin jan-Go chia sẻ liên kết TroTrojan-Go)：\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host=${TSP_Domain}#${HOSTNAME}-TCP" &&
            echo -e " Mã QR Shadowrocket：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP"
        [[ $trojan_ws_mode = true ]] && echo -e "\n Liên kết chia sẻ Trojan-Go WebSocket TLS：" &&
            echo -e " Ứng dụng khách Trojan-Qt5：\n trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=1&ws=1&wspath=${tjwspath}&wshost=${TSP_Domain}#${HOSTNAME}-WS" &&
            echo -e " Ứng dụng khách Qv2ray (đã cài đặt plugin Trojan-Go)：\n trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host=${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-WS" &&
            echo -e " Mã QR Shadowrocket：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-WS"
        read -t 60 -n 1 -s -rp "Nhấn phím bất kỳ để tiếp tục (60 giây)..."
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        echo -e "\n—————————————————— Liên kết chia sẻ V2Ray ——————————————————" &&
            [[ $v2ray_tcp_mode = "vmess" ]] && echo -e "\n VMess TCP TLS 分享链接：" &&
            echo -e " Định dạng V2RayN：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess định dạng mới：\n vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-TCP")" &&
            echo -e " Mã QR Shadowrocket：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMTID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-TCP"
        [[ $v2ray_ws_mode = "vmess" ]] && echo -e "\n VMess WebSocket TLS 分享链接：" &&
            echo -e " Định dạng V2RayN：\n vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e " VMess định dạng mới：\n vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-WS")" &&
            echo -e " Mã QR Shadowrocket：" &&
            qrencode -t ANSIUTF8 -s 1 -m 2 "vmess://$(echo "auto:${VMWSID}@${TSP_Domain}:${TSP_Port}" | base64 -w 0)?tls=1&mux=1&peer=${TSP_Domain}&allowInsecure=0&tfo=0&remarks=${HOSTNAME}-WS&obfs=websocket&obfsParam=${TSP_Domain}&path=${v2wspath}"
        [[ $v2ray_tcp_mode = "vless" ]] && echo -e "\n VLESS TCP TLS 分享链接：" &&
            echo -e " VLESS định dạng mới：\n vless://${VLTID}@${TSP_Domain}:${TSP_Port}?security=tls&sni=${TSP_Domain}#$(urlEncode "${HOSTNAME}-TCP")"
        [[ $v2ray_ws_mode = "vless" ]] && echo -e "\n VLESS WebSocket TLS 分享链接：" &&
            echo -e " VLESS định dạng mới：\n vless://${VLWSID}@${TSP_Domain}:${TSP_Port}?type=ws&security=tls&host=${TSP_Domain}&path=$(urlEncode "${v2wspath}")&sni=${TSP_Domain}#$(urlEncode "${HOSTNAME}-WS")"
        read -t 60 -n 1 -s -rp "Nhấn phím bất kỳ để tiếp tục (60 giây)..."
    fi

    if [[ -f ${v2ray_conf} || -f ${trojan_conf} ]]; then
        echo -e "\n——————————————————— Thông tin liên kết đăng ký ———————————————————"
        rm -rf "$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe*
        cat >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/robots.txt <<-EOF
User-agent: *
Disallow: /
EOF
        subscribe_file="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        subscribe_links | base64 -w 0 >"$(grep '#Website' ${tsp_conf} | sed -r 's/.*: (.*) #.*/\1/')"/subscribe"${subscribe_file}"
        echo -e "Liên kết đăng ký: \n https://${TSP_Domain}/subscribe${subscribe_file} \n${Yellow}Xin lưu ý: Liên kết đăng ký được tạo bởi tập lệnh chứa tất cả thông tin cấu hình giao thức proxy hiện được triển khai trên máy chủ. Vì lý do bảo mật thông tin, địa chỉ liên kết sẽ được làm mới ngẫu nhiên mỗi khi bạn xem! \ n Ngoài ra, vì các máy khách khác nhau có mức độ tương thích và hỗ trợ khác nhau cho các giao thức proxy, vui lòng điều chỉnh chúng theo tình hình thực tế!${Font}"
        read -t 60 -n 1 -s -rp "Nhấn phím bất kỳ để tiếp tục (60 giây)..."
    fi

    clear
}

subscribe_links() {
    if [[ -f ${trojan_conf} && $trojan_stat = "installed" ]]; then
        [[ $trojan_tcp_mode = true ]] &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?sni=${TSP_Domain}&peer=${TSP_Domain}&allowinsecure=0&mux=0#${HOSTNAME}-TCP" &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=original&host=${TSP_Domain}#${HOSTNAME}-Trojan-Go-TCP"
        [[ $trojan_ws_mode = true ]] &&
            echo -e "trojan-go://${tjpassword}@${TSP_Domain}:${TSP_Port}/?sni=${TSP_Domain}&type=ws&host=${TSP_Domain}&path=${tjwspath}#${HOSTNAME}-Trojan-Go-WS" &&
            echo -e "trojan://${tjpassword}@${TSP_Domain}:${TSP_Port}?peer=${TSP_Domain}&mux=1&plugin=obfs-local;obfs=websocket;obfs-host=${TSP_Domain};obfs-uri=${tjwspath}#${HOSTNAME}-Trojan-Go-WS"
    fi

    if [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]]; then
        [[ $v2ray_tcp_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMTID}\",\"net\":\"tcp\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-TCP\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://tcp+tls:${VMTID}-0@${TSP_Domain}:${TSP_Port}/?tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-TCP")"
        [[ $v2ray_ws_mode = "vmess" ]] &&
            echo -e "vmess://$(echo "{\"add\":\"${TSP_Domain}\",\"aid\":\"0\",\"host\":\"${TSP_Domain}\",\"peer\":\"${TSP_Domain}\",\"id\":\"${VMWSID}\",\"net\":\"ws\",\"path\":\"${v2wspath}\",\"port\":\"${TSP_Port}\",\"ps\":\"${HOSTNAME}-WS\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}" | base64 -w 0)" &&
            echo -e "vmess://ws+tls:${VMWSID}-0@${TSP_Domain}:${TSP_Port}/?path=$(urlEncode "${v2wspath}")&host=${TSP_Domain}&tlsServerName=${TSP_Domain}#$(urlEncode "${HOSTNAME}-新版格式-WS")"
        [[ $v2ray_tcp_mode = "vless" ]] &&
            echo -e "vless://${VLTID}@${TSP_Domain}:${TSP_Port}?security=tls&sni=${TSP_Domain}#$(urlEncode "${HOSTNAME}-TCP")"
        [[ $v2ray_ws_mode = "vless" ]] &&
            echo -e "vless://${VLWSID}@${TSP_Domain}:${TSP_Port}?type=ws&security=tls&host=${TSP_Domain}&path=$(urlEncode "${v2wspath}")&sni=${TSP_Domain}#$(urlEncode "${HOSTNAME}-WS")"
    fi
}

cert_stat_check() {
    echo -e "${OK} ${GreenBG} Kiểm tra thông tin trạng thái chứng chỉ... ${Font}"
    if systemctl is-active "$1" &>/dev/null; then
        [[ $1 = "tls-shunt-proxy" ]] && [[ ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.crt || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.json || ! -f ${tsp_cert_dir}/${TSP_Domain}/${TSP_Domain}.key ]] &&
            echo -e "${Yellow}Không phát hiện thấy chứng chỉ SSL hợp lệ nào, hãy thực hiện lệnh sau：\n#systemctl restart tls-shunt-proxy\n#journalctl -u tls-shunt-proxy.service\nKiểm tra nhật ký và chạy lại tập lệnh sau khi hoàn tất ứng dụng chứng chỉ.${Font}" && exit 4
    fi
}

menu_req_check() {
    if systemctl is-active "$1" &>/dev/null; then
        [[ $debug = "enable" ]] && echo -e "${OK} ${GreenBG} $1 Đã được kích hoạt ${Font}"
    else
        echo -e "\n${Error} ${RedBG}Phát hiện $1 Dịch vụ không khởi động thành công, các tùy chọn sau sẽ bị chặn tùy thuộc vào các yếu tố phụ thuộc, vui lòng sửa và thử lại ... ${Font}"
        [[ $1 = "tls-shunt-proxy" ]] && echo -e "${Yellow}[Shield] Cài đặt (Trojan-Go / V2Ray) TCP / WS proxy \ n sửa đổi cấu hình [Shield] (Trojan-Go / V2Ray) \ n [Shield] Xem thông tin cấu hình${Font}"
        [[ $1 = "docker" ]] && echo -e "${Yellow}[Chặn] Cài đặt / Gỡ cài đặt WatchTower (Vùng chứa tự động cập nhật) \ n [Chặn] Cài đặt / Gỡ cài đặt Trình chuyển đổi (Vùng chứa quản trị viên web)${Font}"
        read -t 60 -n 1 -s -rp "Nhấn phím bất kỳ để tiếp tục (60 giây)..."
    fi
}

menu() {
    deployed_status_check
    echo -e "\n${Green}     Phiên bản tập lệnh triển khai TSP & Trojan-Go / V2Ray: ${shell_version} ${Font}"
    echo -e "${Yellow}       Nhóm Telegram：https://t.me/aikocutehotme${Font}\n"
    echo -e "——————————————————————Quản lý triển khai——————————————————————"
    if [[ $tsp_stat = "installed" ]]; then
        echo -e "${Green}1.${Font}  ${Yellow}Gỡ cài đặt${Font} TLS-Shunt-Proxy (trang web và quản lý chứng chỉ tự động)"
    else
        echo -e "${Green}1.${Font}  Cài đặt TLS-Shunt-Proxy (trang web và quản lý chứng chỉ tự động)"
    fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $trojan_stat = "none" ]]; then
            echo -e "${Green}2.${Font}  Cài đặt Trojan-Go TCP / WS Proxy"
        else
            echo -e "${Green}2.${Font}  ${Yellow}Gỡ cài đặt${Font} Trojan-Go TCP/WS 代理"
        fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        if [[ $v2ray_stat = "none" ]]; then
            echo -e "${Green}3.${Font}  Cài đặt V2Ray TCP / WS Proxy"
        else
            echo -e "${Green}3.${Font}  ${Yellow}Gỡ cài đặt${Font} V2Ray TCP/WS 代理"
        fi
    systemctl is-active "docker" &>/dev/null &&
        if [[ $watchtower_stat = "none" ]]; then
            echo -e "${Green}4.${Font}  Cài đặt WatchTower (vùng chứa tự động cập nhật)"
        else
            echo -e "${Green}4.${Font}  ${Yellow}Gỡ cài đặt${Font} WatchTower (vùng chứa tự động cập nhật)"
        fi
    systemctl is-active "docker" &>/dev/null &&
        if [[ $portainer_stat = "none" ]]; then
            echo -e "${Green}5.${Font}  Cài đặt Portainer (vùng chứa quản lý web)"
        else
            echo -e "${Green}5.${Font}  ${Yellow}Gỡ cài đặt${Font} Portainer (vùng chứa quản lý web)"
        fi
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "——————————————————————Sửa đổi cấu hình——————————————————————" &&
        echo -e "${Green}6.${Font}  Sửa đổi cổng TLS / tên miền" &&
        [[ $trojan_stat = "installed" && -f ${trojan_conf} ]] && echo -e "${Green}7.${Font}  Sửa đổi cấu hình proxy Trojan-Go"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        [[ $v2ray_stat = "installed" && -f ${v2ray_conf} ]] && echo -e "${Green}8.${Font}  Sửa đổi cấu hình proxy V2Ray"
    systemctl is-active "tls-shunt-proxy" &>/dev/null &&
        echo -e "——————————————————————Xem thông tin——————————————————————" &&
        echo -e "${Green}9.${Font}  Xem thông tin cấu hình" &&
        [[ $trojan_stat = "installed" || $v2ray_stat = "installed" ]] && echo -e "${Green}10.${Font} Xem liên kết Chia sẻ / Đăng ký"
    echo -e "——————————————————————Quản lý khác——————————————————————"
    [ -f ${tsp_conf} ] && echo -e "${Green}11.${Font} Nâng cấp nền tảng cơ sở TLS-Shunt-Proxy / Docker" &&
        echo -e "${Green}12.${Font} ${Yellow}Gỡ cài đặt${Font} Tất cả các thành phần được cài đặt"
    echo -e "${Green}13.${Font} Cài đặt tập lệnh tốc độ sắc nét BBR 4 trong 1"
    echo -e "${Green}14.${Font} Chạy tập lệnh kiểm tra tốc độ SuperSpeed"
    echo -e "${Green}0.${Font}  Tập lệnh thoát "
    echo -e "————————————————————————————————————————————————————\n"
    read -rp "Vui lòng nhập số：" menu_num
    case "$menu_num" in
    1)
        if [[ $tsp_stat = "installed" ]]; then
            uninstall_tsp
        else
            install_tls_shunt_proxy
            tsp_sync
        fi
        ;;
    2)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $trojan_stat = "none" ]]; then
                install_trojan
            else
                uninstall_trojan
            fi
        ;;
    3)
        systemctl is-active "tls-shunt-proxy" &>/dev/null &&
            if [[ $v2ray_stat = "none" ]]; then
                install_v2ray
            else
                uninstall_v2ray
            fi
        ;;
    4)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $watchtower_stat = "none" ]]; then
                install_watchtower
            else
                uninstall_watchtower
            fi
        ;;
    5)
        systemctl is-active "docker" &>/dev/null &&
            if [[ $portainer_stat = "none" ]]; then
                install_portainer
            else
                uninstall_portainer
            fi
        ;;
    6)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && modify_tsp
        ;;
    7)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${trojan_conf} && $trojan_stat = "installed" ]] && modify_trojan
        ;;
    8)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && [[ -f ${v2ray_conf} && $v2ray_stat = "installed" ]] && modify_v2ray
        ;;
    9)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_config
        ;;
    10)
        systemctl is-active "tls-shunt-proxy" &>/dev/null && info_links
        ;;
    11)
        [ -f ${tsp_conf} ] && read -rp "Vui lòng xác nhận xem có nâng cấp thành phần shunt TLS-Shunt-Proxy hay không，(Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} Bắt đầu nâng cấp các thành phần giảm tải TLS-Shunt-Proxy ${Font}"
            upgrade_mode="Tsp"
            sleep 1
            upgrade_tsp
            ;;
        *)
            echo -e "${GreenBG} Bỏ qua nâng cấp thành phần giảm tải TLS-Shunt-Proxy ${Font}"
            ;;
        esac
        [ -f ${tsp_conf} ] && read -rp "Vui lòng xác nhận xem có nâng cấp các thành phần nền tảng Docker hay không，(Y/N) [N]:" upgrade_mode
        [[ -z ${upgrade_mode} ]] && upgrade_mode="none"
        case $upgrade_mode in
        [yY])
            echo -e "${GreenBG} Bắt đầu nâng cấp các thành phần nền tảng Docker ${Font}"
            upgrade_mode="Docker"
            sleep 1
            install_docker
            ;;
        *)
            echo -e "${GreenBG} Bỏ qua nâng cấp các thành phần nền tảng Docker ${Font}"
            ;;
        esac
        ;;
    12)
        [ -f ${tsp_conf} ] && uninstall_all
        ;;
    13)
        kernel_change="YES"
        systemctl is-active "docker" &>/dev/null && echo -e "${RedBG} !!! Vì Docker liên kết chặt chẽ với nhân hệ thống nên việc thay thế nhân hệ thống có thể khiến Docker không hoạt động bình thường !!! ${Font}\n${WARN} ${Yellow} Nếu Docker không khởi động đúng cách sau khi thay thế nhân, hãy cố gắng khắc phục sự cố này thông qua tập lệnh <tùy chọn 10: nâng cấp Docker> hoặc triển khai lại sau <tùy chọn 11: cài đặt đầy đủ> ${Font}" &&
            read -rp "Vui lòng nhập CÓ sau khi xác nhận (phân biệt chữ hoa chữ thường):" kernel_change
        [[ -z ${kernel_change} ]] && kernel_change="no"
        case $kernel_change in
        YES)
            [ -f "tcp.sh" ] && rm -rf ./tcp.sh
            wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
            ;;
        *)
            echo -e "${RedBG} để tôi nghĩ lại ${Font}"
            exit 0
            ;;
        esac
        ;;
    14)
        bash <(curl -Lso- https://git.io/superspeed)
        ;;
    0)
        exit 0
        ;;
    *)
        echo -e "${RedBG} Vui lòng nhập số chính xác ${Font}"
        sleep 3
        ;;
    esac
    menu
}

clear
check_system
is_root
update_sh
list "$1"
