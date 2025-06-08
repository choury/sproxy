#!/bin/bash
set -x

HOSTNAME=localhost.choury.com

ker=$(uname -s)
run_extended_tests=false

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    --extended-tests)
        if [ $ker != 'Linux' ] || [ $EUID -ne 0 ] ;then
            echo "extended-test require linux and root"
            exit 1
        fi
        run_extended_tests=true
        echo "INFO: Extended tests (SNI, TProxy, VPN) will be executed."
        shift # past argument
        ;;
    *)
        # the first non-flag argument is the build path
        if [ -z "$buildpath" ]; then
            buildpath=$(realpath "$1/src")
        else
            echo "Warning: Unknown argument or multiple build paths specified: $1"
        fi
        shift # past argument or value
        ;;
    esac
done

function test_client(){
    curl -f -v http://localhost:$1/cgi/libsites.do -d 'method=put&site=*&strategy=proxy' 2>> curl.log
    [ $? -ne 0 ] && echo "prepare for failed" && exit 1

    curl -f -v -x http://$HOSTNAME:$1 http://qq.com > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 1 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1 http://taobao.com > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 2 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 3 failed" && exit 1

    curl -f -v -x http://$HOSTNAME:$1 http://qq.com -XPOST -d "foo=bar" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 4 failed" && exit 1

    curl -f -v -x http://$HOSTNAME:$1 http://taobao.com -I > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 5 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1 http://taobao.com -L > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 6 failed" && exit 1

    echo test for 100 continue
    curl -f -H "Expect: 100-continue" -v -x http://$HOSTNAME:$1 http://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 7 failed" && exit 1

    echo test for http1.0
    ./sproxy_test < http1.0_server.exp &
    sleep 1
    curl -f -v -x http://$HOSTNAME:$1 http://test.localhost.choury.com:4445 > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 8 failed" && exit 1

    echo test for shutdown1
    ./sproxy_test < shutdown1_server.exp &
    sleep 1
    cat shutdown1_client.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "client test 9 failed" && exit 1


    echo test for shutdown2
    ./sproxy_test < shutdown2_server.exp &
    sleep 1
    cat shutdown2_client.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "client test 10 failed" && exit 1

    echo test for send and ping
    ./sproxy_test < udp_server.exp &
    sleep 1
    cat send_ping.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "send ping test failed" && exit 1

    echo test pipeline
    curl -f -v  http://localhost:$1/cgi/libsites.do -XDELETE  -d 'site=*' 2>> curl.log
    [ $? -ne 0 ] && echo "delete site failed" && exit 1
    curl -f -v  http://localhost:$1/cgi/libsites.do -XPUT  -d 'site=360.cn&strategy=block' 2>> curl.log
    [ $? -ne 0 ] && echo "add block site failed" && exit 1
    curl -f -v  http://localhost:$1/cgi/libsites.do -XPUT  -d 'site=qq.com&strategy=proxy' 2>> curl.log
    [ $? -ne 0 ] && echo "add proxy site failed" && exit 1
    cat pipeline.exp | sed "s/PORT/$1/" | ./sproxy_test > pipeline-$1.log
    [ $? -ne 0 ] && echo "pipeline test failed" && exit 1
}

function test_https(){
    curl -f -v --http1.1 https://$HOSTNAME:$1/sites.list  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 1 failed" && exit 1
    curl -f -v --http2 https://$HOSTNAME:$1/sites.list  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 2 failed" && exit 1
    curl -f -v --http1.1 https://$HOSTNAME:$1/noexist  -k 2>> curl.log
    [ $? -ne 22 ] && echo "https test 3 failed" && exit 1
    curl -f -v --http2 https://$HOSTNAME:$1/noexist  -k  2>> curl.log
    ( r=$?; [ $r -ne 22 ] && [ $r -ne 56 ]) && echo "https test 4 failed" && exit 1
    curl -f -v --http1.1 https://$HOSTNAME:$1/noexist.do  -k 2>> curl.log
    [ $? -ne 22 ] && echo "https test 5 failed" && exit 1
    curl -f -v --http2 https://$HOSTNAME:$1/noexist.do  -k 2>> curl.log
    ( r=$?; [ $r -ne 22 ] && [ $r -ne 56 ]) && echo "https test 6 failed" && exit 1
    curl -f -v --http1.1 https://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 7 failed" && exit 1
    curl -f -v --http2 https://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 8 failed" && exit 1
    curl -f -v -L --http1.1 https://$HOSTNAME:$1/cgi  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 9 failed" && exit 1
    curl -f -v -L --http2 https://$HOSTNAME:$1/cgi  -k 2>> curl.log
    [ $? -ne 0 ] && echo "https test 10 failed" && exit 1
    curl -f -v --http1.1 https://$HOSTNAME:$1/ -H "Host: www.qq.com" -A "Mozilla/5.0" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "https test 11 failed" && exit 1
    curl -f -v --http2 https://$HOSTNAME:$1/ -H "Host: www.qq.com:443" -A "Mozilla/5.0" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "https test 12 failed" && exit 1
    curl -f -v https://$HOSTNAME:$1/cgi/libtest.do?size=1M -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 13 failed" && exit 1
    curl -f -v https://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed  -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 14 failed" && exit 1
    echo ""
}

function test_http(){
    curl -f -v http://$HOSTNAME:$1/sites.list  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http test 1 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/noexist  -k 2>> curl.log
    [ $? -ne 22 ] && echo "http test 2 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/noexist.do  -k 2>> curl.log
    [ $? -ne 22 ] && echo "http test 3 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http test 4 failed" && exit 1
    curl -f -v -L http://$HOSTNAME:$1/cgi  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http test 5 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/ -H "Host: www.qq.com" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 6 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1/ https://www.qq.com  2>> curl.log
    [ $? -ne 22 ] && echo "http test 7 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1/ https://www.qq.com -A "Mozilla/5.0" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 8 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/cgi/libtest.do?size=1M > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 9 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed  > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 10 failed" && exit 1
    echo ""
}

function test_http3(){
    curl -V | grep HTTP3
    if [[ $? != 0 ]];then
        return
    fi
    curl -f -v --http3-only https://$HOSTNAME:$1/sites.list  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http3 test 1 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/noexist  -k 2>> curl.log
    [ $? -ne 22 ] && echo "http3 test 2 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/noexist.do  -k 2>> curl.log
    [ $? -ne 22 ] && echo "http3 test 3 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http3 test 4 failed" && exit 1
    curl -f -v -L --http3-only https://$HOSTNAME:$1/cgi  -k 2>> curl.log
    [ $? -ne 0 ] && echo "http3 test 5 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/ -H "Host: www.taobao.com" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http3 test 6 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/cgi/libtest.do?size=1M -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 7 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 8 failed" && exit 1
    echo ""
}

function test_tproxy() {
    iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN
    iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-ip 127.0.0.1 --on-port $1
    iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port $1
    iptables -t mangle -A OUTPUT -m mark --mark 0x1 -j RETURN
    iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $1
    iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark $1
    ip rule add fwmark $1 lookup $1
    ip route add local 0.0.0.0/0 dev lo table $1

    ip6tables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN
    ip6tables -t mangle -A PREROUTING -p udp -j TPROXY --on-ip ::1 --on-port $1
    ip6tables -t mangle -A PREROUTING -p tcp -j TPROXY --on-ip ::1 --on-port $1
    ip6tables -t mangle -A OUTPUT -m mark --mark 0x1 -j RETURN
    ip6tables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $1
    ip6tables -t mangle -A OUTPUT -p udp -j MARK --set-mark $1
    ip -6 rule add fwmark $1 lookup $1
    ip -6 route add local ::/0 dev lo table $1

    function _tproxy_cleanup() {
        iptables -t mangle -F PREROUTING
        iptables -t mangle -F OUTPUT
        ip rule del fwmark $1
        ip route flush table $1

        ip6tables -t mangle -F PREROUTING
        ip6tables -t mangle -F OUTPUT
        ip -6 rule del fwmark $1
        ip -6 route flush table $1
    }

    trap "_tproxy_cleanup $1; cleanup " EXIT
    trap "_tproxy_cleanup $1; trap cleanup EXIT" RETURN

    curl -k -f -v --http1.1 http://qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tproxy test 1 failed" && exit 1
    curl -6 -k -f -v --http2 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tproxy test 2 failed" && exit 1
    curl -k -f -v -H "Expect: 100-continue" --http1.1 http://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tproxy test 3 failed" && exit 1
    curl -k -f -v --http2 https://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tproxy test 4 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -k -f -v --http3-only https://www.taobao.com  > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tproxy test 5 failed" && exit 1
    fi
}

function test_vpn(){
    ip rule add from all lookup 1 
    ip rule add fwmark 1 lookup main
    ip route add default dev tun0 table 1

    ip -6 rule add from all lookup 1 
    ip -6 rule add fwmark 1 lookup main
    ip -6 route add default dev tun0 table 1

    function _vpn_cleanup() {
        ip rule del fwmark 1 lookup main
        ip rule del from all lookup 1
        ip route flush table 1

        ip -6 rule del fwmark 1 lookup main
        ip -6 rule del from all lookup 1
        ip -6 route flush table 1
    }

    trap "_vpn_cleanup; cleanup" EXIT
    trap "_vpn_cleanup; trap cleanup EXIT" RETURN

    curl -k -f -v --http1.1 http://qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "vpn test 1 failed" && exit 1
    curl -6 -k -f -v --http2 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "vpn test 2 failed" && exit 1
    curl -k -f -v -H "Expect: 100-continue" --http1.1 http://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "vpn test 3 failed" && exit 1
    curl -k -f -v --http2 https://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "vpn test 4 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -k -f -v --http3-only https://www.taobao.com  > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "vpn test 5 failed" && exit 1
    fi

    ping -4 -c 3 example.com
    [ $? -ne 0 ] && echo "vpn test 6 failed" && exit 1
    ping -6 -c 3 example.com
    [ $? -ne 0 ] && echo "vpn test 7 failed" && exit 1
}

function test_sni(){
    ./sproxy -c server.conf --ssl 443 --quic 443 --sni  --admin unix:${sp}server.sock > server_sni.log 2>&1 &
    wait_tcp_port 443

    curl -f -v --http1.1 https://qq.com --resolve qq.com:443:127.0.0.1 -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 1 failed" && exit 1
    curl -f -v --http2 https://qq.com --resolve qq.com:443:127.0.0.1  -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 2 failed" && exit 1
    curl -f -v https://echo.opera.com -F 'name=@test1k' --resolve echo.opera.com:443:127.0.0.1 > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 3 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -f -v --http3-only https://www.taobao.com --resolve www.taobao.com:443:127.0.0.1 > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "sni test 4 failed" && exit 1
    fi

    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1
    kill -SIGUSR2 %1
    wait %1
    jobs

    ./sproxy -c server.conf --ssl 443 --quic 443 --sni --mitm enable  --admin unix:${sp}server.sock >> server_sni.log 2>&1 &
    wait_tcp_port 443

    curl -k -f -v --http1.1 https://qq.com --resolve qq.com:443:127.0.0.1 -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 6 failed" && exit 1
    curl -k -f -v --http2 https://qq.com --resolve qq.com:443:127.0.0.1  -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 7 failed" && exit 1
    curl -k -f -v -H "Expect: 100-continue" --http1.1 https://echo.opera.com -F 'name=@test1k' --resolve echo.opera.com:443:127.0.0.1 > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 8 failed" && exit 1
    curl -k -f -v --http2 https://echo.opera.com -F 'name=@test1k' --resolve echo.opera.com:443:127.0.0.1 > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 9 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -k -f -v --http3-only https://www.taobao.com --resolve www.taobao.com:443:127.0.0.1 > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "sni test 10 failed" && exit 1
    fi

    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1
    kill -SIGUSR2 %1
    wait %1
    jobs
}



function wait_tcp_port() {
    while ! nc -vz localhost $1; do
        ps aux | grep sproxy | grep -v grep
        sleep 1
    done
}

function wait_udp_port() {
    while ! lsof -Pi udp:$1; do
        ps aux | grep sproxy | grep -v grep
        sleep 1
    done
}

<< EOF
openssl genpkey -algorithm RSA -out ca.key -pass pass:hello
openssl rsa -in ca.key -passin pass:hello -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -batch -subj /commonName=$HOSTNAME/ -days 3560

openssl req -new -key localhost.key -out localhost.csr -subj '/CN=localhost' 

cat >> san.cnf << SEOF
[SAN]
subjectAltName=DNS:localhost,DNS:localhost.choury.com,IP:127.0.0.1,IP:::1
SEOF

openssl x509 -req -days 365 -in localhost.csr  -CA ca.crt -CAkey ca.key -set_serial 01 -out localhost.crt -extfile san.cnf  -extensions SAN

EOF


ln -f -s "$buildpath/sproxy" .
ln -f -s "$buildpath/scli" .
ln -s -f "$buildpath/../test/sproxy_test" .
mkdir -p cgi
ln -f -s "$buildpath"/cgi/libproxy.* cgi/
ln -f -s "$buildpath"/cgi/libsites.* cgi/
ln -f -s "$buildpath"/cgi/libtest.* cgi/
dd if=/dev/zero of=test1k bs=1024 count=1
export ASAN_OPTIONS=malloc_context_size=50
which curl
curl --version

echo "$HOSTNAME local" > sites.list

function cleanup {
    kill -SIGABRT $(jobs -p) || true
}
trap cleanup EXIT

if [ $ker == 'Linux' ];then
   sp='@'
fi

> curl.log

cat > server.conf << EOF
cafile ca.crt
cakey  ca.key
cert localhost.crt
key localhost.key 
root-dir .
policy-file sites.list
index libproxy.do
insecure
http 3333
ssl  3334
quic 3334
quic-cc bbr
debug all
EOF

if [ "$run_extended_tests" = true ]; then
    echo "tproxy 4333" >> server.conf
    echo "fwmark 1" >> server.conf
    echo "tun" >> server.conf
fi

./sproxy -c server.conf --admin unix:${sp}server.sock > server.log 2>&1 &
wait_tcp_port 3333
echo "test http server"
test_http 3333
kill -SIGUSR1 %1

wait_tcp_port 3334
echo "test https server"
test_https 3334
kill -SIGUSR1 %1

wait_udp_port 3334
echo "test quic server"
test_http3 3334
kill -SIGUSR1 %1

cat > client.conf << EOF
root-dir .
policy-file /dev/null
insecure
debug all
EOF

./sproxy -c client.conf --http 3335  https://$HOSTNAME:3334 --disable-http2 --admin unix:${sp}client_h1.sock > client_h1.log 2>&1 &
wait_tcp_port 3335

echo "test http1 -> http1"
test_client 3335
jobs
printf "dump sites" | ./scli -s ${sp}client_h1.sock
printf "dump usage" | ./scli -s ${sp}client_h1.sock
kill -SIGUSR1 %2
kill -SIGUSR2 %2
wait %2

./sproxy -c client.conf --http 3335  https://$HOSTNAME:3334 --admin unix:${sp}client_h23.sock > client_h23.log 2>&1 &
wait_tcp_port 3335

echo "test http1 -> http2"
test_client 3335
printf "dump sites" | ./scli -s ${sp}client_h23.sock
jobs
kill -SIGUSR1 %2

printf "switch quic://$HOSTNAME:3334" | ./scli -s ${sp}client_h23.sock
echo "test http1 -> http3"
test_client 3335
printf "dump sites" | ./scli -s ${sp}client_h23.sock
printf "dump usage" | ./scli -s ${sp}client_h23.sock
jobs
kill -SIGUSR1 %2
kill -SIGUSR2 %2
wait %2

printf "dump usage" | ./scli -s ${sp}server.sock
kill -SIGUSR1 %1

if [ "$run_extended_tests" = true ]; then
    echo "test tproxy"
    test_tproxy 4333
    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1

    echo "test vpn"
    test_vpn
    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1
fi

kill -SIGUSR2 %1
wait %1
jobs

if [ "$run_extended_tests" = true ]; then
    echo "test sni"
    test_sni
fi

$buildpath/prot/dns/dns_test
$buildpath/misc/trie_test
if [ $ker == 'Linux' ];then
    $buildpath/misc/hook_test $buildpath/misc/libhook.so
fi
