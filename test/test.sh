#!/bin/bash
set -x

HOSTNAME=localhost.choury.com

ker=$(uname -s)
run_extended_tests=false

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    --extended-tests|--ex)
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
    curl -f -v -x http://$HOSTNAME:$1 http://cloudflare.com/cdn-cgi/trace 2>> curl.log
    [ $? -ne 0 ] && echo "client test 2 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 3 failed" && exit 1

    curl -f -v -x http://$HOSTNAME:$1 http://qq.com -XPOST -d "foo=bar" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "client test 4 failed" && exit 1

    curl -f -v -x http://$HOSTNAME:$1 http://example.com/ -I 2>> curl.log
    [ $? -ne 0 ] && echo "client test 5 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1 'http://mockhttp.org/redirect-to?url=http://mockhttp.org/anything&status_code=301' -L 2>> curl.log
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
    curl -m 5 -f -v https://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed  -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 14 failed" && exit 1
    echo ""
}

function test_ech(){
    if [ ! -s ech.dns ]; then
        echo "ech not supported by this build, skip"
        return
    fi
    { echo "connect 127.0.0.1 $1";
      echo "tlsconnect localhost $(cat ech.dns)"; } | ./sproxy_test
    [ $? -ne 0 ] && echo "ech test failed" && exit 1
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
    curl -f -v -x http://$HOSTNAME:$1/ https://www.qq.com  > /dev/null 2>> curl.log
    [ $? -ne 22 ] && echo "http test 7 failed" && exit 1
    curl -f -v -x http://$HOSTNAME:$1/ https://www.qq.com -A "Mozilla/5.0" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 8 failed" && exit 1
    curl -f -v http://$HOSTNAME:$1/cgi/libtest.do?size=1M > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 9 failed" && exit 1
    curl -m 5 -f -v http://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed  > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 10 failed" && exit 1

    echo "test rproxy/local"
    # This would cause stack overflow before the fix (infinite recursion between distribute and distribute_rproxy)
    curl -f -v http://$HOSTNAME:$1/rproxy/local/$HOSTNAME:$1/sites.list > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy/local test 1 failed" && exit 1
    # rproxy/local with redirect follow
    curl -f -v -L http://$HOSTNAME:$1/rproxy/local/$HOSTNAME:$1/cgi > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy/local test 2 failed" && exit 1
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
    curl -f -v --http3-only https://$HOSTNAME:$1/ -H "Host: cloudflare-quic.com" -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http3 test 6 failed" && exit 1
    curl -f -v --http3-only https://$HOSTNAME:$1/cgi/libtest.do?size=1M -k > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "http test 7 failed" && exit 1
    if [ $ker == 'Linux' ]; then
        curl -m 5 -f -v --http3-only https://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed -k > /dev/null 2>> curl.log
    else
        curl -m 10 -f -v --http3-only https://$HOSTNAME:$1/cgi/libtest.do?size=100M --compressed -k > /dev/null 2>> curl.log
    fi
    [ $? -ne 0 ] && echo "http test 8 failed" && exit 1
    echo ""
}

function test_auth(){
    echo "test auth functionality"

    # Test 1: correct credentials via liblogin.do
    KEY=$(printf 'testuser:testpass' | base64 | tr -d '\n')
    curl -f -s -o /dev/null http://$HOSTNAME:3333/cgi/liblogin.do --data-urlencode "key=$KEY" 2>> curl.log
    [ $? -ne 0 ] && echo "auth test 1 failed: correct credentials rejected" && exit 1

    # Test 2: wrong password should return 403
    KEY=$(printf 'testuser:wrongpass' | base64 | tr -d '\n')
    local code=$(curl -s -o /dev/null -w "%{http_code}" http://$HOSTNAME:3333/cgi/liblogin.do --data-urlencode "key=$KEY" 2>> curl.log)
    [ "$code" != "403" ] && echo "auth test 2 failed: expected 403, got $code" && exit 1

    # Test 3: wrong user should return 403
    KEY=$(printf 'wronguser:testpass' | base64 | tr -d '\n')
    code=$(curl -s -o /dev/null -w "%{http_code}" http://$HOSTNAME:3333/cgi/liblogin.do --data-urlencode "key=$KEY" 2>> curl.log)
    [ "$code" != "403" ] && echo "auth test 3 failed: expected 403, got $code" && exit 1

    # Test 4: "Basic " prefix + correct credentials, capture cookie
    KEY=$(printf 'testuser:testpass' | base64 | tr -d '\n')
    local cookie=$(curl -s -D - -o /dev/null http://$HOSTNAME:3333/cgi/liblogin.do --data-urlencode "key=Basic $KEY" 2>> curl.log | grep -i 'Set-Cookie:.*sproxy_token=' | sed 's/.*sproxy_token=//;s/;.*//')
    [ -z "$cookie" ] && echo "auth test 4 failed: login did not return sproxy_token cookie" && exit 1

    # Test 5: use token cookie to access page
    curl -f -s -o /dev/null -b "sproxy_token=$cookie" http://$HOSTNAME:3333/rproxy/ 2>> curl.log
    [ $? -ne 0 ] && echo "auth test 5 failed: token cookie rejected" && exit 1

    echo ""
}

function test_rproxy(){
    echo "test rproxy2 functionality"
    # Start rguest2 client that connects to the server and registers as "test_proxy"
    ./sproxy -c client.conf --rproxy test_proxy https://$HOSTNAME:3334 --admin unix:${sp}rproxy2.sock > rproxy.log 2>&1 &
    sleep 2

    # Test listing available rproxys
    curl -f -s http://$HOSTNAME:3333/rproxy/ | grep test_proxy
    [ $? -ne 0 ] && echo "rproxy not found in list" && exit 1

    # Test basic HTTP requests through rproxy2 using URL path method
    curl -f -v http://$HOSTNAME:3333/rproxy/test_proxy/qq.com/ > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy2 URL test 1 failed" && exit 1

    curl -f -v http://$HOSTNAME:3333/rproxy/test_proxy/http://cloudflare.com/cdn-cgi/trace  2>> curl.log
    [ $? -ne 0 ] && echo "rproxy2 URL test 2 failed" && exit 1

    curl -f -v http://$HOSTNAME:3333/rproxy/test_proxy/https://www.qq.com/ -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy2 URL test 3 failed" && exit 1

    curl -f -v http://$HOSTNAME:3333/rproxy/test_proxy/http://qq.com/ -XPOST -d "foo=bar" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy2 URL POST test failed" && exit 1

    curl -f -v http://$HOSTNAME:3333/rproxy/test_proxy/https://example.com/ -I 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy2 URL HEAD test failed" && exit 1

    curl -f -v \
        -H "Sproxy: test_proxy" \
        -H "Expect: 100-continue" \
        -F 'name=@test1k' \
        -x http://$HOSTNAME:3333 \
        http://echo.opera.com  >> curl.log 2>&1
    [ $? -ne 0 ] && echo "rproxy2 100-continue test failed" && exit 1

    printf "dump usage" | ./scli -s ${sp}rproxy2.sock
    kill -SIGUSR1 %2
    kill -SIGINT %2
    wait %2

    echo "test rproxy3 functionality"
    ./sproxy -c client.conf --rproxy test_proxy quic://$HOSTNAME:3334 --admin unix:${sp}rproxy3.sock >> rproxy.log 2>&1 &
    sleep 2

    curl -f -ks https://$HOSTNAME:3334/rproxy/ | grep test_proxy
    [ $? -ne 0 ] && echo "rproxy3 not found in list" && exit 1

    curl -f -kv https://$HOSTNAME:3334/rproxy/test_proxy/qq.com/ > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy3 URL test 1 failed" && exit 1

    curl -f -kv https://$HOSTNAME:3334/rproxy/test_proxy/https://cloudflare.com/cdn-cgi/trace -A "Mozilla/5.0" 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy3 URL test 2 failed" && exit 1

    curl -f -kv https://$HOSTNAME:3334/rproxy/test_proxy/http://qq.com/ -XPOST -d "foo=bar" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "rproxy3 POST test failed" && exit 1


    curl -f -v \
        -H "Sproxy: test_proxy" \
        -H "Expect: 100-continue" \
        -F 'name=@test1k' \
        --proxy-insecure \
        -x https://$HOSTNAME:3334 \
        http://echo.opera.com  >> curl.log 2>&1
    [ $? -ne 0 ] && echo "rproxy2 100-continue test failed" && exit 1

    printf "dump usage" | ./scli -s ${sp}rproxy3.sock
    kill -SIGUSR1 %2
    kill -SIGINT %2
    wait %2
}

#DoH服务(/dns-query)验证：独立实例 + 公共DoH上游(cloudflare-dns.com)。
#1) type-65应答透传ech参数；2) 被MITM的域名(block子域触发mayBeBlocked)
#应答剥离ech；3) curl以sproxy为DoH解析器并经代理访问，验证真实DoH客户端兼容
function test_doh_strip(){
    cat > server_doh.conf << EOF
cafile ca.crt
cakey  ca.key
cert localhost.crt
key localhost.key
root-dir .
policy-file sites_doh.list
secret testuser:testpass
index libproxy.do
insecure
bind 3360
doh https://cloudflare-dns.com/dns-query
debug all
EOF
    echo "localhost.choury.com local" > sites_doh.list
    ./sproxy -c server_doh.conf --admin unix:${sp}doh.sock > doh_server.log 2>&1 &
    doh_pid=$!
    wait_tcp_port 3360

    curl -s -m 15 -H 'content-type: application/dns-message' --data-binary @ech_query.bin \
        http://localhost:3360/dns-query -o doh_resp1.bin
    [ $? -ne 0 -o ! -s doh_resp1.bin ] && echo "doh strip test 1 failed" && exit 1
    if ! grep -q $'\xfe\x0d' doh_resp1.bin; then
        echo "doh strip test 2 failed: upstream has no ech in HTTPS RR, skip"
        kill -SIGINT $doh_pid; wait $doh_pid
        return
    fi

    #block整个域名(将被MITM)后，ech应被剥离
    curl -s http://localhost:3360/cgi/libsites.do -XPUT -d 'site=cloudflare-ech.com&strategy=block' > /dev/null 2>&1
    curl -s -m 15 -H 'content-type: application/dns-message' --data-binary @ech_query.bin \
        http://localhost:3360/dns-query -o doh_resp2.bin
    [ $? -ne 0 -o ! -s doh_resp2.bin ] && echo "doh strip test 3 failed" && exit 1
    if grep -q $'\xfe\x0d' doh_resp2.bin; then
        echo "doh strip test 4 failed: ech not stripped for MITM domain"
        exit 1
    fi

    #curl作为真实DoH客户端：经sproxy解析域名并经其代理访问未block的域名
    curl -s -m 20 -x http://localhost:3360 --doh-url http://localhost:3360/dns-query \
        https://cloudflare-dns.com/ -o /dev/null
    [ $? -ne 0 ] && echo "doh strip test 5 failed: curl --doh-url via proxy" && exit 1

    kill -SIGINT $doh_pid; wait $doh_pid
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
        curl -k -f -v --http3-only https://cloudflare-quic.com  > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tproxy test 5 failed" && exit 1
    fi
}

function test_tun(){
    ./sproxy -c server.conf --tun --admin unix:${sp}server_tun.sock > server_tun.log 2>&1 &
    wait_netdev tun0

    ip rule add from all lookup 1
    ip rule add fwmark 1 lookup main
    ip route add default dev tun0 table 1

    ip -6 rule add from all lookup 1
    ip -6 rule add fwmark 1 lookup main
    ip -6 route add default dev tun0 table 1

    function _tun_cleanup() {
        ip rule del fwmark 1 lookup main
        ip rule del from all lookup 1
        ip route flush table 1

        ip -6 rule del fwmark 1 lookup main
        ip -6 rule del from all lookup 1
        ip -6 route flush table 1
    }

    trap "_tun_cleanup; cleanup" EXIT
    trap "_tun_cleanup; trap cleanup EXIT" RETURN

    curl -k -f -v --http1.1 http://qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tun test 1 failed" && exit 1
    curl -6 -k -f -v --http2 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tun test 2 failed" && exit 1
    curl -k -f -v -H "Expect: 100-continue" --http1.1 http://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tun test 3 failed" && exit 1
    curl -k -f -v --http2 https://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tun test 4 failed" && exit 1
    curl -m 5 -k -f -v https://localhost.choury.com/test?size=100M > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tun test 5 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -k -f -v --http3-only https://cloudflare-quic.com  > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tun test 6 failed" && exit 1
        curl -m 5 -k -f -v --http3-only https://localhost.choury.com/test?size=100M > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tun test 7 failed" && exit 1
    fi

    ping -e 1 -4 -c 3 g.cn || true
    [ $? -ne 0 ] && echo "tun test 8 failed" && exit 1
    ping -6 -c 3 g.cn
    [ $? -ne 0 ] && echo "tun test 9 failed" && exit 1

    printf "dump usage" | ./scli -s ${sp}server_tun.sock
    kill -SIGUSR1 %1
    kill -SIGINT %1
    wait %1
    jobs
}

function test_tap(){
    ./sproxy -c server.conf --tap --admin unix:${sp}server_tap.sock > server_tap.log 2>&1 &
    wait_netdev tap0

    ip rule add from all lookup 1
    ip rule add fwmark 1 lookup main
    ip route add default via 198.18.0.2 dev tap0 table 1

    ip -6 rule add from all lookup 1
    ip -6 rule add fwmark 1 lookup main
    ip -6 route add default via 64:ff9b::c612:2 dev tap0 table 1

    function _tap_cleanup() {
        ip rule del fwmark 1 lookup main
        ip rule del from all lookup 1
        ip route flush table 1

        ip -6 rule del fwmark 1 lookup main
        ip -6 rule del from all lookup 1
        ip -6 route flush table 1
    }

    trap "_tap_cleanup; cleanup" EXIT
    trap "_tap_cleanup; trap cleanup EXIT" RETURN

    curl -k -f -v --http1.1 http://qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tap test 1 failed" && exit 1
    curl -6 -k -f -v --http2 https://www.qq.com -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tap test 2 failed" && exit 1
    curl -k -f -v -H "Expect: 100-continue" --http1.1 http://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tap test 3 failed" && exit 1
    curl -k -f -v --http2 https://echo.opera.com -F 'name=@test1k' > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tap test 4 failed" && exit 1
    curl -m 5 -k -f -v https://localhost.choury.com/test?size=100M > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "tap test 5 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -k -f -v --http3-only https://cloudflare-quic.com  > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tap test 6 failed" && exit 1
        curl -m 5 -k -f -v --http3-only https://localhost.choury.com/test?size=100M > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "tap test 7 failed" && exit 1
    fi


    ping -e 1 -4 -c 3 g.cn || true
    [ $? -ne 0 ] && echo "tap test 8 failed" && exit 1
    ping -6 -c 3 g.cn
    [ $? -ne 0 ] && echo "tap test 9 failed" && exit 1

    printf "dump usage" | ./scli -s ${sp}server_tap.sock
    kill -SIGUSR1 %1
    kill -SIGINT %1
    wait %1
    jobs
}

function test_sni(){
    ./sproxy -c server.conf --bind "443 ssl sni" --bind "443 quic sni"  --admin unix:${sp}server.sock > server_sni.log 2>&1 &
    wait_tcp_port 443

    curl -f -v --http1.1 https://qq.com --resolve qq.com:443:127.0.0.1 -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 1 failed" && exit 1
    curl -f -v --http2 https://qq.com --resolve qq.com:443:127.0.0.1  -A "Mozilla/5.0" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 2 failed" && exit 1
    curl -f -v https://echo.opera.com -F 'name=@test1k' --resolve echo.opera.com:443:127.0.0.1 > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "sni test 3 failed" && exit 1

    curl -V | grep HTTP3
    if [[ $? = 0 ]];then
        curl -f -v --http3-only https://cloudflare-quic.com --resolve cloudflare-quic.com:443:127.0.0.1 > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "sni test 4 failed" && exit 1
    fi

    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1
    kill -SIGINT %1
    wait %1
    jobs

    ./sproxy -c server.conf --bind "443 ssl sni" --bind "443 quic sni" --mitm enable  --admin unix:${sp}server.sock >> server_sni.log 2>&1 &
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
        curl -k -f -v --http3-only https://cloudflare-quic.com --resolve cloudflare-quic.com:443:127.0.0.1 > /dev/null 2>> curl.log
        [ $? -ne 0 ] && echo "sni test 10 failed" && exit 1
    fi

    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1
    jobs
}

#代理CONNECT路径的ECH决策：GREASE(outer SNI==CONNECT域名)保持MITM、真实
#ECH转隧道，及隧道上游EOF向客户端的传播。ECH后端复用test_sni留在443的
#实例(其mitm层持同一ech密钥，能解密inner)，前端4434(h1)/4435(h2)
function test_ech_mitm(){
    if [ ! -s ech.dns ]; then
        #echgen在无ech支持的构建下无输出
        echo "ech not supported by this build, skip"
        kill -SIGINT %1 2>/dev/null; wait %1 2>/dev/null
        return
    fi
    #4435入口证书SAN不含$HOSTNAME：否则lookup_cert会命中预置证书替代
    #动态签发(动态证书subject=CONNECT域名是断言依据)
    openssl req -new -key localhost.key -out h2front.csr -subj '/CN=localhost' 2>/dev/null
    printf '[SAN]
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
' > h2front_san.cnf
    openssl x509 -req -days 365 -in h2front.csr -CA ca.crt -CAkey ca.key -set_serial 02 \
        -out h2front.crt -extfile h2front_san.cnf -extensions SAN 2>/dev/null
    cat > echfront.conf << EOF
cafile ca.crt
cakey  ca.key
cert h2front.crt
key localhost.key
insecure
bind 4434
bind 4435 ssl
mitm enable
debug all
EOF
    ./sproxy -c echfront.conf --admin unix:${sp}echfront.sock > echfront.log 2>&1 &
    echfront_pid=$!
    wait_tcp_port 4434
    wait_tcp_port 4435

    #纯代理前端(无ca/mitm配置)：验证无名目标的无条件嗅探
    ./sproxy -k --bind 4436 --debug all --admin unix:${sp}echplain.sock > echplain.log 2>&1 &
    echplain_pid=$!
    wait_tcp_port 4436

    #GREASE(outer SNI==CONNECT域名)：保持MITM，动态签发证书
    { echo "connect localhost 4434";
      echo "send CONNECT $HOSTNAME:443\r\n\r\n";
      echo "read head";
      echo "tlsconnect $HOSTNAME grease"; } | ./sproxy_test > ech_case1.log 2>&1
    [ $? -ne 0 ] && echo "ech mitm test 1 failed" && exit 1
    grep -q " 200 " ech_case1.log
    [ $? -ne 0 ] && echo "ech mitm test 1.5 failed: CONNECT not established" && exit 1
    grep -q "subject:.*$HOSTNAME" ech_case1.log
    [ $? -ne 0 ] && echo "ech mitm test 2 failed" && exit 1

    #真实ECH(outer SNI=public_name≠CONNECT域名)：转隧道，由后端mitm层解密
    { echo "connect localhost 4434";
      echo "send CONNECT $HOSTNAME:443\r\n\r\n";
      echo "read head";
      echo "tlsconnect localhost $(cat ech.dns)"; } | ./sproxy_test > ech_case2.log 2>&1
    [ $? -ne 0 ] && echo "ech mitm test 3 failed" && exit 1
    grep -q "ech accepted" ech_case2.log
    [ $? -ne 0 ] && echo "ech mitm test 4 failed" && exit 1
    grep -q "subject: /CN=localhost," ech_case2.log
    [ $? -ne 0 ] && echo "ech mitm test 5 failed" && exit 1

    #h2路径(Guest2嗅探)：4435 ssl + alpn h2，h2connect开CONNECT流(200先行
    #应答)，流内再叠tlsconnect跑内层TLS。证书断言只看status 200之后的输出，
    #外层tlsconnect(4435入口)也会打印cert subject
    #GREASE × h2 CONNECT：保持MITM
    { echo "connect localhost 4435";
      echo "tlsconnect localhost - h2";
      echo "h2connect $HOSTNAME:443";
      echo "tlsconnect $HOSTNAME grease";
      echo "close"; } | ./sproxy_test > ech_case4.log 2>&1
    [ $? -ne 0 ] && echo "ech mitm h2 test 1 failed" && exit 1
    grep -q "\[h2\] status 200" ech_case4.log
    [ $? -ne 0 ] && echo "ech mitm h2 test 1.5 failed: CONNECT not established" && exit 1
    sed -n '/\[h2\] status 200/,$p' ech_case4.log | grep -q "subject:.*$HOSTNAME"
    [ $? -ne 0 ] && echo "ech mitm h2 test 2 failed" && exit 1

    #真实ECH × h2 CONNECT：转隧道
    { echo "connect localhost 4435";
      echo "tlsconnect localhost - h2";
      echo "h2connect $HOSTNAME:443";
      echo "tlsconnect localhost $(cat ech.dns)";
      echo "close"; } | ./sproxy_test > ech_case5.log 2>&1
    [ $? -ne 0 ] && echo "ech mitm h2 test 3 failed" && exit 1
    grep -q "ech accepted" ech_case5.log
    [ $? -ne 0 ] && echo "ech mitm h2 test 4 failed" && exit 1
    sed -n '/\[h2\] status 200/,$p' ech_case5.log | grep -q "subject: /CN=localhost,"
    [ $? -ne 0 ] && echo "ech mitm h2 test 5 failed" && exit 1

    #FIN传播：杀掉复用的443后端(%1)换哑上游(nc accept即FIN，单连接，每用例
    #重开)。grease ECH且SNI≠CONNECT目标判真实ECH走隧道，上游FIN应传回使握手
    #立即失败；误MITM则会握手成功并打印证书subject
    kill -SIGINT %1; wait %1
    start_dumb_443() {
        #nc_pid未设时wait无参会等到所有后台任务(含常驻实例)
        if [ -n "$nc_pid" ]; then
            kill $nc_pid 2>/dev/null
            wait $nc_pid 2>/dev/null
        fi
        nc -l -N 127.0.0.1 443 < /dev/null > /dev/null &
        nc_pid=$!
        sleep 0.2
    }
    start_dumb_443
    { echo "connect localhost 4434";
      echo "send CONNECT $HOSTNAME:443\r\n\r\n";
      echo "read head";
      echo "tlsconnect sni-not-target.test grease"; } | ./sproxy_test > ech_case3.log 2>&1 || true
    grep -q "ssl connect failed" ech_case3.log
    [ $? -ne 0 ] && echo "ech mitm test 6 failed" && exit 1
    if grep -q "cert subject" ech_case3.log; then
        echo "ech mitm test 7 failed: mitm should not happen" && exit 1
    fi

    #h2路径FIN传播：同上但经h2 CONNECT
    start_dumb_443
    { echo "connect localhost 4435";
      echo "tlsconnect localhost - h2";
      echo "h2connect $HOSTNAME:443";
      echo "tlsconnect sni-not-target.test grease";
      echo "close"; } | ./sproxy_test > ech_case6.log 2>&1 || true
    grep -q "stream closed during handshake" ech_case6.log
    [ $? -ne 0 ] && echo "ech mitm h2 test 6 failed: tunnel eof not propagated" && exit 1
    if sed -n '/\[h2\] status 200/,$p' ech_case6.log | grep -q "cert subject"; then
        echo "ech mitm h2 test 7 failed: mitm should not happen" && exit 1
    fi
    kill $nc_pid 2>/dev/null; wait $nc_pid 2>/dev/null

    #IP字面量目标无条件嗅探：无ca/mitm的纯代理上也应嗅探并改写目标为SNI
    #(域名不存在，握手失败是预期)
    { echo "connect localhost 4436";
      echo "send CONNECT 127.0.0.1:443\r\n\r\n";
      echo "read head";
      echo "tlsconnect sni-ip-sniff.test"; } | ./sproxy_test > ech_case7.log 2>&1 || true
    grep -q "\[sni\] forward to sni-ip-sniff.test" echplain.log
    [ $? -ne 0 ] && echo "ech plain test 1 failed: ip target not sniffed" && exit 1

    kill -SIGINT $echfront_pid; wait $echfront_pid
    kill -SIGINT $echplain_pid; wait $echplain_pid
    echo ""
}

function test_strategy() {
    local sock=$1
    local port=$2
    echo "Testing strategies ..."

    printf "adds direct direct.test\n" | ./scli -s ${sock}
    printf "adds block block.test\n" | ./scli -s ${sock}
    printf "adds proxy proxy.test http://127.0.0.1:8080\n" | ./scli -s ${sock}
    printf "adds local local.test\n" | ./scli -s ${sock}
    printf "adds forward forward.test http://127.0.0.1:80\n" | ./scli -s ${sock}
    printf "adds rewrite rewrite.test http://127.0.0.1:80\n" | ./scli -s ${sock}
    printf "adds proxy 1.2.3.4 http://1.1.1.1:80\n" | ./scli -s ${sock}
    printf "adds proxy 192.168.0.0/16 http://192.168.1.1:80\n" | ./scli -s ${sock}
    printf "adds proxy [2001:db8::1] http://[::1]:80\n" | ./scli -s ${sock}

    printf "test direct.test\n" | ./scli -s ${sock} | grep "direct" || { echo "direct failed"; exit 1; }
    printf "test block.test\n" | ./scli -s ${sock} | grep "block" || { echo "block failed"; exit 1; }
    printf "test proxy.test\n" | ./scli -s ${sock} | grep "proxy http://127.0.0.1:8080" || { echo "proxy failed"; exit 1; }
    printf "test local.test\n" | ./scli -s ${sock} | grep "local" || { echo "local failed"; exit 1; }
    printf "test forward.test\n" | ./scli -s ${sock} | grep "forward http://127.0.0.1:80" || { echo "forward failed"; exit 1; }
    printf "test rewrite.test\n" | ./scli -s ${sock} | grep "rewrite http://127.0.0.1:80" || { echo "rewrite failed"; exit 1; }
    printf "test 1.2.3.4\n" | ./scli -s ${sock} | grep "proxy http://1.1.1.1:80" || { echo "ipv4 failed"; exit 1; }
    printf "test 192.168.1.50\n" | ./scli -s ${sock} | grep "proxy http://192.168.1.1:80" || { echo "ipv4 cidr failed"; exit 1; }
    printf "test [2001:db8::1]\n" | ./scli -s ${sock} | grep -F "proxy http://[::1]:80" || { echo "ipv6 failed"; exit 1; }

    echo "Testing Alias ..."
    printf "adds alias myauth socks5://user:pass@127.0.0.1:1080\n" | ./scli -s ${sock}
    printf "adds proxy auth.test @myauth\n" | ./scli -s ${sock}
    printf "test auth.test\n" | ./scli -s ${sock} | grep "proxy socks5://user:pass@127.0.0.1:1080" || { echo "alias auth failed"; exit 1; }
    printf "dels @myauth\n" | ./scli -s ${sock}
    printf "test auth.test\n" | ./scli -s ${sock} | grep "null" || { echo "alias deletion/non-exist failed"; exit 1; }

    echo "Testing Matching..."
    printf "adds proxy *.match.test http://wildcard\n" | ./scli -s ${sock}
    printf "adds proxy long.match.test http://specific\n" | ./scli -s ${sock}
    printf "adds block regex.test .*\.png\n" | ./scli -s ${sock}

    printf "test short.match.test\n" | ./scli -s ${sock} | grep "proxy http://wildcard" || { echo "wildcard failed"; exit 1; }
    printf "test long.match.test\n" | ./scli -s ${sock} | grep "proxy http://specific" || { echo "longest match failed"; exit 1; }

    printf "test regex.test/image.png\n" | ./scli -s ${sock} | grep "block .*\.png" || { echo "block regex failed"; exit 1; }
    printf "test regex.test/index.html\n" | ./scli -s ${sock} | grep "direct" || { echo "block regex fallthrough failed"; exit 1; }

    echo "Testing Deletion & Default..."
    printf "dels proxy.test\n" | ./scli -s ${sock}
    printf "test proxy.test\n" | ./scli -s ${sock} | grep "direct" || { echo "strategy deletion/default failed"; exit 1; }

    echo "Testing Backend Selection..."
    printf "adds alias backend_test http://127.0.0.1:3333\n" | ./scli -s ${sock}

    curl -f -v -x http://localhost:$port -U "user+backend_test:pass" http://localhost/sites.list > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "backend selection via Proxy-Authorization failed" && exit 1

    curl -f -v -x http://localhost:$port http://localhost/sites.list -H "Sproxy: backend_test" > /dev/null 2>> curl.log
    [ $? -ne 0 ] && echo "backend selection via sproxy header failed" && exit 1

    printf "dels @backend_test\n" | ./scli -s ${sock}
}

function wait_tcp_port() {
    local count=0
    while ! nc -vz localhost $1; do
        ps aux | grep sproxy | grep -v grep
        count=$((count + 1))
        if [ $count -ge 5 ]; then
            echo "Error: Timeout waiting for port $1"
            exit 1
        fi
        sleep 1
    done
}

function wait_udp_port() {
    local count=0
    while ! lsof -Pi udp:$1; do
        ps aux | grep sproxy | grep -v grep
        count=$((count + 1))
        if [ $count -ge 5 ]; then
            echo "Error: Timeout waiting for udp port $1"
            exit 1
        fi
        sleep 1
    done
}

function wait_netdev() {
    local dev=$1
    local count=0
    while ! ip link show $dev >/dev/null 2>&1; do
        ps aux | grep sproxy | grep -v grep
        count=$((count + 1))
        if [ $count -ge 5 ]; then
            echo "Error: Timeout waiting for $dev"
            exit 1
        fi
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
ln -f -s "$buildpath"/cgi/liblogin.* cgi/
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
secret testuser:testpass
index libproxy.do
insecure
bind 3333
bind 3334 ssl
bind 3334 quic
quic-cc bbr
ipv6 enable
debug all
EOF

#ech密钥文件：无ech支持的构建下echgen失败，ech-key被忽略
rm -f ech.key ech.dns #echgen以O_EXCL建文件，残留会让生成失败而ech测试静默跳过
echo "echgen ech.key localhost" | ./sproxy_test > ech.dns 2>/dev/null || true
if [ -s ech.dns ]; then
    echo "ech-key ech.key" >> server.conf
fi
#出站ech依赖上游DNS返回可信的HTTPS记录，明文DNS环境下可能被污染导致握手被拒，
#测试环境不做外网ech假设，出站ech的验证见sproxy_test的tlsconnect命令
echo "ech disable" >> server.conf

if [ "$run_extended_tests" = true ]; then
    echo "bind 4333 tproxy" >> server.conf
    echo "fwmark 1" >> server.conf
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

if [ -s ech.dns ]; then
    echo "test ech server"
    test_ech 3334
    kill -SIGUSR1 %1
fi

wait_udp_port 3334
echo "test quic server"
test_http3 3334
kill -SIGUSR1 %1

test_auth

cat > client.conf << EOF
root-dir .
policy-file /dev/null
insecure
quic-version 2
debug all
EOF

./sproxy -c client.conf --bind 3335  https://$HOSTNAME:3334 --disable-http2 --admin unix:${sp}client_h1.sock > client_h1.log 2>&1 &
wait_tcp_port 3335

echo "test http1 -> http1"
test_client 3335
test_strategy ${sp}client_h1.sock 3335
jobs
printf "dump sites" | ./scli -s ${sp}client_h1.sock
printf "dump usage" | ./scli -s ${sp}client_h1.sock
kill -SIGUSR1 %2
kill -SIGINT %2
wait %2

./sproxy -c client.conf --bind 3335  https://$HOSTNAME:3334 --admin unix:${sp}client_h23.sock > client_h23.log 2>&1 &
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
kill -SIGINT %2
wait %2

test_rproxy

printf "dump usage" | ./scli -s ${sp}server.sock
kill -SIGUSR1 %1

echo "test doh strip"
test_doh_strip

if [ "$run_extended_tests" = true ]; then
    echo "test tproxy"
    test_tproxy 4333
    printf "dump usage" | ./scli -s ${sp}server.sock
    kill -SIGUSR1 %1

    kill -SIGINT %1
    wait %1
    jobs

    echo "test tun"
    test_tun

    echo "test tap"
    test_tap

    echo "test sni"
    test_sni

    echo "test ech mitm"
    test_ech_mitm
else
    kill -SIGINT %1
    wait %1
fi

jobs

#单测退出码检查：非0失败即中止，77表示skip
function run_test() {
    "$@"
    local ret=$?
    if [ $ret -eq 77 ]; then
        echo "$1 skipped"
        return 0
    fi
    if [ $ret -ne 0 ]; then
        echo "$1 failed: $ret"
        exit 1
    fi
}

run_test $buildpath/prot/dns/dns_test
run_test $buildpath/prot/dns/ech_test
run_test $buildpath/prot/http2/hpack_test
run_test $buildpath/prot/http3/qpack_test
run_test $buildpath/prot/quic/quic_frame_test
run_test $buildpath/misc/trie_test
run_test $buildpath/misc/buffer_test
if [ $ker == 'Linux' ];then
    run_test $buildpath/hook/hook_test $buildpath/hook/hook_bpf.elf
fi
