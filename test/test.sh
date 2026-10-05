#!/bin/bash
set -x

HOSTNAME=localhost.choury.com

#ip6-localhost 是 Debian /etc/hosts 的固有别名，macOS 等平台没有：
#mesh 测试用它当第三个可解析节点名，缺失则补一条（无权限则跳过相关用例）
if ! python3 -c "import socket; socket.getaddrinfo('ip6-localhost', None)" 2>/dev/null; then
    if ! (echo "::1 ip6-localhost" | sudo tee -a /etc/hosts >/dev/null 2>&1) \
       && ! (echo "::1 ip6-localhost" >> /etc/hosts 2>/dev/null); then
        echo "ip6-localhost unresolvable and cannot fix /etc/hosts, mesh ipv6-name tests may fail"
    fi
fi

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

#mesh Phase 1 冒烟：B(3371,出口,名=$HOSTNAME)与A(3370,入口,名=localhost)静态组网。
#节点名取自 peer URL 主机名；出口不再套本地策略而是 direct，目标统一由普通实例(3376)承载；
#CONNECT 用端口特定规则($HOSTNAME:3334)压过主机名的自动 local 规则；全程不依赖外网
function test_mesh(){
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    rm -f mesh_out
    cat > mesh.conf << EOF
root-dir .
policy-file /dev/null
debug all
EOF
    #普通目标服务器（无 mesh）：出口 direct 直连它应答
    printf "127.0.0.1 local\nlocalhost local\n$HOSTNAME local\n" > mesh_t.list
    #B 的本地策略对目标 block：出口 direct 不查本地策略，block 不应生效
    printf "127.0.0.1:3376 block\nlocalhost:3376 block\n" > mesh_b.list
    cat > mesh_a.list << EOF
127.0.0.1:3376 proxy mesh://$HOSTNAME
localhost:3376 proxy mesh://auto
$HOSTNAME:3333 proxy mesh://localhost
$HOSTNAME:3334 proxy mesh://$HOSTNAME
bad-mesh.net proxy mesh://nosuch.node
mesh-loop.local proxy mesh://$HOSTNAME
EOF
    ./sproxy -c mesh.conf --bind 3376 -P mesh_t.list --admin unix:${sp}mesht.sock > mesh_t.log 2>&1 &
    local tpid=$!
    ./sproxy -c mesh.conf --mesh=$HOSTNAME --mesh-secret=mesh-pass \
        --bind 3371 -P mesh_b.list --mesh-peer=http://localhost:3370 \
        --admin unix:${sp}meshb.sock > mesh_b.log 2>&1 &
    local bpid=$!
    ./sproxy -c mesh.conf --mesh=localhost --mesh-secret=mesh-pass \
        --bind 3370 --secret=client:pass -P mesh_a.list \
        --mesh-peer=http://$HOSTNAME:3371 \
        --admin unix:${sp}mesha.sock > mesh_a.log 2>&1 &
    local apid=$!
    wait_tcp_port 3370
    wait_tcp_port 3371
    wait_tcp_port 3376

    #等 A 对 B 的首次探测成功（DNS 失败重试下可能要到第三拍）
    local count=0
    while ! printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "probes=[1-9]/"; do
        count=$((count + 1))
        if [ $count -ge 40 ]; then
            echo "mesh test 1 failed: no probe result"
            exit 1
        fi
        sleep 1
    done

    #经 mesh 转发：A -> B(出口) -> direct -> 普通实例 /status；
    #B 对目标配了 block，仍应 200（出口不套本地策略）
    curl -sf -m 10 -x client:pass@127.0.0.1:3370 http://127.0.0.1:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh test 2 failed: forward via mesh" && exit 1

    #CONNECT 隧道（https 经 mesh 中继）：A -> B(出口) -> direct -> 本测试的 https 服务
    curl -sf -m 10 -k -x client:pass@127.0.0.1:3370 https://$HOSTNAME:3334/sites.list -o mesh_out \
        && [ -s mesh_out ]
    [ $? -ne 0 ] && echo "mesh test 3 failed: CONNECT tunnel via mesh" && exit 1

    #mesh:// 策略写未知节点：mesh/rproxy/alias 三级皆 miss，404
    curl -s -m 10 -x client:pass@127.0.0.1:3370 http://bad-mesh.net/ | grep -q "\[\[can't find backend\]\]"
    [ $? -ne 0 ] && echo "mesh test 4 failed: unknown node" && exit 1

    #出口 direct 后不可达目标自然失败（不再有出口重入 508 一说）
    curl -s -m 10 -x client:pass@127.0.0.1:3370 http://mesh-loop.local/ -o mesh_out
    grep -q "Proxy server" mesh_out
    [ $? -eq 0 ] && echo "mesh test 5 failed: unreachable target should fail" && exit 1

    #合法 mesh 凭据但 identifier 是未知名字：落 rproxy/alias 后 404
    [ "$(curl -s -m 10 -x 127.0.0.1:3371 \
        -H "Proxy-Authorization: Basic $(echo -n mesh+third.node:mesh-pass | base64)" \
        http://127.0.0.1:3376/ -o /dev/null -w "%{http_code}")" != "404" ] \
        && echo "mesh test 6 failed: unknown identifier" && exit 1

    #mesh://auto：唯一出口 B 被选中并成功应答
    curl -sf -m 10 -x client:pass@127.0.0.1:3370 http://localhost:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh test 7 failed: auto exit" && exit 1

    #mesh://<本节点名> 归一化为 direct：请求直连主服务器的 /mesh/ping（其未启用 mesh，应答 404）
    curl -s -m 10 -x client:pass@127.0.0.1:3370 http://$HOSTNAME:3333/mesh/ping | grep -q "\[\[mesh not enabled\]\]"
    [ $? -ne 0 ] && echo "mesh test 8 failed: mesh://self should fall to direct" && exit 1

    #普通用户凭据的 identifier 触发 mesh（不要求 mesh 用户）：A 应记 dispatch 日志
    curl -sf -m 10 -x client+$HOSTNAME:pass@127.0.0.1:3370 http://$HOSTNAME:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh test 9 failed: normal user identifier" && exit 1
    sleep 1
    grep -aq "mesh dispatch: http://$HOSTNAME:3376" mesh_a.log
    [ $? -ne 0 ] && echo "mesh test 9 failed: no dispatch log" && exit 1

    #identifier=auto 同样触发（dump 应出现 auto 出口选择）
    curl -sf -m 10 -x client+auto:pass@127.0.0.1:3370 http://127.0.0.1:3376/status -o mesh_out
    [ $? -ne 0 ] && echo "mesh test 10 failed: identifier auto" && exit 1
    printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "auto exit: $HOSTNAME"
    [ $? -ne 0 ] && echo "mesh test 10 failed: no auto exit in dump" && exit 1

    #控制面端点仅接受 mesh 凭据
    [ "$(curl -s -m 5 --noproxy "*" http://127.0.0.1:3371/mesh/ping -o /dev/null -w "%{http_code}")" != "401" ] \
        && echo "mesh test 11 failed: expect 401" && exit 1
    curl -s -m 5 --noproxy "*" -u mesh:mesh-pass http://127.0.0.1:3371/mesh/ping | grep -q pong
    [ $? -ne 0 ] && echo "mesh test 11 failed: ping" && exit 1

    #h2(https) peer 路径 + 目标解析优先级 alias > rproxy > mesh：
    #B2(4471 ssl) 为 peer/出口并直接受理 identifier 请求。B2 上只给 myback 配 alias（死地址）；
    #ip6-localhost 不配 alias，留给 mesh（A2 节点）与 rproxy 后端（bp 注册，对目标 block）竞争
    printf "127.0.0.1 local\nmyback alias http://127.0.0.1:1/\n" > mesh_b2.list
    printf "127.0.0.1 block\nlocalhost block\n$HOSTNAME block\n" > mesh_bp.list
    printf "127.0.0.1 local\nlocalhost local\n$HOSTNAME local\n" > mesh_bg.list
    ./sproxy -c mesh.conf --mesh=$HOSTNAME --mesh-secret=mesh-pass --secret=client:pass \
        --bind "4471 ssl" --cert localhost.crt --key localhost.key \
        -P mesh_b2.list --admin unix:${sp}meshb2.sock > mesh_b2.log 2>&1 &
    local b2pid=$!
    SSL_CERT_FILE=$PWD/ca.crt ./sproxy -c mesh.conf --mesh=ip6-localhost --mesh-secret=mesh-pass \
        --bind 3372 --secret=client:pass -P mesh_a.list \
        --mesh-peer=https://$HOSTNAME:4471 \
        --admin unix:${sp}mesha2.sock > mesh_a2.log 2>&1 &
    local a2pid=$!
    count=0
    while ! printf "dump mesh" | ./scli -s ${sp}mesha2.sock | grep -q "probes=[1-9]/"; do
        count=$((count + 1))
        if [ $count -ge 40 ]; then
            echo "mesh test 12 failed: no h2 probe result"
            break
        fi
        sleep 1
    done
    #等 B2 对 A2（经 announce 发现）探测出边：mesh 兜底用例需要 B2→A2 可路由
    count=0
    while ! printf "dump mesh" | ./scli -s ${sp}meshb2.sock | grep -q "ip6-localhost.*probes=[1-9]"; do
        count=$((count + 1))
        if [ $count -ge 20 ]; then
            echo "mesh test 13 failed: no probe to a2"
            exit 1
        fi
        sleep 1
    done

    #mesh 兜底：rproxy 后端尚未注册，identifier=mesh 节点名（A2）无冲突，走 mesh 成功
    curl -sf -m 10 --proxy-insecure -x https://$HOSTNAME:4471 \
        -H "Proxy-Authorization: Basic $(echo -n client+ip6-localhost:pass | base64)" \
        http://127.0.0.1:3376/status -o mesh_out && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh test 12 failed: mesh fallback" && exit 1

    #h2 peer 转发
    curl -sf -m 10 -x client:pass@127.0.0.1:3372 http://127.0.0.1:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh test 12 failed: forward via h2 peer" && exit 1
    grep -q "AddressSanitizer" mesh_a2.log && echo "mesh test 12 failed: asan report" && exit 1

    #注册 rproxy 后端：ip6-localhost（bp，对目标 block）、myback（bg，本地应答）
    SSL_CERT_FILE=$PWD/ca.crt ./sproxy -c mesh.conf --rproxy https://$HOSTNAME:4471/ip6-localhost \
        -P mesh_bp.list --admin unix:${sp}meshbp.sock > mesh_bp.log 2>&1 &
    local bppid=$!
    SSL_CERT_FILE=$PWD/ca.crt ./sproxy -c mesh.conf --rproxy https://$HOSTNAME:4471/myback \
        -P mesh_bg.list --admin unix:${sp}meshbg.sock > mesh_bg.log 2>&1 &
    local bgpid=$!
    #等 rproxy 注册：ip6-localhost 注册前走 mesh 会成功，注册后被 bp 截住（block 403）
    count=0
    while ! curl -s -m 5 --proxy-insecure -x https://$HOSTNAME:4471 \
        -H "Proxy-Authorization: Basic $(echo -n client+ip6-localhost:pass | base64)" \
        http://127.0.0.1:3376/status | grep -q "blocked"; do
        count=$((count + 1))
        if [ $count -ge 20 ]; then
            echo "mesh test 13 failed: rproxy backend not registered"
            exit 1
        fi
        sleep 1
    done
    #rproxy 压过 mesh：identifier=ip6-localhost 须走 rproxy 后端 bp（block 403）而非 mesh（会成功）
    curl -s -m 5 --proxy-insecure -x https://$HOSTNAME:4471 \
        -H "Proxy-Authorization: Basic $(echo -n client+ip6-localhost:pass | base64)" \
        http://127.0.0.1:3376/status | grep -q "blocked"
    [ $? -ne 0 ] && echo "mesh test 13 failed: rproxy should beat mesh" && exit 1
    #alias 压过 rproxy：identifier=myback 须走 alias（死地址失败）而非 rproxy 后端 bg（会成功）
    curl -sf -m 5 --proxy-insecure -x https://$HOSTNAME:4471 \
        -H "Proxy-Authorization: Basic $(echo -n client+myback:pass | base64)" \
        http://127.0.0.1:3376/status -o mesh_out \
        && echo "mesh test 14 failed: alias should beat rproxy" && exit 1

    kill -SIGINT $bppid $bgpid $b2pid $a2pid
    wait $bppid $bgpid $b2pid $a2pid 2>/dev/null

    #出口失联：杀 B 后请求必须失败（错误形态因平台/时序而异：
    #连接拒绝 [[connect failed]]、探测判死 [[mesh: no route]] 或连接重置空响应），
    #断言不变量为"不成功、不挂起"
    kill -SIGINT $bpid
    wait $bpid
    curl -s -m 10 -x client:pass@127.0.0.1:3370 http://127.0.0.1:3376/status -o mesh_out
    grep -q "Proxy server" mesh_out
    [ $? -eq 0 ] && echo "mesh test 15 failed: exit down" && exit 1

    kill -SIGINT $apid $tpid
    wait $apid $tpid 2>/dev/null
}

#mesh Phase 2：gossip 发现 + auto 出口。A(3370)只配种子 B(3371)，
#C(3373,名=ip6-localhost)只与 B 互联；A 应经 B 的节点表发现 C 并经其转发；
#auto 出口在 B/C 间选择（经 dump mesh 观察），杀掉被选中的节点后应切换到另一个。
#出口 direct，目标统一由普通实例(3376)承载
function test_mesh_gossip(){
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    rm -f mesh_out
    #探测/gossip 周期加速（环境变量是测试专用旋钮，非配置项）
    export SPROXY_MESH_PROBE_INTERVAL=1 SPROXY_MESH_GOSSIP_INTERVAL=2
    cat > meshg.conf << EOF
root-dir .
policy-file /dev/null
debug all
EOF
    printf "127.0.0.1 local\nlocalhost local\n$HOSTNAME local\n" > meshg_t.list
    : > meshg_c.list
    : > meshg_b.list
    cat > meshg_a.list << EOF
127.0.0.1:3376 proxy mesh://ip6-localhost
localhost:3376 proxy mesh://auto
EOF
    ./sproxy -c meshg.conf --bind 3376 -P meshg_t.list --admin unix:${sp}meshgt.sock > meshg_t.log 2>&1 &
    local tpid=$!
    ./sproxy -c meshg.conf --mesh=ip6-localhost --mesh-secret=mesh-pass \
        --bind 3373 -P meshg_c.list --mesh-peer=http://$HOSTNAME:3371 \
        --admin unix:${sp}meshc.sock > mesh_c.log 2>&1 &
    local cpid=$!
    ./sproxy -c meshg.conf --mesh=$HOSTNAME --mesh-secret=mesh-pass \
        --bind 3371 -P meshg_b.list --mesh-peer=http://localhost:3370 \
        --mesh-peer=http://ip6-localhost:3373 \
        --admin unix:${sp}meshb.sock > mesh_b.log 2>&1 &
    local bpid=$!
    ./sproxy -c meshg.conf --mesh=localhost --mesh-secret=mesh-pass \
        --bind 3370 --secret=client:pass -P meshg_a.list \
        --mesh-peer=http://$HOSTNAME:3371 \
        --admin unix:${sp}mesha.sock > mesh_a.log 2>&1 &
    local apid=$!
    wait_tcp_port 3370
    wait_tcp_port 3371
    wait_tcp_port 3373
    wait_tcp_port 3376

    #发现：A 的节点表应出现 C（仅经 gossip 学得，无静态配置）且探测已有样本
    #（路由需要边：直连边来自探测成功）
    local count=0
    while ! printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "ip6-localhost.*probes=[1-9]"; do
        count=$((count + 1))
        if [ $count -ge 30 ]; then
            echo "mesh gossip test 1 failed: no discovery"
            exit 1
        fi
        sleep 1
    done
    #经发现的节点转发：A -> C(出口) -> direct -> 普通实例 /status
    curl -sf -m 10 -x client:pass@127.0.0.1:3370 http://127.0.0.1:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh gossip test 2 failed: forward to discovered node" && exit 1

    #控制面 nodes 端点鉴权：普通凭据拒绝
    [ "$(curl -s -m 5 --noproxy "*" -u client:pass \
        http://127.0.0.1:3370/mesh/nodes -o /dev/null -w "%{http_code}")" = "401" ]
    [ $? -ne 0 ] && echo "mesh gossip test 3 failed: nodes must require mesh credential" && exit 1

    #同名冲突：D 与 C 同名(ip6-localhost)不同地址，A 应告警并保留既有条目
    ./sproxy -c meshg.conf --mesh=ip6-localhost --mesh-secret=mesh-pass \
        --bind 3374 --mesh-peer=http://localhost:3370 \
        --admin unix:${sp}meshd.sock > mesh_d.log 2>&1 &
    local dpid=$!
    count=0
    while ! grep -q "changed addrs" mesh_a.log; do
        count=$((count + 1))
        if [ $count -ge 20 ]; then
            echo "mesh gossip test 4 failed: no conflict alarm"
            break
        fi
        sleep 1
    done
    grep -q "changed addrs" mesh_a.log
    [ $? -ne 0 ] && echo "mesh gossip test 4 failed: conflict alarm" && exit 1
    #冲突不被劫持：A 保留既有条目的地址
    printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "ip6-localhost \[http://ip6-localhost:3373\]"
    [ $? -ne 0 ] && echo "mesh gossip test 4 failed: hijacked by conflicting entry" && exit 1
    kill -SIGINT $dpid; wait $dpid

    #mesh-exit=off：E 自宣无 exit 能力位，A 的节点表不应标记其为出口
    ./sproxy -c meshg.conf --mesh=noexit.local --mesh-secret=mesh-pass --mesh-exit=off \
        --bind 3375 --mesh-peer=http://localhost:3370 \
        --admin unix:${sp}meshe.sock > mesh_e.log 2>&1 &
    local epid=$!
    count=0
    while ! printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "noexit.local"; do
        count=$((count + 1))
        if [ $count -ge 20 ]; then
            echo "mesh gossip test 5 failed: no discovery of noexit node"
            break
        fi
        sleep 1
    done
    printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep "noexit.local \[" | grep -qv " exit"
    [ $? -ne 0 ] && echo "mesh gossip test 5 failed: exit cap should be off" && exit 1
    kill -SIGINT $epid; wait $epid

    #auto 出口：请求成功且 dump 记录被选中的出口
    curl -sf -m 10 -x client:pass@127.0.0.1:3370 http://localhost:3376/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh gossip test 6 failed: auto exit" && exit 1
    local picked=""
    picked=$(printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep "auto exit:" | awk '{print $3}')
    [ -z "$picked" ] && echo "mesh gossip test 6 failed: no auto exit in dump" && exit 1
    #杀掉被选中的出口，auto 应切换到另一个并继续应答
    local other=""
    if [ "$picked" = "ip6-localhost" ]; then
        kill -SIGINT $cpid; wait $cpid 2>/dev/null; other=$HOSTNAME
    else
        kill -SIGINT $bpid; wait $bpid 2>/dev/null; other=ip6-localhost
    fi
    count=0
    while ! curl -sf -m 5 -x client:pass@127.0.0.1:3370 http://localhost:3376/status -o mesh_out 2>/dev/null \
        || ! grep -q "Proxy server" mesh_out \
        || ! printf "dump mesh" | ./scli -s ${sp}mesha.sock | grep -q "auto exit: $other"; do
        count=$((count + 1))
        if [ $count -ge 60 ]; then
            echo "mesh gossip test 7 failed: auto exit switch"
            exit 1
        fi
        sleep 1
    done

    #剩余出口也失联（入口 A 保留）：auto 应显式报错而非挂起
    if [ "$other" = "ip6-localhost" ]; then
        kill -SIGINT $cpid; wait $cpid 2>/dev/null
    else
        kill -SIGINT $bpid; wait $bpid 2>/dev/null
    fi
    sleep 6
    curl -s -m 10 -x client:pass@127.0.0.1:3370 http://localhost:3376/status | grep -q "\[\[mesh: no exit\]\]"
    [ $? -ne 0 ] && echo "mesh gossip test 8 failed: expect no exit" && exit 1
    kill -SIGINT $apid $tpid
    wait $apid $tpid 2>/dev/null
}


#mesh Phase 3：逐跳中继。B(3371) 与 C(3373) 互联，凭据 identifier 直接指定 B 把出口定为 C，
#验证中继转发/未知目标 404。出口 direct，目标用主服务器(3333/3334)
function test_mesh_relay(){
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    rm -f mesh_out
    export SPROXY_MESH_PROBE_INTERVAL=1 SPROXY_MESH_GOSSIP_INTERVAL=2
    cat > meshr.conf << 'MRC'
root-dir .
policy-file /dev/null
debug all
MRC
    : > meshr_c.list
    ./sproxy -c meshr.conf --mesh=ip6-localhost --mesh-secret=mesh-pass \
        --bind 3373 -P meshr_c.list --mesh-peer=http://$HOSTNAME:3371 \
        --admin unix:${sp}meshrc.sock > mesh_rc.log 2>&1 &
    local cpid=$!
    ./sproxy -c meshr.conf --mesh=$HOSTNAME --mesh-secret=mesh-pass \
        --bind 3371 --mesh-peer=http://ip6-localhost:3373 \
        --admin unix:${sp}meshrb.sock > mesh_rb.log 2>&1 &
    local bpid=$!
    wait_tcp_port 3371
    wait_tcp_port 3373
    local MESHCRED="Basic $(echo -n mesh+ip6-localhost:mesh-pass | base64)"

    #等 B 对 C 的探测有样本（中继路由需要 B→C 边）
    local count=0
    while ! printf "dump mesh" | ./scli -s ${sp}meshrb.sock | grep -q "ip6-localhost.*probes=[1-9]"; do
        count=$((count + 1))
        if [ $count -ge 30 ]; then
            echo "mesh relay test 1 failed: no probe result"
            exit 1
        fi
        sleep 1
    done

    #B 中继：凭据 identifier 即出口声明，请求经 B 转发到出口 C，C 出口 direct 连主服务器
    curl -sf -m 10 -x 127.0.0.1:3371 -H "Proxy-Authorization: $MESHCRED" \
        http://$HOSTNAME:3333/status -o mesh_out \
        && grep -q "Proxy server" mesh_out
    [ $? -ne 0 ] && echo "mesh relay test 1 failed: relay forward" && exit 1
    sleep 1 && grep -q "mesh dispatch:" mesh_rb.log
    [ $? -ne 0 ] && echo "mesh relay test 2 failed: no dispatch log" && exit 1

    #CONNECT 隧道过中继（https 经 B 中继、C 出口 direct 连本测试的 https 服务）。
    #注1：curl 对 CONNECT 请求不发送 -H 头，必须用 --proxy-header，
    #否则请求以普通代理 CONNECT 直连目标、断言形同虚设（曾长期假通过）
    #注2：目标端口非 443，SNI 嗅探分支本身不进入（guest_sni 只对 :443 生效），
    #此处验证的是 CONNECT 语义在中继路径上的透传
    curl -s -m 10 -k -x 127.0.0.1:3371 --proxy-header "Proxy-Authorization: $MESHCRED" \
        https://$HOSTNAME:3334/sites.list -o mesh_out
    #非空、非 sproxy 错误页（错误页均带 [[...]] 标记）、且中继确实发生
    [ -s mesh_out ] && ! grep -q "\[\[" mesh_out \
        && sleep 1 && grep -aq "mesh dispatch: tcp://$HOSTNAME:3334" mesh_rb.log
    [ $? -ne 0 ] && echo "mesh relay test 3 failed: CONNECT tunnel via relay" && exit 1

    #identifier 是未知名字：落 rproxy/alias 后 404
    [ "$(curl -s -m 10 -x 127.0.0.1:3371 \
        -H "Proxy-Authorization: Basic $(echo -n mesh+nosuch.node:mesh-pass | base64)" \
        http://$HOSTNAME:3333/status -o /dev/null -w "%{http_code}")" = "404" ]
    [ $? -ne 0 ] && echo "mesh relay test 4 failed: unknown identifier expect 404" && exit 1

    kill -SIGINT $bpid $cpid
    wait $bpid $cpid 2>/dev/null
}


#mesh Phase 3：真实分区拓扑（用户命名空间 + veth，无需 root）。
#哑铃：A-B、B-D、C-D、A-E、E-D（D 为出口，A 有两条互异路径：经 B/C 或经 E）。
#验收：A 到 D 两跳中继成功；杀掉中继 B 后自动经 E 重路由
function test_mesh_dumbbell(){
    if ! unshare -Urn true 2>/dev/null; then
        echo "mesh dumbbell test skipped: user namespace unavailable"
        return 0
    fi
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    local D=$(pwd)/meshdumb
    rm -rf $D; mkdir -p $D
    export SPROXY_MESH_PROBE_INTERVAL=1 SPROXY_MESH_GOSSIP_INTERVAL=2
    cat > $D/common.conf << 'MDC'
policy-file /dev/null
debug all
MDC
    #普通目标 F（无 mesh）放在 D 的 netns：D 出口 direct 直连它应答，且只能经 D 到达
    : > $D/other.list
    printf "10.99.0.5 local\n" > $D/f.list
    echo "10.99.0.5:4431 proxy mesh://10.99.0.5" > $D/a.list

    #拓扑：环回口为各节点唯一身份（A=.0.1 B=.0.9 C=.0.3 D=.0.5 E=.1.9），
    #veth 仅作链路中继（10.1.x.y 点对点）：A-B、B-D、C-D、A-E、E-D。
    #A 到 D 有两条互异路径（经 B 或经 E），杀 B 后应经 E 重路由
    unshare -Urmn bash -c '
    SPROXY="$PWD/../build/src/sproxy"
    D="$PWD/meshdumb"
    unshare -n sleep 600 & PA=$!
    unshare -n sleep 600 & PB=$!
    unshare -n sleep 600 & PC=$!
    unshare -n sleep 600 & PE=$!
    unshare -n sleep 600 & PD=$!
    #退出时回收 netns 持有进程，避免 CI 并行下累积
    trap "kill $PA $PB $PC $PE $PD 2>/dev/null" EXIT
    sleep 0.5
    pair() { ip link add $1 type veth peer name $2; ip link set $1 netns $3; ip link set $2 netns $4; }
    pair l1a l1b $PA $PB   # A-B   10.1.1.1 / 10.1.1.2
    pair l2a l2b $PB $PD   # B-D   10.1.2.1 / 10.1.2.2
    pair l3a l3b $PC $PD   # C-D   10.1.3.1 / 10.1.3.2
    pair l4a l4b $PA $PE   # A-E   10.1.4.1 / 10.1.4.2
    pair l5a l5b $PE $PD   # E-D   10.1.5.1 / 10.1.5.2
    cfg() { nsenter -t $1 -n bash -c "$2"; }
    cfg $PA "ip l set lo up; ip a add 10.99.0.1/32 dev lo
        ip l set l1a up; ip a add 10.1.1.1/32 dev l1a; ip r add 10.1.1.2/32 dev l1a; ip r add 10.99.0.9/32 via 10.1.1.2
        ip l set l4a up; ip a add 10.1.4.1/32 dev l4a; ip r add 10.1.4.2/32 dev l4a; ip r add 10.99.1.9/32 via 10.1.4.2"
    cfg $PB "ip l set lo up; ip a add 10.99.0.9/32 dev lo
        ip l set l1b up; ip a add 10.1.1.2/32 dev l1b; ip r add 10.1.1.1/32 dev l1b; ip r add 10.99.0.1/32 via 10.1.1.1
        ip l set l2a up; ip a add 10.1.2.1/32 dev l2a; ip r add 10.1.2.2/32 dev l2a; ip r add 10.99.0.5/32 via 10.1.2.2"
    cfg $PC "ip l set lo up; ip a add 10.99.0.3/32 dev lo
        ip l set l3a up; ip a add 10.1.3.1/32 dev l3a; ip r add 10.1.3.2/32 dev l3a; ip r add 10.99.0.5/32 via 10.1.3.2"
    cfg $PE "ip l set lo up; ip a add 10.99.1.9/32 dev lo
        ip l set l4b up; ip a add 10.1.4.2/32 dev l4b; ip r add 10.1.4.1/32 dev l4b; ip r add 10.99.0.1/32 via 10.1.4.1
        ip l set l5a up; ip a add 10.1.5.1/32 dev l5a; ip r add 10.1.5.2/32 dev l5a; ip r add 10.99.0.5/32 via 10.1.5.2"
    cfg $PD "ip l set lo up; ip a add 10.99.0.5/32 dev lo
        ip l set l2b up; ip a add 10.1.2.2/32 dev l2b; ip r add 10.1.2.1/32 dev l2b; ip r add 10.99.0.9/32 via 10.1.2.1
        ip l set l3b up; ip a add 10.1.3.2/32 dev l3b; ip r add 10.1.3.1/32 dev l3b; ip r add 10.99.0.3/32 via 10.1.3.1
        ip l set l5b up; ip a add 10.1.5.2/32 dev l5b; ip r add 10.1.5.1/32 dev l5b; ip r add 10.99.1.9/32 via 10.1.5.1"

    run1() { nsenter -t $1 -n $SPROXY -c $D/common.conf --mesh=$2 --mesh-secret=mesh-pass \
        --bind 4430 -P $3 --mesh-peer=$4 --admin unix:$D/$5.sock > $D/$5.log 2>&1 & }
    run2() { nsenter -t $1 -n $SPROXY -c $D/common.conf --mesh=$2 --mesh-secret=mesh-pass \
        --bind 4430 -P $3 --mesh-peer=$4 --mesh-peer=$5 --admin unix:$D/$6.sock > $D/$6.log 2>&1 & }
    run2 $PD 10.99.0.5 $D/other.list http://10.99.0.9:4430 http://10.99.0.3:4430 d
    nsenter -t $PD -n $SPROXY -c $D/common.conf --bind 4431 -P $D/f.list \
        --admin unix:$D/f.sock > $D/f.log 2>&1 &
    run1 $PC 10.99.0.3 $D/other.list http://10.99.0.5:4430 c
    run1 $PB 10.99.0.9 $D/other.list http://10.99.0.1:4430 b
    BPROXY=$!
    run1 $PE 10.99.1.9 $D/other.list http://10.99.0.1:4430 e
    EPROXY=$!
    run2 $PA 10.99.0.1 $D/a.list    http://10.99.0.9:4430 http://10.99.1.9:4430 a

    #等 gossip 收敛：A 经 B 发现 D（A 对 D 无直连，探测必败，只看条目出现）
    #再留数个 gossip 周期让链路状态泛洪到达 A
    for i in $(seq 1 40); do
        if printf "dump mesh" | "$PWD/scli" -s $D/a.sock 2>/dev/null | grep -q "10.99.0.5 \["; then break; fi
        sleep 1
    done
    sleep 12
    nsenter -t $PA -n curl -sf -m 15 -x 10.99.0.1:4430 http://10.99.0.5:4431/status -o $D/out1
    [ $? -ne 0 ] && echo "MESHFAIL forward" && exit 1
    sleep 1
    #两跳中继：A 的下一跳必须是某个中继（B 或 E，两条对称路径谁便宜走谁），不能是直连 D
    VIA=$(grep -ao "exit=10.99.0.5 via=10.99.[01].9" $D/a.log | tail -1 | grep -o "10.99.[01].9$")
    [ -z "$VIA" ] && echo "MESHFAIL via-relay" && exit 1
    if [ "$VIA" = "10.99.0.9" ]; then
        KILLPID=$BPROXY; OTHER=10.99.1.9
        grep -aq "mesh dispatch.*exit=10.99.0.5" $D/b.log || { echo "MESHFAIL relay-log"; exit 1; }
    else
        KILLPID=$EPROXY; OTHER=10.99.0.9
        grep -aq "mesh dispatch.*exit=10.99.0.5" $D/e.log || { echo "MESHFAIL relay-log"; exit 1; }
    fi

    #杀掉首发中继（nsenter exec 后即 sproxy 本体，按 PID 精确杀）：A 应切到另一条路径
    kill -INT $KILLPID
    sleep 6
    for i in $(seq 1 30); do
        if nsenter -t $PA -n curl -sf -m 8 -x 10.99.0.1:4430 http://10.99.0.5:4431/status -o $D/out2 2>/dev/null; then
            #重路由后必须经另一条路径的中继
            if [ -s $D/out2 ] && grep -aq "exit=10.99.0.5 via=$OTHER" $D/a.log; then
                echo "MESHOK reroute" && exit 0
            fi
        fi
        sleep 1
    done
    echo "MESHFAIL reroute" && exit 1
    '
    local rc=$?
    grep -q "Proxy server" $D/out1 || { echo "mesh dumbbell test 1 failed: no relayed output"; rc=1; }
    if [ $rc -ne 0 ]; then
        echo "mesh dumbbell test failed"
        grep -aE "mesh dispatch|no route" $D/a.log 2>/dev/null | tail -5
    fi
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    return $rc
}



#mesh 专项：identifier 命中 mesh 目标的 SNI 嗅探跳过（真 443 端口）与逐跳 Via 追加。
#用户命名空间内可绑 443；python 起TLS 服务与记录请求头的 echo 上游
function test_mesh_443via(){
    if ! unshare -Urn true 2>/dev/null; then
        echo "mesh 443/via test skipped: user namespace unavailable"
        return 0
    fi
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    sleep 1
    local D=$(pwd)/mesh443
    rm -rf $D; mkdir -p $D
    cat > $D/echo.py << 'M4E'
import http.server
class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open("/tmp/mesh443_recv.txt", "a") as f:
            f.write(str(self.headers))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8398), Echo).serve_forever()
M4E
    export SPROXY_MESH_PROBE_INTERVAL=1 SPROXY_MESH_GOSSIP_INTERVAL=2
    cat > $D/conf << 'M4C'
policy-file /dev/null
debug all
M4C
    #出口 direct 不查本地策略，C 无需配置目标规则
    : > $D/exit.list

    printf "ok443\n" > $D/x
    printf "root-dir $D\npolicy-file $D/tls.list\n" > $D/tls.conf
    printf "127.0.0.1 local\n" > $D/tls.list
    unshare -Urmn bash -c '
    set -x
    SPROXY="$PWD/../build/src/sproxy"
    D="$PWD/mesh443"
    T="$PWD"
    #tls 实例无 mesh 参数，外层 pkill 匹配不到，退出时由本 trap 回收全部实例
    trap "kill \$(jobs -p) 2>/dev/null" EXIT
    ip l set lo up
    rm -f /tmp/mesh443_recv.txt
    (cd $T && python3 $D/echo.py) & EPID=$!
    sleep 0.5
    $SPROXY -c $D/tls.conf --bind "443 ssl" --cert $T/localhost.crt --key $T/localhost.key \
        --admin unix:$D/tls.sock > $D/tls.log 2>&1 &
    $SPROXY -c $D/conf --mesh=127.0.0.3 --mesh-secret=mesh-pass --bind 4431 \
        -P $D/exit.list --admin unix:$D/c.sock > $D/c.log 2>&1 &
    $SPROXY -c $D/conf --mesh=127.0.0.2 --mesh-secret=mesh-pass --bind 4432 \
        --secret=client:pass --mesh-peer=http://127.0.0.3:4431 \
        --admin unix:$D/b.sock > $D/b.log 2>&1 &
    sleep 5
    MESHCRED="Basic $(echo -n mesh+127.0.0.3:mesh-pass | base64)"

    #1: 真443 CONNECT 过中继（凭据门控放行 mesh 流量、跳过嗅探）。
    #目标用 IP：netns 内无 DNS，域名 direct 解析会失败
    curl -sf -m 10 -k -x 127.0.0.1:4432 --proxy-header "Proxy-Authorization: $MESHCRED" \
        https://127.0.0.1/x -o $D/out1
    R1=$?
    sleep 1
    #中继确实发生（若门控失效会落入嗅探分支、不可能有中继日志）
    grep -aq "mesh dispatch: tcp://127.0.0.1:443" $D/b.log
    R2=$?
    echo "T1 rc=$R1 relay=$R2"

    #2: 错误密钥的 mesh 凭据不得过境：嗅探豁免只看 identifier 命中 mesh（不校验密钥），
    #认证由 distribute 兜底——checksecret 失败应 407，请求失败
    curl -sf -m 10 -k -x 127.0.0.1:4432 \
        --proxy-header "Proxy-Authorization: Basic $(echo -n mesh+127.0.0.3:wrong-pass | base64)" \
        https://127.0.0.1/x -o $D/out2
    R3=$?
    echo "T2 rc=$R3"

    #3: 逐跳 Via：http 经 B 中继、C 出口 direct 连 echo 上游，上游应见两条 Via（B、C）
    curl -sf -m 10 -x 127.0.0.1:4432 --proxy-header "Proxy-Authorization: $MESHCRED" \
        http://127.0.0.1:8398/x -o $D/out3
    R5=$?
    sleep 1
    NVIA=$(grep -ao "HTTP/1.1 sproxy:" /tmp/mesh443_recv.txt 2>/dev/null | wc -l)
    echo "T3 rc=$R5 out=$(cat $D/out3 2>/dev/null) via=$NVIA"

    kill $EPID 2>/dev/null
    #内层不做 pkill：bash -c 的命令行包含脚本文本，pkill -f 会匹配到自身
    [ $R1 -eq 0 ] && [ $R2 -eq 0 ] && [ $R3 -ne 0 ] && [ $R5 -eq 0 ] && [ "$NVIA" = "2" ]
    '
    local rc=$?
    [ $rc -ne 0 ] && echo "mesh 443/via test failed" && \
        grep -ahE "T1 |T2 |T3 " $D/b.log 2>/dev/null | tail -3
    pkill -f "mesh-secret=mesh-pass" 2>/dev/null
    return $rc
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

echo "test mesh"
test_mesh

echo "test mesh gossip"
test_mesh_gossip

echo "test mesh relay"
test_mesh_relay

echo "test mesh dumbbell"
test_mesh_dumbbell || exit 1

echo "test mesh 443/via"
test_mesh_443via || exit 1

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
run_test $buildpath/mesh/gossip_test
run_test $buildpath/mesh/route_test
if [ $ker == 'Linux' ];then
    run_test $buildpath/hook/hook_test $buildpath/hook/hook_bpf.elf
fi
