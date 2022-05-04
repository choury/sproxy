#!/bin/bash
set -x

HOSTNAME=localhost.choury.com

function test_client(){
    curl -f -s http://localhost:$1/cgi/libsites.do -d 'method=put&site=*&strategy=proxy'
    [ $? -ne 0 ] && echo "prepare for failed" && exit 1

    curl -f -s -x http://$HOSTNAME:$1 http://qq.com > /dev/null
    [ $? -ne 0 ] && echo "client test 1 failed" && exit 1
    curl -f -s -x http://$HOSTNAME:$1 http://taobao.com > /dev/null
    [ $? -ne 0 ] && echo "client test 2 failed" && exit 1
    curl -f -s -x http://$HOSTNAME:$1 https://www.qq.com > /dev/null
    [ $? -ne 0 ] && echo "client test 3 failed" && exit 1

    curl -f -s -x http://$HOSTNAME:$1 http://qq.com -XPOST -d "foo=bar" > /dev/null
    [ $? -ne 0 ] && echo "client test 4 failed" && exit 1

    curl -f -s -x http://$HOSTNAME:$1 http://taobao.com -I > /dev/null
    [ $? -ne 0 ] && echo "client test 5 failed" && exit 1
    curl -f -s -x http://$HOSTNAME:$1 http://taobao.com -L > /dev/null
    [ $? -ne 0 ] && echo "client test 6 failed" && exit 1

#test for 100 continue
    curl -f -s -x http://$HOSTNAME:$1 http://echo.opera.com -F 'name=@test1k' > /dev/null
    [ $? -ne 0 ] && echo "client test 7 failed" && exit 1
#test for http1.0
    ./sproxy_test < http1.0_server.exp &
    sleep 3
    curl -f -s -x http://$HOSTNAME:$1 http://test.localhost.choury.com:4444 > /dev/null
    [ $? -ne 0 ] && echo "client test 8 failed" && exit 1
#test for shutdown
    ./sproxy_test < shutdown1_server.exp &
    sleep 3
    cat shutdown1_client.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "client test 9 failed" && exit 1


    ./sproxy_test < shutdown2_server.exp &
    sleep 3
    cat shutdown2_client.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "client test 10 failed" && exit 1
#test for send and ping
    ./sproxy_test < udp_server.exp &
    sleep 3
    cat send_ping.exp | sed "s/PORT/$1/" | ./sproxy_test
    [ $? -ne 0 ] && echo "send ping test failed" && exit 1

#test pipeline
    curl -f -s  http://localhost:$1/cgi/libsites.do -XDELETE  -d 'site=*'
    [ $? -ne 0 ] && echo "delete site failed" && exit 1
    curl -f -s  http://localhost:$1/cgi/libsites.do -XPUT  -d 'site=360.cn&strategy=block'
    [ $? -ne 0 ] && echo "add block site failed" && exit 1
    curl -f -s  http://localhost:$1/cgi/libsites.do -XPUT  -d 'site=qq.com&strategy=proxy'
    [ $? -ne 0 ] && echo "add proxy site failed" && exit 1
    cat pipeline.exp | sed "s/PORT/$1/" | ./sproxy_test > pipeline-$1.log
    [ $? -ne 0 ] && echo "pipeline test failed" && exit 1
}

function test_https(){
    curl -f -s --http1.1 https://$HOSTNAME:$1/sites.list  -k
    [ $? -ne 0 ] && echo "https test 1 failed" && exit 1
    curl -f -s --http2 https://$HOSTNAME:$1/sites.list  -k
    [ $? -ne 0 ] && echo "https test 2 failed" && exit 1
    curl -f -s --http1.1 https://$HOSTNAME:$1/noexist  -k
    [ $? -ne 22 ] && echo "https test 3 failed" && exit 1
    curl -f -s --http2 https://$HOSTNAME:$1/noexist  -k
    [ $? -ne 22 ] && echo "https test 4 failed" && exit 1
    curl -f -s --http1.1 https://$HOSTNAME:$1/noexist.do  -k
    [ $? -ne 22 ] && echo "https test 5 failed" && exit 1
    curl -f -s --http2 https://$HOSTNAME:$1/noexist.do  -k
    [ $? -ne 22 ] && echo "https test 6 failed" && exit 1
    curl -f -s --http1.1 https://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k
    [ $? -ne 0 ] && echo "https test 7 failed"
    curl -f -s --http2 https://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k
    [ $? -ne 0 ] && echo "https test 8 failed"
    curl -f -s -L --http1.1 https://$HOSTNAME:$1/cgi  -k
    [ $? -ne 0 ] && echo "https test 9 failed"
    curl -f -s -L --http2 https://$HOSTNAME:$1/cgi  -k
    [ $? -ne 0 ] && echo "https test 10 failed"
    curl -f -s --http1.1 https://$HOSTNAME:$1/ -H "Host: www.qq.com" -k > /dev/null
    [ $? -ne 0 ] && echo "https test 11 failed" && exit 1
    curl -f -s --http2 https://$HOSTNAME:$1/ -H "Host: www.qq.com:443" -k > /dev/null
    [ $? -ne 0 ] && echo "https test 12 failed" && exit 1
    echo ""
}

function test_http(){
    curl -f -s http://$HOSTNAME:$1/sites.list  -k
    [ $? -ne 0 ] && echo "https test 1 failed" && exit 1
    curl -f -s http://$HOSTNAME:$1/noexist  -k
    [ $? -ne 22 ] && echo "https test 2 failed" && exit 1
    curl -f -s http://$HOSTNAME:$1/noexist.do  -k
    [ $? -ne 22 ] && echo "https test 3 failed" && exit 1
    curl -f -s http://$HOSTNAME:$1/cgi/libproxy.do?a=b  -k
    [ $? -ne 0 ] && echo "https test 4 failed"
    curl -f -s -L http://$HOSTNAME:$1/cgi  -k
    [ $? -ne 0 ] && echo "https test 5 failed"
    curl -f -s http://$HOSTNAME:$1/ -H "Host: www.qq.com" -k > /dev/null
    [ $? -ne 0 ] && echo "https test 6 failed" && exit 1
    echo ""
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

buildpath=`realpath "$1/src"`

ln -f -s "$buildpath/sproxy" .
ln -f -s "$buildpath/scli" .
ln -s -f "$1/test/sproxy_test" .
mkdir -p cgi
ln -f -s "$buildpath"/cgi/libproxy.* cgi/
ln -f -s "$buildpath"/cgi/libsites.* cgi/
dd if=/dev/zero of=test1k bs=1024 count=1

echo "$HOSTNAME local" > sites.list
cat > https.conf << EOF
port 4443
cafile ca.crt
cert localhost.crt
key localhost.key 
root-dir .
policy-file sites.list
index libproxy.do
insecure
debug-all
EOF

./sproxy -c https.conf --socket server_ssl.sock  >server_ssl.log 2>&1  &
./sproxy -c https.conf --socket server_quic.sock  --quic >server_quic.log  2>&1 &

cat > http.conf << EOF
port 4444
root-dir .
policy-file sites.list
index libproxy.do
insecure
debug-all
EOF

./sproxy -c http.conf  --socket server_http.sock > server_http.log 2>&1 &
sleep 5

echo "test server"
test_https 4443
kill -SIGUSR1 %1
test_http 4444
kill -SIGUSR1 %3


cat > client.conf << EOF
root-dir .
policy-file /dev/null
insecure
debug-all
EOF

./sproxy -c client.conf -p 3334  https://$HOSTNAME:4443 --disable-http2 --socket client_h1.sock > client_h1.log 2>&1 &
./sproxy -c client.conf -p 3335  https://$HOSTNAME:4443 --socket client_h2.sock > client_h2.log 2>&1 &
./sproxy -c client.conf -p 3336  quic://$HOSTNAME:4443 --socket client_h3.sock > client_h3.log 2>&1 &
sleep 5

function cleanup {
    kill %1
    kill %2
    kill %3
    kill %4
    kill %5
    kill %6
}

trap cleanup EXIT

echo "test client ssl http2 proxy"
test_client 3334
test_client 3335
test_client 3336
sleep 5

kill -SIGUSR1 %1
kill -SIGUSR1 %2
kill -SIGUSR1 %3
kill -SIGUSR1 %4
kill -SIGUSR1 %5
kill -SIGUSR1 %6

printf "sites" | ./scli -s client_h1.sock
printf "sites" | ./scli -s client_h2.sock
printf "sites" | ./scli -s client_h3.sock
sleep 30

