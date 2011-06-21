if [ ! -x /bin/nc ]; then
	exit 77
fi

( echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:04:33 GMT
Content-Language: en-US
Content-Type: text/plain

no
" | nc -l 8080  1>/dev/null ) &


./src/cascli cas1 http://localhost:8080 http://localhost 12345
if [ $? -eq 1 ]; then /bin/true; else /bin/false;fi
