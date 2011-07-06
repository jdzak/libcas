
if [ ! -x /bin/nc ]; then
	exit 77
fi
echo "----------------------------------------"
( echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:05:18 GMT
Content-Language: en-US
Content-Type: text/plain

GARBAGE

" | nc -l 8082  1>/dev/null ) &

../src/cascli cas2 http://localhost:8082 http://localhost 12345
if [ $? -eq 8 ]; then /bin/true; else /bin/false;fi
