if [ ! -x /bin/nc ]; then
	exit 77
fi

( echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:05:18 GMT
Content-Language: en-US
Content-Type: text/plain

yes
myprinc

" | /bin/nc -l 8081 1>/dev/null ) &
p=`../src/cascli cas1 http://localhost:8081 http://localhost 12345`
echo $p
[ "$p" = "myprinc" ]
