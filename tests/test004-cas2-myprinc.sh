if [ ! -x /bin/nc ]; then
	exit 77
fi

( echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:05:18 GMT
Content-Language: en-US
Content-Type: text/plain

<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>myprinc</cas:user>
    </cas:authenticationSuccess>
</cas:serviceResponse>

" | /bin/nc -l 8081 1>/dev/null ) &
p=`../src/cascli -p cas2 http://localhost:8081 http://localhost 12345`
if [ "$p" = "myprinc" ]; then /bin/true; else /bin/false;fi
