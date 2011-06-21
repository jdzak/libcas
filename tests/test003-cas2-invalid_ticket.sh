if [ ! -x /bin/nc ]; then
	exit 77
fi

( echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:04:33 GMT
Content-Language: en-US
Content-Type: text/plain

<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationFailure code='INVALID_TICKET'>
        Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized
    </cas:authenticationFailure>
</cas:serviceResponse>

" | nc -l 8080  1>/dev/null ) &


./src/cascli cas2 http://localhost:8080 http://localhost 12345
if [ $? -eq 3 ]; then /bin/true; else /bin/false;fi
