if [ ! -x /bin/nc ]; then
	exit 77
fi

if [ ! -x /usr/bin/openssl ]; then
	exit 77
fi

tmpfile=`mktemp --tmpdir=.`
echo "HTTP/1.1 200 OK
Date: Sun, 05 Jun 2011 20:05:18 GMT
Content-Language: en-US
Content-Type: text/plain

<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>myprinc</cas:user>
    </cas:authenticationSuccess>
</cas:serviceResponse>

" > ${tmpfile}

openssl req -new -keyout ${tmpfile}.key  -nodes -subj "/C=ZZ/ST=STATE/L=LOCALE/O=ORGANIZATION/CN=localhost" | openssl x509 -req -days 1 -signkey ${tmpfile}.key -out ${tmpfile}.crt

openssl s_server -accept 8443 -cert ${tmpfile}.crt -key ${tmpfile}.key -HTTP &
pid=$!

p=`./src/cascli cas2 https://localhost:8443/${tmpfile} http://localhost 12345`

kill $! 1>/dev/null 2>/dev/null

rm ${tmpfile} ${tmpfile}.key ${tmpfile}.crt

if [ "$p" = "myprinc" ]; then /bin/true; else /bin/false;fi

