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

" > "${tmpfile}?service=localhost&ticket=12345"

openssl req -new -keyout ${tmpfile}.key  -nodes -subj "/C=ZZ/ST=STATE/L=LOCALE/O=ORGANIZATION/CN=localhost" | openssl x509 -req -days 1 -signkey ${tmpfile}.key -out ${tmpfile}.crt
c_rehash $PWD
openssl s_server -accept 8443 -cert ${tmpfile}.crt -key ${tmpfile}.key -HTTP &
pid=$!
c="../src/cascli -p cas2  -c $PWD/${tmpfile}.crt https://localhost:8443/${tmpfile} localhost 12345"
echo $c
p=`$c`

kill $pid

rm 4fb486cd.0 ${tmpfile} "${tmpfile}?service=localhost&ticket=12345" ${tmpfile}.key ${tmpfile}.crt

if [ "$p" = "myprinc" ]; then /bin/true; else echo $p; /bin/false;fi

