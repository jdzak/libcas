if [ ! -x /bin/nc ]; then
	exit 77
fi

../src/cascli cas1 http://localhost:999 http://localhost 12345
if [ $? -eq 7 ]; then /bin/true; else /bin/false;fi
