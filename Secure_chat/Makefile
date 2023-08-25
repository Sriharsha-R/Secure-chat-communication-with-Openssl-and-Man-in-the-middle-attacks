all:
	scp Makefile ns@192.168.51.123:
	scp -r alice/ ns@192.168.51.123:
	scp -r bob/ ns@192.168.51.123:
	scp -r Root/ ns@192.168.51.123:
	scp -r trudy/ ns@192.168.51.123:
	scp secure_chat_app.py ns@192.168.51.123:
	scp secure_chat_interceptor.py ns@192.168.51.123:

ns13:
	lxc file push -r alice/ alice1/../
	lxc file push -r bob/ bob1/../
	lxc file push -r trudy/ trudy1/../
	lxc file push Root/ca_cert.pem alice1/../alice/
	lxc file push Root/ca_cert.pem bob1/../bob/
	lxc file push Root/ca_cert.pem trudy1/../trudy/
	lxc file push secure_chat_app.py alice1/../alice/
	lxc file push secure_chat_app.py bob1/../bob/
	lxc file push secure_chat_interceptor.py trudy1/../trudy/
	lxc file push Makefile alice1/../
	lxc file push Makefile bob1/../
	lxc file push Makefile trudy1/../

ns13clear:
	rm -r alice/
	rm -r bob/
	rm -r trudy/
	rm -r Root/
	rm secure_chat_app.py
	rm secure_chat_interceptor.py
	rm Makefile 

aliceclear:
	rm -r alice/

bobclear:
	rm -r bob/

trudyclear:
	rm -r trudy/