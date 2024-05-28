all:
	gcc -m32 -fstack-protector -o vuln vuln.c
	gcc -m32 -mshstk -fcf-protection -fstack-protector -o vuln-cet vuln.c
