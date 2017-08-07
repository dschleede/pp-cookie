all:	rc4.c base64.c rc4.h base64.h encode.c
	gcc -c -o base64.o base64.c
	gcc -c -o rc4.o rc4.c
	gcc -c -o sha256.o sha256.c
	gcc -o encode encode.c base64.o rc4.o sha256.o

clean:
	rm *.o test

