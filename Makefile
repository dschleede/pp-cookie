all:	rc4.c base64.c rc4.h base64.h test.c
	gcc -c -o base64.o base64.c
	gcc -c -o rc4.o rc4.c
	gcc -o test test.c base64.o rc4.o

clean:
	rm *.o test

