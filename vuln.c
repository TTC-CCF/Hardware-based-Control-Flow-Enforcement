#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int task() {
	char buf[32];

	printf("===========================================\n");
	printf("Welcome to the UNIX Hotel Messaging Service\n");
	printf("===========================================\n");

	printf("\nWhat's your name? ");
	read(0, buf, 256);
	printf("Welcome, %s", buf);

	printf("\nWhat's the room number? ");
	read(0, buf, 256);
	printf("The room number is: %s", buf);

	printf("\nWhat's the customer's name? ");
	read(0, buf, 256);
	printf("The customer's name is: %s", buf);

	printf("\nLeave your message: ");
	read(0, buf, sizeof(buf));
}

int main() {
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin,  NULL, _IONBF, 0);
	task();
	return 0;
}
