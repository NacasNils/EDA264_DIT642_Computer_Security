/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */ // TODO I HAD TO SWITCH TO FGETS FOR IT TO COMPILE
			exit(0); /*  overflow attacks.  */

		/* Remove newline character if present */
		user[strcspn(user, "\n")] = 0;

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user); // THIS CALLS FUNCTION IN pwent.c WHICH READS FROM FILE AND RETURNS POINTER TO A STRUCT WITH USER DATA

		if (passwddata != NULL) {
			// printf("Debug: User found: %s\n", passwddata->pwname);
			// printf("Debug: Stored password: %s\n", passwddata->passwd);
			// printf("Debug: Stored salt: %s\n", passwddata->passwd_salt);
			/* You have to encrypt user_pass for this to work */
			char *encrypted_pass = crypt(user_pass, passwddata->passwd_salt);
			printf("Debug: Encrypted password: %s\n", encrypted_pass);
			printf("Debug: Stored password: %s\n", passwddata->passwd);
			/* Don't forget to include the salt */

			if (!strcmp(encrypted_pass, passwddata->passwd)) {
				printf("Number of login attempts: %d\n", passwddata->pwfailed);
				passwddata->pwfailed = 0;
				passwddata->pwage++;
				if(passwddata->pwage > 3) {
					printf("Password has expired, please change it!\n");
					char *new_user_pass = getpass("New password: ");
					char *cryptedNewPass = crypt(new_user_pass, passwddata->passwd_salt);
					strcpy(passwddata->passwd, cryptedNewPass);
					printf("Password changed to: %s\n", passwddata->passwd);
					passwddata->pwage = 0;
					mysetpwent(user, passwddata);
					continue;
				}
				mysetpwent(user, passwddata);
				printf(" You're in !\n");

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			} else {
				passwddata->pwfailed++;
				mysetpwent(user, passwddata);
				printf("Password Incorrect \n");
			}
		}
		printf("Looping \n");
	}
	return 0;
}
