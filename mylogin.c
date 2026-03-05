/*
 * mylogin.c — Simple login program (final version)
 * Compile: gcc -o mylogin mylogin.c pwdblib.c -lcrypt
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "pwdblib.h"

#define USERNAME_SIZE (32)
#define MAX_FAILED_ATTEMPTS (3)
#define PASSWORD_AGE_LIMIT (5)

void read_username(char *username)
{
    printf("login: ");
    if (fgets(username, USERNAME_SIZE, stdin) == NULL)
    {
        clearerr(stdin); // Clear errors
        username[0] = '\0';
        printf("\n");
        return;
    }
    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n')
    {
        username[len - 1] = '\0'; // strip newline
    }
}

int verify_password(const char *password, const char *stored_hash)
{
    char salt[3];                  // 2 chars for salt + null terminator
    strncpy(salt, stored_hash, 2); // Extract the 2-character salt
    salt[2] = '\0';
    char *hashed_input = crypt(password, salt); // Hash the input password with the extracted salt
    return (strcmp(hashed_input, stored_hash) == 0);
}

int is_account_locked(const struct pwdb_passwd *p)
{
    return (p->pw_failed > MAX_FAILED_ATTEMPTS);
}

void handle_failed_login(struct pwdb_passwd *p)
{
    if (p != NULL)
    {
        p->pw_failed++;
        if (pwdb_update_user(p) != 0)
        {
            printf("Error updating user database.\n");
        }
    }
    printf("Unknown user or incorrect password.\n");
}

void start_user_shell(const struct pwdb_passwd *p)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork failed");
    }
    else if (pid == 0)
    {
        if (setgid(p->pw_gid) != 0) // set group ID of the calling process
        {
            perror("setgid failed");
            _exit(1);
        }
        if (setuid(p->pw_uid) != 0) // set user ID of the calling process
        {
            perror("setuid failed");
            _exit(1);
        }
        execl(p->pw_shell, p->pw_shell, NULL);
        perror("execl failed");
        _exit(1);
    }
    else
    {
        wait(NULL);
    }
}

void handle_successful_login(struct pwdb_passwd *p)
{
    p->pw_failed = 0;
    p->pw_age++;

    if (pwdb_update_user(p) != 0)
    {
        printf("Error updating user database.\n");
    }

    if (p->pw_age > PASSWORD_AGE_LIMIT)
    {
        printf("Warning: Your password is old (%d logins). Please change it!\n", p->pw_age);
    }

    printf("User authenticated successfully. Starting shell...\n");
    start_user_shell(p);
}

int main(int argc, char **argv)
{
    signal(SIGINT, SIG_IGN);
    char username[USERNAME_SIZE];

    while (1)
    {
        read_username(username);

        if (strlen(username) == 0)
        {
            continue;
        }

        struct pwdb_passwd *p = pwdb_getpwnam(username);
        char *password = getpass("Password: ");

        if (p == NULL)
        {
            handle_failed_login(NULL);
            continue;
        }

        if (is_account_locked(p))
        {
            printf("Account is locked due to too many failed attempts.\n");
            continue;
        }

        if (verify_password(password, p->pw_passwd))
        {
            handle_successful_login(p);
        }
        else
        {
            handle_failed_login(p);
        }
    }

    return 0;
}
