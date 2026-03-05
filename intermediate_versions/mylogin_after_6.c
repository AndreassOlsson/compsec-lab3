/*
 * mylogin_after_6.c — Preparatory Assignment 6
 *
 * Builds on mylogin_after_5.c (Ctrl-C protection).
 *
 * Prep 6 is a STUDY assignment — no new login features are added.
 * The task is to understand fork(), setuid/setgid, and how openshell_demo.c works.
 * This file is identical to after_5 in functionality, but includes detailed
 * study notes (as comments) about the concepts needed for prep 7.
 *
 * === STUDY NOTES: fork() ===
 *
 * fork() creates a new process by duplicating the calling process.
 * After fork(), there are TWO processes running the same code:
 *   - The PARENT process: fork() returns the child's PID (a positive number).
 *   - The CHILD process:  fork() returns 0.
 *   - On error:           fork() returns -1 (no child was created).
 *
 * Both processes continue executing from the line AFTER fork().
 * The typical pattern is:
 *
 *   pid_t pid = fork();
 *   if (pid == 0) {
 *       // Child process code
 *   } else if (pid > 0) {
 *       // Parent process code
 *       waitpid(pid, &status, 0);  // Wait for child to finish
 *   } else {
 *       // fork() failed
 *   }
 *
 * === STUDY NOTES: setuid / setgid family ===
 *
 * In Unix, every process has several IDs:
 *   - Real UID/GID:      The actual user/group who started the process.
 *   - Effective UID/GID:  The user/group used for permission checks.
 *                          Normally same as real, but differs for setuid programs.
 *
 * Functions:
 *   getuid()  / getgid()   — returns the real UID / GID.
 *   geteuid() / getegid()  — returns the effective UID / GID.
 *   setuid(uid)             — sets real, effective, and saved UID (if permitted).
 *   seteuid(uid)            — sets only the effective UID.
 *   setgid(gid) / setegid(gid) — same as above but for group ID.
 *
 * IMPORTANT: In the child process after fork(), we must call setgid() BEFORE
 * setuid(). Why? Because once we drop root privileges via setuid(), we can no
 * longer change the group ID. Order matters!
 *
 * === STUDY NOTES: execl() ===
 *
 * execl() replaces the current process image with a new program.
 * After a successful execl(), the old code is gone — it never returns.
 * If execl() fails, it returns -1 and the old code continues.
 *
 * In the child after fork(), we use execl() to start the user's shell.
 * The child process BECOMES the shell — it's not running alongside it.
 *
 * === STUDY NOTES: _exit() vs exit() ===
 *
 * In a child process after fork(), always use _exit() instead of exit().
 * exit() flushes stdio buffers and runs atexit handlers, which could cause
 * double-flushing of data that the parent also has buffered. _exit() does
 * a raw process termination without these side effects.
 *
 * Compile: gcc -o mylogin mylogin_after_6.c pwdblib.c -lcrypt
 */

#define _XOPEN_SOURCE /* Required for crypt() to be declared in <unistd.h>/<crypt.h> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getpass(), fork(), setuid(), setgid(), execl(), _exit() */
#include <crypt.h>   /* crypt()   — one-way hash function for password verification */
#include <signal.h>  /* signal()  — for registering signal handlers */
#include "pwdblib.h" /* pwdb_getpwnam(), pwdb_update_user(), struct pwdb_passwd, etc. */

/* Maximum length of a username (including the null terminator '\0'). */
#define USERNAME_SIZE (32)

/* After this many consecutive failed attempts, the account is locked. */
#define MAX_FAILED_ATTEMPTS (3)

/* After this many successful logins, the user is warned to change their password. */
#define PASSWORD_AGE_LIMIT (5)

/*
 * read_username — Prompts "login: " and reads the username from stdin.
 *
 * Parameters:
 *   username — a pointer to a char array (buffer) of at least USERNAME_SIZE bytes.
 *              The function writes the entered username into this buffer.
 *              In C, arrays decay to pointers when passed to functions,
 *              so the caller's buffer is modified directly.
 */
void read_username(char *username)
{
    printf("login: ");

    /* fgets reads at most USERNAME_SIZE-1 chars and always null-terminates.
     * It also includes the newline '\n' if there's room, so we strip it below. */
    if (fgets(username, USERNAME_SIZE, stdin) == NULL)
    {
        /* fgets returns NULL on error or EOF. clearerr resets the error/EOF
         * flags on stdin so subsequent reads will work again. */
        clearerr(stdin);
        username[0] = '\0'; /* Set to empty string so main loop skips this attempt. */
        printf("\n");
        return;
    }

    /* strlen() returns the number of characters before the '\0' terminator.
     * The last character is the '\n' from pressing Enter — overwrite it with '\0'. */
    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n')
    {
        username[len - 1] = '\0';
    }
}

/*
 * verify_password — Checks if the given plaintext password matches the stored hash.
 *
 * Parameters:
 *   password    — pointer to the plaintext password string (from getpass).
 *   stored_hash — pointer to the stored hash string from the pwfile
 *                 (format: 2-char salt + hashed password, e.g. "0BWGsAnLYCtBU").
 *
 * Returns:
 *   1 if the password matches, 0 otherwise.
 */
int verify_password(const char *password, const char *stored_hash)
{
    /* Salt buffer: 2 characters + 1 null terminator = 3 bytes. */
    char salt[3];
    strncpy(salt, stored_hash, 2);
    salt[2] = '\0';

    /* crypt() returns a pointer to a static internal buffer containing the hash. */
    char *hashed_input = crypt(password, salt);

    /* strcmp returns 0 when strings are identical → convert to boolean. */
    return (strcmp(hashed_input, stored_hash) == 0);
}

/*
 * is_account_locked — Checks whether the account has been locked.
 */
int is_account_locked(const struct pwdb_passwd *p)
{
    return (p->pw_failed > MAX_FAILED_ATTEMPTS);
}

/*
 * handle_failed_login — Increments pw_failed and persists to pwfile.
 */
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

/*
 * handle_successful_login — Resets pw_failed, increments pw_age, persists to pwfile.
 */
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

    printf("User authenticated successfully.\n");
}

int main(int argc, char **argv)
{
    /* Ignore SIGINT (Ctrl-C) so the login program cannot be interrupted. */
    signal(SIGINT, SIG_IGN);

    char username[USERNAME_SIZE];

    /* Main login loop: keeps prompting until a successful login. */
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
            return 0;
        }
        else
        {
            handle_failed_login(p);
        }
    }

    return 0;
}
