/*
 * mylogin_after_7.c — Preparatory Assignment 7 (FINAL VERSION)
 *
 * Builds on mylogin_after_6.c (study of fork/setuid) by adding:
 *   - After successful authentication, fork a child process that:
 *       1. Sets the group ID to the user's pw_gid (setgid).
 *       2. Sets the user ID to the user's pw_uid (setuid).
 *       3. Starts the user's preferred shell (pw_shell) via execl.
 *   - The parent process waits for the child (shell) to exit, then
 *     shows the "login:" prompt again for the next user.
 *   - The program no longer exits after successful login — it loops forever,
 *     acting like a real /bin/login.
 *
 * Changes from after_6:
 *   - Added sys/types.h and sys/wait.h includes for pid_t, fork(), wait().
 *   - New function: start_user_shell() — forks and execs the user's shell.
 *   - handle_successful_login() now calls start_user_shell() instead of returning.
 *   - main() no longer exits after successful login (removed 'return 0').
 *
 * Compile: gcc -o mylogin mylogin_after_7.c pwdblib.c -lcrypt
 */

#define _XOPEN_SOURCE /* Required for crypt() to be declared in <unistd.h>/<crypt.h> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    /* getpass(), fork(), setuid(), setgid(), execl(), _exit() */
#include <crypt.h>     /* crypt()   — one-way hash function for password verification */
#include <signal.h>    /* signal()  — for registering signal handlers */
#include <sys/types.h> /* pid_t     — data type for process IDs (NEW in prep 7) */
#include <sys/wait.h>  /* wait()    — for parent to wait on child process (NEW in prep 7) */
#include "pwdblib.h"   /* pwdb_getpwnam(), pwdb_update_user(), struct pwdb_passwd, etc. */

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

    /* Strip the trailing newline character from the input. */
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
 *
 * How it works:
 *   1. Extract the 2-char salt from the start of stored_hash.
 *   2. crypt(password, salt) hashes the input with the same salt.
 *   3. strcmp compares the result with stored_hash (0 = identical).
 */
int verify_password(const char *password, const char *stored_hash)
{
    /* Salt buffer: 2 characters + 1 null terminator = 3 bytes. */
    char salt[3];
    strncpy(salt, stored_hash, 2);
    salt[2] = '\0';

    /* crypt() returns a pointer to a static internal buffer containing the hash.
     * WARNING: this buffer is overwritten on every call to crypt(). */
    char *hashed_input = crypt(password, salt);

    /* strcmp returns 0 when strings are identical → convert to boolean. */
    return (strcmp(hashed_input, stored_hash) == 0);
}

/*
 * is_account_locked — Checks whether the account has been locked due to too many
 *                     consecutive failed login attempts.
 *
 * Parameters:
 *   p — pointer to the user's pwdb_passwd struct.
 *       'const' means this function promises not to modify the struct.
 *
 * Returns:
 *   1 if locked, 0 if not.
 */
int is_account_locked(const struct pwdb_passwd *p)
{
    return (p->pw_failed > MAX_FAILED_ATTEMPTS);
}

/*
 * handle_failed_login — Increments pw_failed and persists to pwfile.
 *
 * Parameters:
 *   p — pointer to user struct, or NULL if user doesn't exist.
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
 * start_user_shell — Forks a child process to run the user's preferred shell.
 *                    (NEW in prep 7)
 *
 * How fork() works:
 *   fork() duplicates the current process. After the call, there are TWO
 *   processes running the same code. They are distinguished by the return value:
 *     - In the CHILD:  fork() returns 0.
 *     - In the PARENT: fork() returns the child's PID (positive integer).
 *     - On error:      fork() returns -1 (no child was created).
 *
 * In the child process:
 *   1. setgid(gid) — change the group ID to the user's group.
 *      MUST be called before setuid(), because once we drop root privileges
 *      via setuid(), we can no longer change the group ID.
 *   2. setuid(uid) — change the user ID to the authenticated user.
 *      After this, the child process runs with the user's permissions.
 *   3. execl(shell, shell, NULL) — replace this process with the user's shell.
 *      execl() never returns on success; the child process BECOMES the shell.
 *      The first argument is the path to the program, the second is argv[0]
 *      (conventionally the program name), and NULL terminates the argument list.
 *   4. If execl() fails, _exit(-1) terminates the child.
 *      We use _exit() instead of exit() in the child to avoid flushing stdio
 *      buffers that the parent process also holds (would cause double output).
 *
 * In the parent process:
 *   wait(NULL) blocks until the child process exits. NULL means we don't care
 *   about the child's exit status. After the child (shell) exits, control
 *   returns here, and then back to the main login loop.
 *
 * Parameters:
 *   p — pointer to the authenticated user's struct (contains uid, gid, shell).
 */
void start_user_shell(const struct pwdb_passwd *p)
{
    /* pid_t is a signed integer type used for process IDs.
     * fork() returns this type. */
    pid_t pid = fork();

    if (pid < 0)
    {
        /* fork() failed — could not create child process (e.g. out of memory). */
        perror("fork failed"); /* perror prints the error message for the last errno. */
    }
    else if (pid == 0)
    {
        /* === CHILD PROCESS === */

        /* Step 1: Set group ID FIRST (before dropping root with setuid).
         * p->pw_gid is the group ID stored in the pwfile for this user. */
        if (setgid(p->pw_gid) != 0)
        {
            perror("setgid failed");
            _exit(1);
        }

        /* Step 2: Set user ID — after this, we run as the authenticated user. */
        if (setuid(p->pw_uid) != 0)
        {
            perror("setuid failed");
            _exit(1);
        }

        /* Step 3: Replace this process with the user's preferred shell.
         * p->pw_shell is a string like "/bin/sh" or "/bin/bash".
         * execl(path, arg0, arg1, ..., NULL):
         *   - path: the executable to run.
         *   - arg0: conventionally the program name (same as path here).
         *   - NULL: marks the end of the argument list. */
        execl(p->pw_shell, p->pw_shell, NULL);

        /* If we reach here, execl() failed (e.g. shell path doesn't exist). */
        perror("execl failed");
        _exit(1); /* Use _exit, NOT exit — see comment in function header. */
    }
    else
    {
        /* === PARENT PROCESS === */

        /* Wait for the child process (the shell) to finish.
         * This blocks until the user exits their shell (e.g. types 'exit').
         * After this, control returns to the main login loop. */
        wait(NULL);
    }
}

/*
 * handle_successful_login — Resets pw_failed, increments pw_age, persists to pwfile,
 *                           warns about old password, and starts the user's shell.
 *
 * Parameters:
 *   p — pointer to the authenticated user's struct.
 */
void handle_successful_login(struct pwdb_passwd *p)
{
    p->pw_failed = 0;
    p->pw_age++;

    /* Persist the changes to the pwfile. */
    if (pwdb_update_user(p) != 0)
    {
        printf("Error updating user database.\n");
    }

    /* Warn user if their password is old (many successful logins without changing it). */
    if (p->pw_age > PASSWORD_AGE_LIMIT)
    {
        printf("Warning: Your password is old (%d logins). Please change it!\n", p->pw_age);
    }

    printf("User authenticated successfully. Starting shell...\n");

    /* Fork and start the user's shell. The parent waits for the shell to exit,
     * then returns here, and the main loop shows the "login:" prompt again. */
    start_user_shell(p);
}

int main(int argc, char **argv)
{
    /* Ignore SIGINT (Ctrl-C) so the login program cannot be interrupted. */
    signal(SIGINT, SIG_IGN);

    char username[USERNAME_SIZE];

    /*
     * Main login loop — runs forever, like a real /bin/login.
     * After a user logs in and their shell exits, the loop shows "login:" again.
     * (In after_3 through after_6, the program exited after a successful login.
     *  Now in after_7, it keeps running to serve the next login.)
     */
    while (1)
    {
        read_username(username);

        /* If username is empty (e.g. from Ctrl-C interrupting fgets), skip. */
        if (strlen(username) == 0)
        {
            continue;
        }

        /* Look up the user in the local pwfile.
         * Returns a pointer to a malloc'd struct, or NULL if not found. */
        struct pwdb_passwd *p = pwdb_getpwnam(username);

        /* Read password without echo. Always ask even if user doesn't exist
         * to prevent timing-based username enumeration. */
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
            /* Successful login: update counters and start shell.
             * After the shell exits, this call returns and the loop continues. */
            handle_successful_login(p);
            /* No 'return 0' here — loop back to show "login:" again. */
        }
        else
        {
            handle_failed_login(p);
        }
    }

    return 0;
}
