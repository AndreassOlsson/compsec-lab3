/*
 * mylogin_after_3.c — Preparatory Assignment 3
 *
 * A simple login program that mimics the system login procedure.
 * Based on userinfo.c, rewritten to:
 *   1. Prompt for a username.
 *   2. Read the password WITHOUT echoing it to the screen (using getpass).
 *   3. Look up the user in the local pwfile via pwdb_getpwnam.
 *   4. Verify the password using crypt() with the stored salt.
 *   5. On success: print "User authenticated successfully" and exit.
 *   6. On failure: print "Unknown user or incorrect password." and re-prompt.
 *
 * Compile: gcc -o mylogin mylogin_after_3.c pwdblib.c -lcrypt
 */

#define _XOPEN_SOURCE /* Required for crypt() to be declared in <unistd.h>/<crypt.h> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getpass() — reads password without echoing to terminal */
#include <crypt.h>   /* crypt()   — one-way hash function for password verification */
#include "pwdblib.h" /* pwdb_getpwnam(), struct pwdb_passwd, pwdb_errno, etc. */

/* Maximum length of a username (including the null terminator '\0'). */
#define USERNAME_SIZE (32)

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
    fgets(username, USERNAME_SIZE, stdin);

    /* strlen() returns the number of characters before the '\0' terminator.
     * The last character is the '\n' from pressing Enter — overwrite it with '\0'. */
    username[strlen(username) - 1] = '\0';
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
 *   1. The first 2 characters of stored_hash are the "salt" — a value that was
 *      used when the password was originally hashed, to prevent identical passwords
 *      from producing identical hashes.
 *   2. crypt(password, salt) hashes the plaintext password with that same salt,
 *      producing a string in the same format as stored_hash.
 *   3. strcmp compares the two strings: returns 0 if they are identical.
 */
int verify_password(const char *password, const char *stored_hash)
{
    /* Salt buffer: 2 characters + 1 null terminator = 3 bytes.
     * In C, strings must always end with '\0', so a 2-char salt needs a 3-byte array. */
    char salt[3];

    /* strncpy copies at most 2 bytes from stored_hash into salt.
     * Unlike strcpy, strncpy limits how many characters are copied,
     * preventing buffer overflow if stored_hash were unexpectedly short. */
    strncpy(salt, stored_hash, 2);
    salt[2] = '\0'; /* Ensure null termination — strncpy does NOT guarantee this. */

    /* crypt() returns a pointer to a static internal buffer containing the hash.
     * WARNING: this buffer is overwritten on every call to crypt(), so we must
     * use the result immediately (or copy it) before calling crypt() again. */
    char *hashed_input = crypt(password, salt);

    /* strcmp returns 0 when the two strings are identical.
     * We convert this to a boolean: (0 == 0) is 1 (true), anything else is 0 (false). */
    return (strcmp(hashed_input, stored_hash) == 0);
}

int main(int argc, char **argv)
{
    /* Stack-allocated buffer for the username.
     * In C, local arrays like this live on the stack and are automatically
     * freed when the function returns — no need for malloc/free. */
    char username[USERNAME_SIZE];

    /* Main login loop: keeps prompting until a successful login. */
    while (1)
    {
        read_username(username);

        /* pwdb_getpwnam searches the local pwfile for a user with this name.
         * Returns a pointer to a dynamically allocated (malloc'd) struct, or
         * NULL if the user was not found (or on error).
         * The '*' in 'struct pwdb_passwd *p' means p is a POINTER — it holds
         * the memory address of the struct, not the struct itself. */
        struct pwdb_passwd *p = pwdb_getpwnam(username);

        /* getpass() prints "Password: " to the terminal and reads input WITHOUT
         * echoing characters — essential for password security. It returns a
         * pointer to a static buffer containing the entered password.
         * We always ask for the password even if the user doesn't exist,
         * to avoid revealing whether a username is valid (timing attack prevention). */
        char *password = getpass("Password: ");

        if (p == NULL)
        {
            /* User not found in pwfile, but we don't reveal this specifically. */
            printf("Unknown user or incorrect password.\n");
            continue; /* Jump back to the top of the while loop. */
        }

        /* p->pw_passwd accesses the pw_passwd field through the pointer p.
         * The '->' operator dereferences a pointer and accesses a struct member.
         * Equivalent to (*p).pw_passwd, but much more readable. */
        if (verify_password(password, p->pw_passwd))
        {
            printf("User authenticated successfully.\n");
            return 0; /* Exit the program with success status. */
        }
        else
        {
            printf("Unknown user or incorrect password.\n");
            /* Loop continues — re-prompt for login. */
        }
    }

    return 0;
}
