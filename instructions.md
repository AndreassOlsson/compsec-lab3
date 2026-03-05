# Preparatory assignment 3

## INstructions

Study the downloaded program userinfo.c. Copy it to a new file called mylogin.c.
Rewrite it so that it mimics the system login procedure, which for example includes
that it should not echo the password as you type it on the screen. The program should
check the password entered by the user with the corresponding entry in the pwfile-
file. Useful library functions might include pwdb_getpwnam, getpass(3), crypt(3)
and strcmp(3). You may ignore warnings that getpass(3) is deprecated. If the pass-
words match, the program should write something like ”User authenticated successfully”
and terminate. If the password is wrong, or the username invalid, it should respond
”Unknown user or incorrect password.” and start over with the "login:" prompt.
To use crypt(3), you must #include <crypt.h> in your source filea. The password
verification works as follows:
Look up the user with pwdb_getpwnam to get the stored hash from pw_passwd.
1.2. Extract the 2-character salt from the beginning of the stored hash (e.g., using
strncpy into a 3-byte buffer). 3. Call crypt(password, salt) which returns the hashed password (salt + hash). 4. Compare the result with pw_passwd using strcmp.
Compile and run your program mylogin.c with the functionality we have described in
the previous preparatory assignment. Remember to compile with the pwdblib.c-file.
If you use crypt(3) function, link crypt libraryb. Test your program with some users.
Hint: use getpass and pwdb_getpwnam functions. The code is less than 60 lines.

## Context: userinfo.c

```c
/*
 * Shows user info from local pwfile.
 *
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h" /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)

int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL)
  {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n", p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
    return 0;
  }
  else
  {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

int main(int argc, char **argv)
{
  char username[USERNAME_SIZE];

  /*
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */
  read_username(username);

  /* Show user info from our local pwfile. */
  if (print_info(username) == NOUSER)
  {
    /* if there are no user with that usename... */
    printf("\nFound no user with name: %s\n", username);
    return 0;
  }
}
```

# Preparatory assignment 4

## INstructions

Based on your mylogin.c and the provided example in update_user.c, implement the
following ”update-pwfile” features:
The field pw_failed should be used to count the number of unsuccessful logins.
Each time an unsuccessful login is encountered this counter should increase by
one. When the right password is entered, pw_failed should be reset to zero.
1.2. Use the pw_failed counter to lock out a user account which has entered the
wrong password more than 3 times in a row. The account locking can be made
in several ways, implement it as you like but remember that it should be easy for
the administrator to enable the account again. So erasing the entry in pwfile is
not a great idea. . . 3. The field pw_age should be used to count the number of successful logins. When
the age is greater than some value, e.g. 5, the user should be reminded to change
her/his password. This field would be zeroed by a program corresponding to
passwd(1), which you don’t have to write.
Compile, debug, compile again and run your program. Check the pwfile from another
terminal window (or text editor) while testing your program. Does it work as you
expected?
Hint: You can copy some code snippets from pwdblib.c while implementing this fea-
ture. The code is less than 120 lines.

## COntext: update_user.c

```c
/*
 * Depends on: pwdblib.c
 *
 * Synopsis:
 *
 * Updates a users entry in the passwd file.
 * It ask for new data for each item in struct pwdb_passwd
 * If you just press enter for any question, the old information
 * will be unchanged.
 * If the user does not exist, it will add a new entry in the passwd file.
 * The entered password will be stored in plaintext.
 *
 *  Usage: update_user username
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h" /* include header declarations for pwdblib.c */

int main(int argc, char **argv)
{
  char *username;
  char *buf;
  size_t buflen, chread;
  struct pwdb_passwd *p, *oldp;
  int updt;

  if (argc < 2)
  {
    printf("Usage: update_user username\n");
    return (0);
  }

  username = argv[1];
  oldp = pwdb_getpwnam(username);
  if (oldp != NULL)
    updt = 1;
  else if ((oldp == NULL) && (pwdb_errno == PWDB_NOUSER))
    updt = 0;
  else
  {
    printf("pwdb_getpwnam return error: %s\n", pwdb_err2str(pwdb_errno));
    return (0);
  }

  p = (struct pwdb_passwd *)malloc(sizeof(struct pwdb_passwd));
  buf = NULL;
  buflen = 0;

  p->pw_name = username;

  chread = 0;
  while (1)
  {
    printf("Password:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_passwd = oldp->pw_passwd;
      break;
    }
    if (chread > 0)
    {
      p->pw_passwd = (char *)malloc(sizeof(char) * (chread + 1));
      strncpy(p->pw_passwd, buf, chread);
      p->pw_passwd[chread] = '\0';
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Uid:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_uid = oldp->pw_uid;
      break;
    }
    if (chread > 0)
    {
      p->pw_uid = atoi(buf);
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Gid:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_gid = oldp->pw_gid;
      break;
    }
    if (chread > 0)
    {
      p->pw_gid = atoi(buf);
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Real name:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_gecos = oldp->pw_gecos;
      break;
    }
    if (chread > 0)
    {
      p->pw_gecos = (char *)malloc(sizeof(char) * (chread + 1));
      strncpy(p->pw_gecos, buf, chread);
      p->pw_gecos[chread] = '\0';
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Home directory:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_dir = oldp->pw_dir;
      break;
    }
    if (chread > 0)
    {
      p->pw_dir = (char *)malloc(sizeof(char) * (chread + 1));
      strncpy(p->pw_dir, buf, chread);
      p->pw_dir[chread] = '\0';
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Shell:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_shell = oldp->pw_shell;
      break;
    }
    if (chread > 0)
    {
      p->pw_shell = (char *)malloc(sizeof(char) * (chread + 1));
      strncpy(p->pw_shell, buf, chread);
      p->pw_shell[chread] = '\0';
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Failed:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_failed = oldp->pw_failed;
      break;
    }
    if (chread > 0)
    {
      p->pw_failed = atoi(buf);
      break;
    }
  }

  chread = 0;
  while (1)
  {
    printf("Age:");
    chread = getline(&buf, &buflen, stdin);
    buf[chread] = '\0';
    chread--; /* remove '\n' included by getline */
    if ((!updt) && (chread < 1))
      printf("New user, so you must enter data\n");
    if ((updt) && (chread < 1))
    {
      p->pw_age = oldp->pw_age;
      break;
    }
    if (chread > 0)
    {
      p->pw_age = atoi(buf);
      break;
    }
  }

  if (pwdb_update_user(p) != 0)
  {
    printf("pwdb_update_user returned error %s\n", pwdb_err2str(pwdb_errno));
  }

  return (0);
}
```

# Preparatory assignment 5

Secure your program against Ctrl-C, such that your program doesn’t exit when the
combination is pressed. Check the man pages for signal(2) and signal(7). Hint: If
you need to kill your program after blocking Ctrl-C, you can press Ctrl-Z to go back
the terminal, then write sudo killall -9 mylogin

# Preparatory assignment 6

## Instructions

Study the program openshell_demo.c. Make sure you understand how the program
works. Remember that when you call fork(2), both the parent and the child process
continues execution in the program, but fork returns different values to the parent and
the child, so that you can separate the line of execution.
Read about the functions setuid(2), seteuid(2), setgid(2) and setegid(2).
Read about the functions getuid(2), geteuid(2), getgid(2) and getegid(2).

## Context: openshell_demo.c

```c
/*
 * Program: openshell_demo.c
 *
 * Synopsis:
 *
 * Creates a new child process which starts a xterm window.
 * The parent just waits for the child to complete, and then exits.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define PROGRAM "/usr/bin/xterm"

int main()
{
  pid_t pid;
  int status;

  printf("uid = %d, gid = %d, euid = %d, egid = %d\n", getuid(), getgid(), geteuid(), getegid());

  pid = fork();

  if (pid == 0)
  {
    /* This is the child process. Run an xterm window */
    execl(PROGRAM, PROGRAM, "-e", "/bin/sh", "-l", NULL);

    /* if child returns we must inform parent.
     * Always exit a child process with _exit() and not return() or exit().
     */
    _exit(-1);
  }
  else if (pid < 0)
  { /* Fork failed */
    printf("Fork faild\n");
    status = -1;
  }
  else
  {
    /* This is parent process. Wait for child to complete */
    if (waitpid(pid, &status, 0) != pid)
    {
      status = -1;
    }
  }

  return status;
}
```

## Context: Functions

- setuid(2) = Sets the real, effective, and saved user ID of the calling process to the specified user ID (if permitted).
- seteuid(2) = Sets the effective user ID of the calling process.
- setgid(2) = Sets the real, effective, and saved group ID of the calling process to the specified group ID (if permitted).
- setegid(2) = Sets the effective group ID of the calling process.
- getuid(2) = Returns the real user ID (UID) of the calling process.
- geteuid(2) = Returns the effective user ID (EUID) of the calling process.
- getgid(2) = Returns the real group ID (GID) of the calling process.
- getegid(2) = Returns the effective group ID (EGID) of the calling process.

# Preparatory assignment 7

Implement the following feature in your program. After a successful authentication of
a user, your program should fork and start a terminal window with the user’s preferred
shell. The parent process should just wait until the child exits and then show the
"login:" prompt again.
