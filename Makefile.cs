CC = gcc
CFLAGS = -Wall - Wextra - O2
LIBS = -lsqlite3

all: security_app security_tests

security_app: security_app.c
    $(CC) $(CFLAGS)security_app.c - o security_app $(LIBS)

security_tests: security_tests.c
    $(CC) $(CFLAGS)security_tests.c - o security_tests $(LIBS)

clean:
    rm - f security_app security_tests security_app.db
