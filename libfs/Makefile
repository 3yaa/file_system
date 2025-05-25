CC      ?= gcc
CFLAGS  ?=  -Wall -Wextra -Werror

SRC     := disk.c fs.c
OBJ     := $(SRC:.c=.o)
LIB     := libfs.a

.PHONY: all
all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

%.o: %.c fs.h disk.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	$(RM) $(OBJ) $(LIB)