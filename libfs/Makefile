# Target library
CC      ?= gcc
CFLAGS  ?=  -Wall -Wextra -Werror

SRC     := disk.c fs.c
OBJ     := $(SRC:.c=.o)
LIB     := libfs.a

.PHONY: all
all: $(LIB)

# Build static library
$(LIB): $(OBJ)
	ar rcs $@ $^

# Compile each .c → .o (header changes recompile automatically)
%.o: %.c fs.h disk.h
	$(CC) $(CFLAGS) -c $< -o $@

# Convenience target -----------------------------------------
.PHONY: clean
clean:
	$(RM) $(OBJ) $(LIB)