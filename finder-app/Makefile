NAME = writer

CC = gcc

CFLAGS = -Wall -Wextra -Werror

SRC_C = writer.c

SRC_C_BONUS = src_bonus/checker.c

all: $(NAME)

$(NAME):
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(SRC_C) -o $(NAME)

clean:
	rm -rf $(NAME)

