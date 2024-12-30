NAME = aesdsocket

CC = gcc

CFLAGS = -Wall -Wextra -Werror

SRC_C = aesdsocket.c

OBJ = $(SRC_C:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

clean:
	rm -rf $(NAME)
	rm -rf $(OBJ)
