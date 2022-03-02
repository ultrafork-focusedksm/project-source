CFLAGS = -Wall -Werror -Wextra -Wpedantic -O2 -fPIC -MMD -DSUS_USERSPACE -D_GNU_SOURCE -g
LDFLAGS = -pthread -lrt -lb2

OBJECT_DIR = obj
INCLUDE =-I../kernel

SRC := $(wildcard *.c)
OBJ := $(addprefix $(OBJECT_DIR)/,$(SRC:.c=.o))
DEPS := $(OBJ:.o=.d)

ARTIFACT = sus_mod_tester

all: src

$(ARTIFACT): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

init:
	@mkdir -p $(OBJECT_DIR)

src: init $(ARTIFACT)

-include $(DEPS)
$(OBJECT_DIR)/%.o: %.c
	$(CC) -c $(INCLUDE) -o $@ $< $(CFLAGS)

tags:
	ctags -R .

clean:
	rm -rf $(OBJECT_DIR) $(ARTIFACT)
