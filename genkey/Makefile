LIBKECCAK_DIR=../libs/libkeccak/
LIBKECCAK_ARCH=libkeccak.a
LIBKECCAK=$(LIBKECCAK_DIR)$(LIBKECCAK_ARCH)

FINAL=genkey

SOURCE=main.c

WARNINGS=-Wall -Werror -Wno-deprecated-declarations
CFLAGS=$(WARNINGS) -isystem $(LIBKECCAK_DIR) -ggdb3
LDFLAGS=-l:$(LIBKECCAK_ARCH) -lcrypto -L$(LIBKECCAK_DIR)

$(FINAL): $(LIBKECCAK) $(SOURCE)
	$(CC) $(SOURCE) $(LDFLAGS) $(CFLAGS) -o $@

$(LIBKECCAK):
	cd $(LIBKECCAK_DIR); make

clean:
	rm -f $(FINAL)
