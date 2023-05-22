#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/sockets.h"
#include "io/channel-file.h"
#include "qapi/error.h"

#include <sys/ioctl.h>
#include <termios.h>
#include "chardev/char-fd.h"

#ifdef HAVE_CHARDEV_ZCONSOLE

// XXX once illumos has cfmakeraw() that can be used instead.
static void
cfmakeraw (struct termios *termios_p)
{
	termios_p->c_iflag &=
	    ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	termios_p->c_oflag &= ~OPOST;
	termios_p->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	termios_p->c_cflag &= ~(CSIZE | PARENB);
	termios_p->c_cflag |= CS8;

	termios_p->c_cc[VMIN] = 0;
	termios_p->c_cc[VTIME] = 0;
}

static void
char_zconsole_open(Chardev *chr, ChardevBackend *backend, bool *be_opened,
    Error **errp)
{
	struct termios tty;
	int fd;

	fd = qmp_chardev_open_file_source((char *)"/dev/zconsole",
	    O_RDWR | O_NONBLOCK, errp);
	if (fd < 0)
		return;

	tcgetattr(fd, &tty);
	cfmakeraw(&tty);
	tcsetattr(fd, TCSAFLUSH, &tty);

	if (!g_unix_set_fd_nonblocking(fd, true, NULL)) {
		error_setg_errno(errp, errno, "Failed to set FD nonblocking");
		return;
	}

	qemu_chr_open_fd(chr, fd, fd);
}

static void
char_zconsole_init(ObjectClass *oc, void *data)
{
	ChardevClass *cc = CHARDEV_CLASS(oc);

	cc->open = char_zconsole_open;
}

static const TypeInfo char_serial_type_info = {
	.name = TYPE_CHARDEV_ZCONSOLE,
	.parent = TYPE_CHARDEV_FD,
	.class_init = char_zconsole_init,
};

static void register_types(void)
{
	type_register_static(&char_serial_type_info);
}

type_init(register_types);

#endif
