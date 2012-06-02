/*
   Copyright 2012 Pontus Fuchs <pontus.fuchs@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <errno.h>

#include "wireless.h"

#ifdef ANDROID
#define PIDFILE "/data/misc/usniff.pid"
#define TCPDUMP "/system/bin/tcpdump"
#define OUTPUT "/sdcard/usniff.pcap"
#else
#define PIDFILE "/var/run/usniff.pid"
#define TCPDUMP "/usr/sbin/tcpdump"
#define OUTPUT "./usniff.pcap"
#endif

#define MONITOR_IFACE "usniff0"

static int pid_write(void)
{
	FILE *f = fopen(PIDFILE, "w");
	if (!f)
		return -1;
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return 0;
}

static pid_t pid_read(void)
{
	char buf[100];
	int pid = 0, ret;
	FILE *f = fopen(PIDFILE, "r");
	if (!f)
		return -1;
	ret = fscanf(f, "%d", &pid);
	fclose(f);
	if (ret != 1) {
		return -1;
	}

	ret = snprintf(buf, sizeof(buf), "/proc/%d", pid);
	if (ret >= sizeof(buf))
		return -1;

	f = fopen(buf, "r");
	if (!f)
		return -1;

	fclose(f);

	return pid;
}

static int child_main(const char *iface)
{
	int ret;
	const char *env[] = { (char *) 0 };

	pid_write();
	umask(0077);
	ret = execle(TCPDUMP, TCPDUMP, "-w", OUTPUT, "-i", iface, "-s", "65535", (char *) 0, env); 
	if (ret) {
		exit(errno);
	}
	exit(0);
}

static int start_dump(const char *iface)
{
	pid_t ret;
	ret = fork();

	switch (ret) {
	case -1:
		exit(1);
		break;
	case 0:
		child_main(iface);
		break;
	default:
		break;
	}
	return 0;
}

static int prepare_iface(const char *iface)
{
	char *t;
	int phyidx = 0, ret;

	if (!strncmp(iface, "wlan", 4))
		return 0;
	if (!strncmp(iface, "phy", 3)) {
		if (strlen(iface) < 4)
			return -1;
		phyidx = strtoul(iface + 3, &t, 0);
		if (*t != '\0')
			return -1;
		ret = add_monitor(phyidx, MONITOR_IFACE);
		if (ret) {
			perror("Failed to create monitor interface");
			return ret;
		}
	}
	else {
		return -1;
	}

	ret = interface_up(MONITOR_IFACE);
	if (ret) {
		perror("Failed to bring up monitor interface");
		del_monitor(MONITOR_IFACE);
		return ret;
	}
	return 0;
}

static const char * translate_ifname(const char *orig)
{
	return (!strncmp(orig, "phy", 3)) ? MONITOR_IFACE : orig;
}

static void usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  usniff start wlanX|phyX - phyX for air sniffing\n");
	fprintf(stderr, "  usniff stop wlanX|phyX\n");
	fprintf(stderr, "  usniff status\n");
}

int main(int argc, char **argv)
{
	int ret;
	pid_t pid;
	const char *iface;

	pid = pid_read();
	if (argc == 3 && strcmp(argv[1], "stop") == 0) {
		if (pid == -1) {
			fprintf(stderr, "Not running\n");
			exit(ENOENT);
		}

		iface = translate_ifname(argv[2]);
		kill(pid, SIGINT);
		if (!strcmp(iface, MONITOR_IFACE))
			del_monitor(MONITOR_IFACE);
	}
	else if (argc == 3 && strcmp(argv[1], "start") == 0) {
		if (pid > 0) {
			fprintf(stderr, "Already running\n");
			exit(EBUSY);
		}
		ret = prepare_iface(argv[2]);
		if ( ret < 0) {
			fprintf(stderr, "Bad Interface\n");
			exit(-ret);
		}
		start_dump(translate_ifname(argv[2]));
	}
	else if (argc == 2 && strcmp(argv[1], "status") == 0) {
		if (pid > 0) {
			printf("Running as pid %d\n", pid);
			exit(0);
		}
		else {
			printf("Not running\n");
			exit(ENOENT);
		}
	}
	else
		usage();

	return 0;
}

