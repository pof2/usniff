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
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <signal.h>
#include <errno.h>

#include "wireless.h"

#ifdef ANDROID
#define STATEFILE "/data/misc/usniff-%s.state"
#define TCPDUMP "/system/xbin/tcpdump"
#define OUTPUT "/data/misc/usniff-%s-%s.pcap"
#else
#define STATEFILE "/var/run/usniff-%s.state"
#define TCPDUMP "/usr/sbin/tcpdump"
#define OUTPUT "./usniff-%s-%s.pcap"
#endif

#define MONITOR_NAME "%s.usniff"

static int get_statefile_name(const char *iface, char *buf, int bufsize)
{
	int ret;

	ret = snprintf(buf, bufsize, STATEFILE, iface);
	if (ret >= bufsize)
		return -E2BIG;

	return 0;
}

static int state_write(const char *iface, const char *output)
{
	char buf[100];

	if (get_statefile_name(iface, buf, sizeof(buf)))
		return -E2BIG;

	FILE *f = fopen(buf, "w");
	if (!f)
		return -1;
	fprintf(f, "%d\n", getpid());
	fprintf(f, "%s\n", output);
	fclose(f);
	return 0;
}

static pid_t state_read(const char *iface, char *output, size_t output_size)
{
	char buf[100];
	pid_t pid;
	int ret;

	if (get_statefile_name(iface, buf, sizeof(buf)))
		return -E2BIG;

	FILE *f = fopen(buf, "r");
	if (!f)
		return -ENOENT;
	ret = fscanf(f, "%d\n", &pid);
	if (ret != 1)
		goto err;
	if (!fgets(output, output_size, f))
		goto err;
	fclose(f);

	if (strlen(output))
		output[strlen(output) - 1] = 0; 

	/* Check for stale pid */
	ret = snprintf(buf, sizeof(buf), "/proc/%d", pid);
	if (ret >= (int) sizeof(buf))
		return -ENOENT;

	f = fopen(buf, "r");
	if (!f)
		return -ENOENT;

	fclose(f);
	return pid;

err:
	fclose(f);
	return -1;
}

static int child_main(const char *iface, const char *real_iface)
{
	int ret;
	char output[100], timestr[20];
	const char *env[] = { (char *) 0 };
	time_t epoch;
	struct tm *tm;

	epoch = time(NULL);
	tm = localtime(&epoch);
	if (!tm) {
		perror("localtime failed");
		exit(EINVAL);
	}
	if (!strftime(timestr, sizeof(timestr), "%Y%m%d-%H%M%S", tm)) {
		perror("strftime failed");
		exit(EINVAL);
	}

	ret = snprintf(output, sizeof(output), OUTPUT, iface, timestr);
	if (ret >= (int) sizeof(output))
		exit(E2BIG);

	state_write(iface, output);
	umask(0077);
	ret = execle(TCPDUMP, TCPDUMP, "-w", output, "-i", real_iface,
		     "-s", "65535", (char *) 0, env); 
	if (ret)
		exit(errno);
	exit(0);
}

static int start_dump(const char *iface, const char *real_iface)
{
	pid_t ret;
	ret = fork();

	switch (ret) {
	case -1:
		exit(errno);
		break;
	case 0:
		child_main(iface, real_iface);
		break;
	default:
		break;
	}
	return 0;
}

static enum nl80211_channel_type str_to_chan_type(const char *s)
{
	int ret = -EINVAL;
	if (!s)
		return -EINVAL;

	if (!strcmp(s, "NOHT"))
		ret = NL80211_CHAN_NO_HT;
	else if (!strcmp(s, "HT20"))
		ret = NL80211_CHAN_HT20;
	else if (!strcmp(s, "HT40-"))
		ret = NL80211_CHAN_HT40MINUS;
	else if (!strcmp(s, "HT40+"))
		ret = NL80211_CHAN_HT40PLUS;
	return ret;
}

/* Create a monitor if interface is phy and bring interface up */
static int prepare_iface(const char *iface, const char *real_iface, const char *freq_s, const char *type_s)
{
	char *t;
	int phyidx = 0, ret;
	int freq = -1;
	enum nl80211_channel_type chan_type = -1;

	if (!strncmp(iface, "phy", 3)) {
		if (strlen(iface) < 4)
			return -EINVAL;
		phyidx = strtoul(iface + 3, &t, 0);
		if (*t != '\0')
			return -EINVAL;

		if (freq_s) {
			freq = strtoul(freq_s, &t, 0);
			if (*t != '\0')
				return -EINVAL;
		}

		if (type_s) {
			chan_type = str_to_chan_type(type_s);
			if ((int) chan_type == -1)
				return -EINVAL;
		}
		
		ret = add_monitor(phyidx, real_iface, freq, chan_type);
		if (ret) {
			perror("Failed to create monitor interface");
			return ret;
		}
	}

	ret = interface_up(real_iface);
	if (ret) {
		fprintf(stderr, "Failed to bring up interface %s: %s", real_iface, strerror(errno));
		if (!strncmp(iface, "phy", 3))
			del_monitor(real_iface);
		return ret;
	}
	return 0;
}

/* returns phyX.usniff if "orig" is phy, otherwise "orig" is returned */
static int translate_ifname(const char *orig, char *buf, unsigned int bufsize)
{
	int ret;

	if (strncmp(orig, "phy", 3)) {
		if (strlen(orig) >= bufsize)
			return -E2BIG;
		strcpy(buf, orig);
	}
	else {
		ret = snprintf(buf, bufsize, MONITOR_NAME, orig);
		if (ret >= (int) bufsize)
			return -E2BIG;
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  usniff start <iface|phy> [freq [NOHT|HT20|HT40-|HT40+]\n");
	fprintf(stderr, "  usniff stop <iface|phy>\n");
	fprintf(stderr, "  usniff status <iface|phy>\n");
}

int main(int argc, char **argv)
{
	int ret;
	pid_t pid;
	const char *iface;
	char real_iface[100];
	char output_file[100];

	if (argc < 3) {
		usage();
		exit(EINVAL);
	}

	iface = argv[2];
	ret = translate_ifname(iface, real_iface, sizeof(real_iface));
	if (ret)
		exit(E2BIG);

	pid = state_read(iface, output_file, sizeof(output_file));

	if (argc == 3 && strcmp(argv[1], "stop") == 0) {
		if (pid < 0) {
			fprintf(stderr, "Not running\n");
			exit(ENOENT);
		}

		kill(pid, SIGINT);
		if (!strncmp(iface, "phy", 3))
			del_monitor(real_iface);
	}
	else if ((argc == 3 || argc == 5) && strcmp(argv[1], "start") == 0) {
		if (pid > 0) {
			fprintf(stderr, "Already running\n");
			exit(EBUSY);
		}
		if (argc == 3)
			ret = prepare_iface(iface, real_iface, 0, 0);
		else
			ret = prepare_iface(iface, real_iface, argv[3], argv[4]);

		if (ret < 0) {
			fprintf(stderr, "Bad Interface\n");
			exit(-ret);
		}
		start_dump(iface, real_iface);
	}
	else if (argc == 3 && strcmp(argv[1], "status") == 0) {
		if (pid > 0) {
			printf("Running,%d,%s\n", pid, output_file);
			exit(0);
		}
		else {
			printf("Stopped\n");
			exit(ENOENT);
		}
	}
	else
		usage();

	return 0;
}

