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

#ifndef WIRELESS_H
#define WIRELESS_H

#ifdef ANDROID
#include <nl80211.h>
#else
#include <linux/nl80211.h>
#endif

int add_monitor(int phyidx, const char *name, int freq, enum nl80211_channel_type chan_type);
int del_monitor(const char *iface);
int interface_up(const char *ifname);

#endif /* WIRELESS_H */

