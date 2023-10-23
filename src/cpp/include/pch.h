#pragma once

#include <iostream>
#include <cstring>
#include <queue>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#elif __linux__
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#else
#endif

#include "pcap.h"

