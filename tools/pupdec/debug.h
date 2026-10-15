#ifndef __DEBUG_SHIM_H__
#define __DEBUG_SHIM_H__
#include <stdio.h>
#define printfsocket(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define SSIZET_FMT "%zd"
#endif
