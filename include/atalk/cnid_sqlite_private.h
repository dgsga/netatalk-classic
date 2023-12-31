#ifndef _ATALK_CNID_SQLITE_PRIVATE_H
#define _ATALK_CNID_SQLITE_PRIVATE_H 1

#include "sqlite3.h"
#include <atalk/cnid_private.h>
#include <atalk/uuid.h>

#define CNID_SQLITE_FLAG_DEPLETED (1 << 0)	/* CNID set overflowed */

typedef struct CNID_sqlite_private {
	struct vol *vol;
	uint32_t cnid_sqlite_flags;
	sqlite3 *cnid_sqlite_con;
	char *cnid_sqlite_voluuid_str;
	cnid_t cnid_sqlite_hint;
	sqlite3_stmt *stmt;
	void *cnid_lookup_stmt;
	void *cnid_add_stmt;
	void *cnid_put_stmt;
} CNID_sqlite_private;

#endif
