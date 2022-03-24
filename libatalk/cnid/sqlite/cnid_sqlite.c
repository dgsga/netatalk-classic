/*
 * Copyright (C) Ralph Boehme 2013
 * All Rights Reserved.  See COPYING.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif				/* HAVE_CONFIG_H */

#undef _FORTIFY_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>

#include <sqlite3.h>

#include <atalk/logger.h>
#include <atalk/adouble.h>
#include <atalk/util.h>
#include <atalk/cnid_sqlite_private.h>
#include <atalk/errchk.h>
#include <atalk/globals.h>
#include <atalk/volume.h>


sqlite3_stmt *stmt = NULL;
// CK static MYSQL_BIND lookup_param[4], lookup_result[5];
// CK static MYSQL_BIND add_param[4], put_param[5];

/*
 * Prepared statement parameters
 */
static char stmt_param_name[MAXPATHLEN];
static u_int32_t stmt_param_name_len;
static u_int64_t stmt_param_id;
static u_int64_t stmt_param_did;
static u_int64_t stmt_param_dev;
static u_int64_t stmt_param_ino;

/*
 * lookup result parameters
 */
static u_int64_t lookup_result_id;
static u_int64_t lookup_result_did;
static char lookup_result_name[MAXPATHLEN];
static unsigned long lookup_result_name_len;
static u_int64_t lookup_result_dev;
static u_int64_t lookup_result_ino;

static int vasprintf(char **ret, const char *fmt, va_list ap)
{
    int n, size = 64;
    char *p, *np;

    if ((p = malloc(size)) == NULL)
        return -1;

    while (1) {
        /* Try to print in the allocated space. */
        n = vsnprintf(p, size, fmt, ap);
        /* If that worked, return the string. */
        if (n > -1 && n < size) {
            *ret = p;
            return n;
        }
        /* Else try again with more space. */
        if (n > -1)    /* glibc 2.1 */
            size = n+1; /* precisely what is needed */
        else           /* glibc 2.0 */
            size *= 2;  /* twice the old size */
        if ((np = realloc (p, size)) == NULL) {
            free(p);
            *ret = NULL;
            return -1;
        } else {
            p = np;
        }
    }
}

static int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vasprintf(strp, fmt, ap);
    va_end(ap);

    return len;
}

static int init_prepared_stmt_lookup(CNID_sqlite_private * db)
{
	EC_INIT;
	char *sql = NULL;
	int code;

#ifdef FIXCK
	lookup_result[0].buffer_type = MYSQL_TYPE_LONGLONG;
	lookup_result[0].buffer = &lookup_result_id;
	lookup_result[0].is_unsigned = true;

	lookup_result[1].buffer_type = MYSQL_TYPE_LONGLONG;
	lookup_result[1].buffer = &lookup_result_did;
	lookup_result[1].is_unsigned = true;

	lookup_result[2].buffer_type = MYSQL_TYPE_STRING;
	lookup_result[2].buffer = &lookup_result_name;
	lookup_result[2].buffer_length = sizeof(lookup_result_name);
	lookup_result[2].length = &lookup_result_name_len;

	lookup_result[3].buffer_type = MYSQL_TYPE_LONGLONG;
	lookup_result[3].buffer = &lookup_result_dev;
	lookup_result[3].is_unsigned = true;

	lookup_result[4].buffer_type = MYSQL_TYPE_LONGLONG;
	lookup_result[4].buffer = &lookup_result_ino;
	lookup_result[4].is_unsigned = true;
#endif

	EC_NEG1(asprintf
		(&sql,
		 "SELECT Id,Did,Name,DevNo,InodeNo FROM `%s` "
		 "WHERE (Name=? AND Did=?) OR (DevNo=? AND InodeNo=?)",
		 db->cnid_sqlite_voluuid_str));
	EC_ZERO_LOG(sqlite3_prepare_v2(db->cnid_lookup_stmt, sql, strlen(sql), &stmt, NULL));
	
	EC_ZERO_LOG(sqlite3_bind_text(db->cnid_lookup_stmt, 1, stmt_param_name, strlen(stmt_param_name), SQLITE_STATIC) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt, 2, stmt_param_did) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt, 3, stmt_param_dev) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt, 4, stmt_param_ino) );

      EC_CLEANUP:
	if (sql)
		free(sql);
	EC_EXIT;
}

static int init_prepared_stmt_add(CNID_sqlite_private * db)
{
	EC_INIT;
	char *sql = NULL;

// CK	EC_NULL(db->cnid_add_stmt = mysql_stmt_init(db->cnid_sqlite_con));
	EC_NEG1(asprintf(&sql,
			 "INSERT INTO `%s` (Name,Did,DevNo,InodeNo) VALUES(?,?,?,?,?)",
			 db->cnid_sqlite_voluuid_str) );

	EC_ZERO_LOG(sqlite3_prepare_v2
		    (db->cnid_lookup_stmt, sql, strlen(sql), &stmt, NULL));
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    1, stmt_param_id) );
	EC_ZERO_LOG(sqlite3_bind_text(db->cnid_lookup_stmt,
		    2, stmt_param_name, strlen(stmt_param_name), SQLITE_STATIC) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    3, stmt_param_did) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    4, stmt_param_dev) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    5, stmt_param_ino) );

      EC_CLEANUP:
	if (sql)
		free(sql);
	EC_EXIT;
}

static int init_prepared_stmt_put(CNID_sqlite_private * db)
{
	EC_INIT;
	char *sql = NULL;

// CK	EC_NULL(db->cnid_put_stmt = mysql_stmt_init(db->cnid_sqlite_con));
	EC_NEG1(asprintf(&sql,
			 "INSERT INTO `%s` (Id,Name,Did,DevNo,InodeNo) VALUES(?,?,?,?,?)",
			 db->cnid_sqlite_voluuid_str));

	EC_ZERO_LOG(sqlite3_prepare_v2
		    (db->cnid_put_stmt, sql, strlen(sql), &stmt, NULL));
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    1, stmt_param_id) );
	EC_ZERO_LOG(sqlite3_bind_text(db->cnid_lookup_stmt,
		    2, stmt_param_name, strlen(stmt_param_name), SQLITE_STATIC) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    3, stmt_param_did) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    4, stmt_param_dev) );
	EC_ZERO_LOG(sqlite3_bind_int64(db->cnid_lookup_stmt,
		    5, stmt_param_ino) );

      EC_CLEANUP:
	if (sql)
		free(sql);
	EC_EXIT;
}

static int init_prepared_stmt(CNID_sqlite_private * db)
{
	EC_INIT;

	EC_ZERO(init_prepared_stmt_lookup(db));
	EC_ZERO(init_prepared_stmt_add(db));
	EC_ZERO(init_prepared_stmt_put(db));

      EC_CLEANUP:
	EC_EXIT;
}

static void close_prepared_stmt(CNID_sqlite_private * db)
{
	sqlite3_finalize(db->cnid_lookup_stmt);
	sqlite3_finalize(db->cnid_add_stmt);
	sqlite3_finalize(db->cnid_put_stmt);
}

static int cnid_sqlite_execute(sqlite3 * con, char *fmt, ...)
{
	char *sql = NULL;
	char *sqlite_error;
	va_list ap;
	int rv;

	va_start(ap, fmt);
	if (vasprintf(&sql, fmt, ap) == -1)
		return -1;
	va_end(ap);

	LOG(log_maxdebug, logtype_cnid, "SQL: %s", sql);

	rv = sqlite3_step(stmt);

	if (rv) {
		LOG(log_info, logtype_cnid,
		    "sqlite query \"%s\", error: %s", sql, sqlite_error);
		sqlite3_free(sqlite_error);
		errno = CNID_ERR_DB;
	}
	free(sql);
	return rv;
}

int cnid_sqlite_delete(struct _cnid_db *cdb, const cnid_t id)
{
	EC_INIT;
	CNID_sqlite_private *db;

	if (!cdb || !(db = cdb->_private) || !id) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_delete: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	LOG(log_debug, logtype_cnid,
	    "cnid_sqlite_delete(%" PRIu32 "): BEGIN", ntohl(id));

	EC_NEG1(cnid_sqlite_execute(db->cnid_sqlite_con,
				    "DELETE FROM `%s` WHERE Id=%" PRIu32,
				    db->cnid_sqlite_voluuid_str,
				    ntohl(id)));

	LOG(log_debug, logtype_cnid,
	    "cnid_sqlite_delete(%" PRIu32 "): END", ntohl(id));

      EC_CLEANUP:
	EC_EXIT;
}

void cnid_sqlite_close(struct _cnid_db *cdb)
{
	CNID_sqlite_private *db;

	if (!cdb) {
		LOG(log_error, logtype_cnid,
		    "cnid_close called with NULL argument !");
		return;
	}

	if ((db = cdb->_private) != NULL) {
		LOG(log_debug, logtype_cnid,
		    "closing database connection for volume '%s'",
		    cdb->cnid_db_vol->v_localname);

		free(db->cnid_sqlite_voluuid_str);

		close_prepared_stmt(db);

		if (db->cnid_sqlite_con) {
			sqlite3_close(db->cnid_sqlite_con);
			sqlite3_shutdown();
		}
		free(db);
	}

	free(cdb);

	return;
}

int cnid_sqlite_update(struct _cnid_db *cdb,
		      cnid_t id,
		      const struct stat *st,
		      cnid_t did, const char *name, size_t len)
{
	EC_INIT;
	CNID_sqlite_private *db;
	cnid_t update_id;

	if (!cdb || !(db = cdb->_private) || !id || !st || !name) {
		LOG(log_error, logtype_cnid,
		    "cnid_update: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	if (len > MAXPATHLEN) {
		LOG(log_error, logtype_cnid,
		    "cnid_update: Path name is too long");
		errno = CNID_ERR_PATH;
		EC_FAIL;
	}

	uint64_t dev = st->st_dev;
	uint64_t ino = st->st_ino;

	do {
		EC_NEG1(cnid_sqlite_execute(db->cnid_sqlite_con,
					    "DELETE FROM `%s` WHERE Id=%"
					    PRIu32,
					    db->cnid_sqlite_voluuid_str,
					    ntohl(id)));
		EC_NEG1(cnid_sqlite_execute
			(db->cnid_sqlite_con,
			 "DELETE FROM `%s` WHERE Did=%" PRIu32
			 " AND Name='%s'", db->cnid_sqlite_voluuid_str,
			 ntohl(did), name));
		EC_NEG1(cnid_sqlite_execute
			(db->cnid_sqlite_con,
			 "DELETE FROM `%s` WHERE DevNo=%" PRIu64
			 " AND InodeNo=%" PRIu64,
			 db->cnid_sqlite_voluuid_str, dev, ino));

		stmt_param_id = ntohl(id);
		strncpy(stmt_param_name, name, sizeof(stmt_param_name));
		stmt_param_name_len = len;
		stmt_param_did = ntohl(did);
		stmt_param_dev = dev;
		stmt_param_ino = ino;

		if (sqlite3_exec(db->cnid_sqlite_con, db->cnid_put_stmt, NULL, NULL, NULL)) {
			switch (sqlite3_errcode(db->cnid_sqlite_con)) {
//			case ER_DUP_ENTRY:
//				/*
//				 * Race condition:
//				 * between deletion and insert another process
//				 * may have inserted this entry.
//				 */
//				continue;
			default:
				EC_FAIL;
			}
		}
		update_id = sqlite3_last_insert_rowid(db->cnid_put_stmt);
	} while (update_id != ntohl(id));

      EC_CLEANUP:
	EC_EXIT;
}

cnid_t cnid_sqlite_lookup(struct _cnid_db *cdb,
			  const struct stat *st,
			  cnid_t did, const char *name, size_t len)
{
	EC_INIT;
	CNID_sqlite_private *db;
	cnid_t id = CNID_INVALID;
	bool have_result = false;

	if (!cdb || !(db = cdb->_private) || !st || !name) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_lookup: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	if (len > MAXPATHLEN) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_lookup: Path name is too long");
		errno = CNID_ERR_PATH;
		EC_FAIL;
	}

	uint64_t dev = st->st_dev;
	uint64_t ino = st->st_ino;
	cnid_t hint = db->cnid_sqlite_hint;

	LOG(log_maxdebug, logtype_cnid,
	    "cnid_sqlite_lookup(did: %" PRIu32 ", name: \"%s\", hint: %"
	    PRIu32 "): START", ntohl(did), name, ntohl(hint));

	strncpy(stmt_param_name, name, sizeof(stmt_param_name));
	stmt_param_name_len = len;
	stmt_param_did = ntohl(did);
	stmt_param_dev = dev;
	stmt_param_ino = ino;

      exec_stmt:
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		switch (sqlite3_errcode(db->cnid_sqlite_con)) {
		default:
			EC_FAIL;
		}
	}
	EC_ZERO_LOG(sqlite_stmt_store_result(db->cnid_lookup_stmt));
	have_result = true;
	EC_ZERO_LOG(sqlite_stmt_bind_result
		    (db->cnid_lookup_stmt, lookup_result));

	uint64_t retdev, retino;
	cnid_t retid, retdid;
	char *retname;

	switch (mysql_stmt_num_rows(db->cnid_lookup_stmt)) {

	case 0:
		/* not found */
		LOG(log_debug, logtype_cnid,
		    "cnid_sqlite_lookup: name: '%s', did: %u is not in the CNID database",
		    name, ntohl(did));
		errno = CNID_DBD_RES_NOTFOUND;
		EC_FAIL;

	case 1:
		/* either both OR clauses matched the same id or only one matched, handled below */
		EC_ZERO(sqlite_stmt_fetch(db->cnid_lookup_stmt));
		break;

	case 2:
		/* a mismatch, delete both and return not found */
		while (sqlite_stmt_fetch(db->cnid_lookup_stmt) == 0) {
			if (cnid_sqlite_delete
			    (cdb, htonl((cnid_t) lookup_result_id))) {
				LOG(log_error, logtype_cnid,
				    "sqlite query error: %s",
				    sqlite_error(db->cnid_sqlite_con));
				errno = CNID_ERR_DB;
				EC_FAIL;
			}
		}
		errno = CNID_DBD_RES_NOTFOUND;
		EC_FAIL;

	default:
		errno = CNID_ERR_DB;
		EC_FAIL;
	}

	retid = htonl(lookup_result_id);
	retdid = htonl(lookup_result_did);
	retname = lookup_result_name;
	retdev = lookup_result_dev;
	retino = lookup_result_ino;

	if (retdid != did || STRCMP(retname, !=, name)) {
		LOG(log_debug, logtype_cnid,
		    "cnid_sqlite_lookup(CNID hint: %" PRIu32 ", DID: %"
		    PRIu32
		    ", name: \"%s\"): server side mv oder reused inode",
		    ntohl(hint), ntohl(did), name);
		if (hint != retid) {
			if (cnid_sqlite_delete(cdb, retid) != 0) {
				LOG(log_error, logtype_cnid,
				    "sqlite query error: %s",
				    sqlite_error(db->cnid_sqlite_con));
				errno = CNID_ERR_DB;
				EC_FAIL;
			}
			errno = CNID_DBD_RES_NOTFOUND;
			EC_FAIL;
		}
		LOG(log_debug, logtype_cnid,
		    "cnid_sqlite_lookup: server side mv, got hint, updating");
		if (cnid_sqlite_update(cdb, retid, st, did, name, len) != 0) {
			LOG(log_error, logtype_cnid,
			    "sqlite query error: %s",
			    sqlite_error(db->cnid_sqlite_con));
			errno = CNID_ERR_DB;
			EC_FAIL;
		}
		id = retid;
	} else if (retdev != dev || retino != ino) {
		LOG(log_debug, logtype_cnid,
		    "cnid_sqlite_lookup(DID:%u, name: \"%s\"): changed dev/ino",
		    ntohl(did), name);
		if (cnid_sqlite_delete(cdb, retid) != 0) {
			LOG(log_error, logtype_cnid,
			    "sqlite query error: %s",
			    sqlite_error(db->cnid_sqlite_con));
			errno = CNID_ERR_DB;
			EC_FAIL;
		}
		errno = CNID_DBD_RES_NOTFOUND;
		EC_FAIL;
	} else {
		/* everythings good */
		id = retid;
	}

      EC_CLEANUP:
	LOG(log_debug, logtype_cnid, "cnid_sqlite_lookup: id: %" PRIu32,
	    ntohl(id));
	if (have_result)
		sqlite_stmt_free_result(db->cnid_lookup_stmt);
	if (ret != 0)
		id = CNID_INVALID;
	return id;
}

cnid_t cnid_sqlite_add(struct _cnid_db *cdb,
		      const struct stat *st,
		      cnid_t did,
		      const char *name, size_t len, cnid_t hint)
{
	EC_INIT;
	CNID_sqlite_private *db;
	cnid_t id = CNID_INVALID;
	MYSQL_RES *result = NULL;
	MYSQL_STMT *stmt;
	my_ulonglong lastid;

	if (!cdb || !(db = cdb->cnid_db_private) || !st || !name) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_add: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	if (len > MAXPATHLEN) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_add: Path name is too long");
		errno = CNID_ERR_PATH;
		EC_FAIL;
	}

	uint64_t dev = st->st_dev;
	uint64_t ino = st->st_ino;
	db->cnid_sqlite_hint = hint;

	LOG(log_maxdebug, logtype_cnid,
	    "cnid_sqlite_add(did: %" PRIu32 ", name: \"%s\", hint: %" PRIu32
	    "): START", ntohl(did), name, ntohl(hint));

	do {
		if ((id =
		     cnid_sqlite_lookup(cdb, st, did, name,
				       len)) == CNID_INVALID) {
			if (errno == CNID_ERR_DB)
				EC_FAIL;
			/*
			 * If the CNID set overflowed before (CNID_MYSQL_FLAG_DEPLETED)
			 * ignore the CNID "hint" taken from the AppleDouble file
			 */
			if (!db->cnid_sqlite_hint
			    || (db->
				cnid_sqlite_flags &
				CNID_MYSQL_FLAG_DEPLETED)) {
				stmt = db->cnid_add_stmt;
			} else {
				stmt = db->cnid_put_stmt;
				stmt_param_id = ntohl(db->cnid_sqlite_hint);
			}
			strncpy(stmt_param_name, name,
				sizeof(stmt_param_name));
			stmt_param_name_len = len;
			stmt_param_did = ntohl(did);
			stmt_param_dev = dev;
			stmt_param_ino = ino;

			if (sqlite_stmt_execute(stmt)) {
				switch (sqlite_stmt_errno(stmt)) {
				case ER_DUP_ENTRY:
					break;
				case CR_SERVER_LOST:
					close_prepared_stmt(db);
					EC_ZERO(init_prepared_stmt(db));
					continue;
				default:
					EC_FAIL;
				}
				/*
				 * Race condition:
				 * between lookup and insert another process may have inserted
				 * this entry.
				 */
				if (db->cnid_sqlite_hint)
					db->cnid_sqlite_hint = CNID_INVALID;
				continue;
			}

			lastid = sqlite3_last_insert_rowid(stmt);

			if (lastid > 0xffffffff) { /* CK this is wrong */
				/* CNID set ist depleted, restart from scratch */
				EC_NEG1(cnid_sqlite_execute
					(db->cnid_sqlite_con,
					 "START TRANSACTION;"
					 "UPDATE volumes SET Depleted=1 WHERE VolUUID='%s';"
					 "TRUNCATE TABLE %s;"
					 "ALTER TABLE %s AUTO_INCREMENT = 17;"
					 "COMMIT;",
					 db->cnid_sqlite_voluuid_str,
					 db->cnid_sqlite_voluuid_str,
					 db->cnid_sqlite_voluuid_str));
				db->cnid_sqlite_flags |=
				    CNID_MYSQL_FLAG_DEPLETED;
				hint = CNID_INVALID;
				do {
					result =
					    sqlite_store_result(db->
							       cnid_sqlite_con);
					if (result)
						sqlite_free_result(result);
				} while (sqlite_next_result
					 (db->cnid_sqlite_con) == 0);
				continue;
			}

			/* Finally assign our result */
			id = htonl((uint32_t) lastid);
		}
	} while (id == CNID_INVALID);

      EC_CLEANUP:
	LOG(log_debug, logtype_cnid, "cnid_sqlite_add: id: %" PRIu32,
	    ntohl(id));

	if (result)
		sqlite_free_result(result);
	return id;
}

cnid_t cnid_sqlite_get(struct _cnid_db *cdb, cnid_t did, const char *name,
		      size_t len)
{
	EC_INIT;
	CNID_sqlite_private *db;
	cnid_t id = CNID_INVALID;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;

	if (!cdb || !(db = cdb->cnid_db_private) || !name) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_get: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	if (len > MAXPATHLEN) {
		LOG(log_error, logtype_cnid,
		    "cnid_sqlite_get: name is too long");
		errno = CNID_ERR_PATH;
		return CNID_INVALID;
	}

	LOG(log_debug, logtype_cnid,
	    "cnid_sqlite_get(did: %" PRIu32 ", name: \"%s\"): START",
	    ntohl(did), name);

	EC_NEG1(cnid_sqlite_execute(db->cnid_sqlite_con,
				    "SELECT Id FROM `%s` "
				    "WHERE Name='%s' AND Did=%" PRIu32,
				    db->cnid_sqlite_voluuid_str,
				    name, ntohl(did)));

	if ((result = sqlite_store_result(db->cnid_sqlite_con)) == NULL) {
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    mysql_error(db->cnid_sqlite_con));
		errno = CNID_ERR_DB;
		EC_FAIL;
	}

	if (mysql_num_rows(result)) {
		row = mysql_fetch_row(result);
		id = htonl(atoi(row[0]));
	}

      EC_CLEANUP:
	LOG(log_debug, logtype_cnid, "cnid_mysql_get: id: %" PRIu32,
	    ntohl(id));

	if (result)
		mysql_free_result(result);

	return id;
}

char *cnid_mysql_resolve(struct _cnid_db *cdb, cnid_t * id, void *buffer,
			 size_t len)
{
	EC_INIT;
	CNID_sqlite_private *db;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;

	if (!cdb || !(db = cdb->cnid_db_private)) {
		LOG(log_error, logtype_cnid,
		    "cnid_mysql_get: Parameter error");
		errno = CNID_ERR_PARAM;
		EC_FAIL;
	}

	EC_NEG1(cnid_sqlite_execute(db->cnid_sqlite_con,
				    "SELECT Did,Name FROM `%s` WHERE Id=%"
				    PRIu32, db->cnid_sqlite_voluuid_str,
				    ntohl(*id)));

	EC_NULL(result = mysql_store_result(db->cnid_sqlite_con));

	if (mysql_num_rows(result) != 1)
		EC_FAIL;

	row = mysql_fetch_row(result);

	*id = htonl(atoi(row[0]));
	strncpy(buffer, row[1], len);

      EC_CLEANUP:
	if (result)
		mysql_free_result(result);

	if (ret != 0) {
		*id = CNID_INVALID;
		return NULL;
	}
	return buffer;
}

/**
 * Caller passes buffer where we will store the db stamp
 **/
int cnid_mysql_getstamp(struct _cnid_db *cdb, void *buffer,
			const size_t len)
{
	EC_INIT;
	CNID_sqlite_private *db;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;

	if (!cdb || !(db = cdb->cnid_db_private)) {
		LOG(log_error, logtype_cnid, "cnid_find: Parameter error");
		errno = CNID_ERR_PARAM;
		return CNID_INVALID;
	}

	if (!buffer)
		EC_EXIT_STATUS(0);

	if (cnid_sqlite_execute(db->cnid_sqlite_con,
				"SELECT Stamp FROM volumes WHERE VolPath='%s'",
				cdb->cnid_db_vol->v_path)) {
		if (mysql_errno(db->cnid_sqlite_con) != ER_DUP_ENTRY) {
			LOG(log_error, logtype_cnid,
			    "sqlite query error: %s",
			    mysql_error(db->cnid_sqlite_con));
			EC_FAIL;
		}
	}

	if ((result = mysql_store_result(db->cnid_sqlite_con)) == NULL) {
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    mysql_error(db->cnid_sqlite_con));
		errno = CNID_ERR_DB;
		EC_FAIL;
	}
	if (!mysql_num_rows(result)) {
		LOG(log_error, logtype_cnid,
		    "Can't get DB stamp for volumes \"%s\"",
		    cdb->cnid_db_vol->v_path);
		EC_FAIL;
	}
	row = mysql_fetch_row(result);
	memcpy(buffer, row[0], len);

      EC_CLEANUP:
	if (result)
		mysql_free_result(result);
	EC_EXIT;
}


int cnid_mysql_find(struct _cnid_db *cdb, const char *name, size_t namelen,
		    void *buffer, size_t buflen)
{
	LOG(log_error, logtype_cnid,
	    "cnid_mysql_find(\"%s\"): not supported with MySQL CNID backend",
	    name);
	return -1;
}

cnid_t cnid_mysql_rebuild_add(struct _cnid_db *cdb, const struct stat *st,
			      cnid_t did, const char *name, size_t len,
			      cnid_t hint)
{
	LOG(log_error, logtype_cnid,
	    "cnid_mysql_rebuild_add(\"%s\"): not supported with MySQL CNID backend",
	    name);
	return CNID_INVALID;
}

int cnid_mysql_wipe(struct _cnid_db *cdb)
{
	EC_INIT;
	CNID_sqlite_private *db;
	MYSQL_RES *result = NULL;

	if (!cdb || !(db = cdb->cnid_db_private)) {
		LOG(log_error, logtype_cnid, "cnid_wipe: Parameter error");
		errno = CNID_ERR_PARAM;
		return -1;
	}

	LOG(log_debug, logtype_cnid, "cnid_dbd_wipe");

	EC_NEG1(cnid_sqlite_execute(db->cnid_sqlite_con,
				    "START TRANSACTION;"
				    "UPDATE volumes SET Depleted=0 WHERE VolUUID='%s';"
				    "TRUNCATE TABLE `%s`;"
				    "ALTER TABLE `%s` AUTO_INCREMENT = 17;"
				    "COMMIT;",
				    db->cnid_sqlite_voluuid_str,
				    db->cnid_sqlite_voluuid_str,
				    db->cnid_sqlite_voluuid_str));

	do {
		result = mysql_store_result(db->cnid_sqlite_con);
		if (result)
			mysql_free_result(result);
	} while (mysql_next_result(db->cnid_sqlite_con) == 0);

      EC_CLEANUP:
	EC_EXIT;
}

static struct _cnid_db *cnid_sqlite_new(struct vol *vol)
{
	struct _cnid_db *cdb;

	if ((cdb =
	     (struct _cnid_db *) calloc(1,
					sizeof(struct _cnid_db))) == NULL)
		return NULL;

	cdb->cnid_db_vol = vol;
	cdb->cnid_db_flags = CNID_FLAG_PERSISTENT | CNID_FLAG_LAZY_INIT;
	cdb->cnid_add = cnid_mysql_add;
	cdb->cnid_delete = cnid_sqlite_delete;
	cdb->cnid_get = cnid_mysql_get;
	cdb->cnid_lookup = cnid_mysql_lookup;
	cdb->cnid_find = cnid_mysql_find;
	cdb->cnid_nextid = NULL;
	cdb->cnid_resolve = cnid_mysql_resolve;
	cdb->cnid_getstamp = cnid_mysql_getstamp;
	cdb->cnid_update = cnid_mysql_update;
	cdb->cnid_rebuild_add = cnid_mysql_rebuild_add;
	cdb->cnid_close = cnid_sqlite_close;
	cdb->cnid_wipe = cnid_mysql_wipe;
	return cdb;
}

/* Return allocated UUID string with dashes stripped */
static char *uuid_strip_dashes(const char *uuid)
{
	static char stripped[33];
	int i = 0;

	while (*uuid && i < 32) {
		if (*uuid != '-') {
			stripped[i++] = *uuid;
		}
		uuid++;
	}
	stripped[i] = 0;
	return strdup(stripped);
}

/* ---------------------- */
struct _cnid_db *cnid_sqlite_open(struct cnid_open_args *args)
{
	EC_INIT;
	CNID_sqlite_private *db = NULL;
	struct _cnid_db *cdb = NULL;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	struct vol *vol = args->cnid_args_vol;

	EC_NULL(cdb = cnid_sqlite_new(vol));
	EC_NULL(db =
		(CNID_sqlite_private *) calloc(1,
					       sizeof
					       (CNID_sqlite_private)));
	cdb->cnid_db_private = db;

	EC_NULL(db->cnid_sqlite_voluuid_str =
		uuid_strip_dashes(vol->v_uuid));

	/* Initialize and connect to sqlite3 database */
	sqlite3_initialize();
	EC_ZERO(db->cnid_sqlite_con =
		sqlite3_open_v2("file:/var/db/netatalk-classic/cnid.sqlite",
			    db->cnid_sqlite_con,
			    SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL));

	const AFPObj *obj = vol->v_obj;


	/* Add volume to volume table */
	if (cnid_sqlite_execute(db->cnid_sqlite_con,
				"CREATE TABLE IF NOT EXISTS volumes "
				"( VolUUID CHAR(32) PRIMARY KEY,"
				"VolPath TEXT(4096),"
				"Stamp BINARY(8),"
				"Depleted INT,"
				"INDEX(VolPath(64))"
				")"))
	{
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    sqlite3_errmsg(db->cnid_sqlite_con));
		EC_FAIL;
	}
	time_t now = time(NULL);
	char stamp[8];
	memset(stamp, 0, 8);
	memcpy(stamp, &now, sizeof(time_t));
	char blob[16 + 1];
	mysql_real_escape_string(db->cnid_sqlite_con, blob, stamp, 8);

	if (cnid_sqlite_execute(db->cnid_sqlite_con,
				"INSERT INTO volumes "
				"(VolUUID, Volpath, Stamp, Depleted) "
				"VALUES('%s','%s','%s',0)",
				db->cnid_sqlite_voluuid_str, vol->v_path, blob))
		{
		if (mysql_errno(db->cnid_sqlite_con) != ER_DUP_ENTRY) {
			LOG(log_error, logtype_cnid,
			    "sqlite query error: %s",
			    sqlite3_errmsg(db->cnid_sqlite_con));
			EC_FAIL;
		}
	}

	/*
	 * Check whether CNID set overflowed before.
	 * If that's the case, in cnid_sqlite_add() we'll ignore the CNID
	 * "hint" taken from the AppleDouble file.
	 */
	if (cnid_sqlite_execute(db->cnid_sqlite_con,
				"SELECT Depleted FROM volumes WHERE VolUUID='%s'",
				db->cnid_sqlite_voluuid_str)) {
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    sqlite3_errmsg(db->cnid_sqlite_con));
		EC_FAIL;
	}
	if ((result = mysql_store_result(db->cnid_sqlite_con)) == NULL) {
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    sqlite3_errmsg(db->cnid_sqlite_con));
		errno = CNID_ERR_DB;
		EC_FAIL;
	}
	if (mysql_num_rows(result)) {
		row = mysql_fetch_row(result);
		int depleted = atoi(row[0]);
		if (depleted)
			db->cnid_mysql_flags |= CNID_MYSQL_FLAG_DEPLETED;
	}
	mysql_free_result(result);
	result = NULL;

	/* Create volume table */
	if (cnid_sqlite_execute(db->cnid_sqlite_con,
				"CREATE TABLE IF NOT EXISTS `%s`"
				"(Id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,"
				"Name VARCHAR(255) NOT NULL,"
				"Did INT UNSIGNED NOT NULL,"
				"DevNo BIGINT UNSIGNED NOT NULL,"
				"InodeNo BIGINT UNSIGNED NOT NULL,"
				"UNIQUE DidName(Did, Name), UNIQUE DevIno(DevNo, InodeNo)) "
				"AUTO_INCREMENT=17",
				db->cnid_sqlite_voluuid_str)) {
		LOG(log_error, logtype_cnid, "sqlite query error: %s",
		    sqlite3_errmsg(db->cnid_sqlite_con));
		EC_FAIL;
	}

	EC_ZERO(init_prepared_stmt(db));

	LOG(log_debug, logtype_cnid,
	    "Finished initializing sqlite CNID module for volume '%s'",
	    vol->v_path);

      EC_CLEANUP:
	if (result)
		mysql_free_result(result);
	if (ret != 0) {
		if (cdb)
			free(cdb);
		cdb = NULL;
		if (db)
			free(db);
	}
	return cdb;
}

struct _cnid_module cnid_sqlite_module = {
	"sqlite",
	{ NULL, NULL },
	cnid_sqlite_open,
	0
};
