#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <atalk/util.h>
#include <atalk/adouble.h>
#include <atalk/cnid.h>
#include <atalk/logger.h>

#define FILEIOFF_ATTR 14
#define AFPFILEIOFF_ATTR 2

/* 
   Note:
   the "shared" and "invisible" attributes are opaque and stored and
   retrieved from the FinderFlags. This fixes Bug #2802236:
   <https://sourceforge.net/tracker/?func=detail&aid=2802236&group_id=8642&atid=108642>
 */
int ad_getattr(const struct adouble *ad, u_int16_t * attr)
{
	u_int16_t fflags;
    char *ade = NULL;
	*attr = 0;

	if (ad->ad_version == AD_VERSION1) {
		if (ad_getentryoff(ad, ADEID_FILEI)) {
            ade = ad_entry(ad, ADEID_FILEI);
            AFP_ASSERT(ade != NULL);

            memcpy(attr, ade + FILEIOFF_ATTR, sizeof(u_int16_t));
		}
	}
#if AD_VERSION == AD_VERSION2
	else if (ad->ad_version == AD_VERSION2) {
		if (ad_getentryoff(ad, ADEID_AFPFILEI)) {
            ade = ad_entry(ad, ADEID_AFPFILEI);
            AFP_ASSERT(ade != NULL);

            memcpy(attr, ade + AFPFILEIOFF_ATTR, 2);

			/* Now get opaque flags from FinderInfo */
            ade = ad_entry(ad, ADEID_FINDERI);
            AFP_ASSERT(ade != NULL);

            memcpy(&fflags, ade + FINDERINFO_FRFLAGOFF, 2);

			if (fflags & htons(FINDERINFO_INVISIBLE))
				*attr |= htons(ATTRBIT_INVISIBLE);
			else
				*attr &= htons(~ATTRBIT_INVISIBLE);
			/*
			   This one is tricky, I actually got it wrong the first time:
			   for directories bit 1<<1 is ATTRBIT_EXPFLDR and is NOT opaque !
			 */
			if (!(ad->ad_adflags & ADFLAGS_DIR)) {
				if (fflags & htons(FINDERINFO_ISHARED))
					*attr |= htons(ATTRBIT_MULTIUSER);
				else
					*attr &= htons(~ATTRBIT_MULTIUSER);
			}
		}
	}
#endif
	else
		return -1;

	*attr |= htons(ad->ad_open_forks);

	return 0;
}

/* ----------------- */
int ad_setattr(const struct adouble *ad, const u_int16_t attribute)
{
	uint16_t fflags;
    char *adp = NULL;

	/* we don't save open forks indicator */
	u_int16_t attr = attribute & ~htons(ATTRBIT_DOPEN | ATTRBIT_ROPEN);

	/* Proactively (10.4 does indeed try to set ATTRBIT_MULTIUSER (=ATTRBIT_EXPFLDR)
	   for dirs with SetFile -a M <dir> ) disable all flags not defined for dirs. */
	if (ad->ad_adflags & ADFLAGS_DIR)
		attr &=
		    ~(ATTRBIT_MULTIUSER | ATTRBIT_NOWRITE |
		      ATTRBIT_NOCOPY);

	if (ad->ad_version == AD_VERSION1) {
		if (ad_getentryoff(ad, ADEID_FILEI)) {
            adp = ad_entry(ad, ADEID_FILEI);
            AFP_ASSERT(adp != NULL);

            memcpy(adp + FILEIOFF_ATTR, &attr, sizeof(attr));
		}
	}
#if AD_VERSION == AD_VERSION2
	else if (ad->ad_version == AD_VERSION2) {
		if (ad_getentryoff(ad, ADEID_AFPFILEI)
		    && ad_getentryoff(ad, ADEID_FINDERI)) {
            adp = ad_entry(ad, ADEID_AFPFILEI);
            AFP_ASSERT(adp != NULL);

            memcpy(adp + AFPFILEIOFF_ATTR, &attr, sizeof(attr));

			/* Now set opaque flags in FinderInfo too */
            adp = ad_entry(ad, ADEID_FINDERI);
            AFP_ASSERT(adp != NULL);

            memcpy(&fflags, adp + FINDERINFO_FRFLAGOFF, 2);
			if (attr & htons(ATTRBIT_INVISIBLE))
				fflags |= htons(FINDERINFO_INVISIBLE);
			else
				fflags &= htons(~FINDERINFO_INVISIBLE);

			/* See above comment in ad_getattr() */
			if (attr & htons(ATTRBIT_MULTIUSER)) {
				if (!(ad->ad_adflags & ADFLAGS_DIR))
					fflags |=
					    htons(FINDERINFO_ISHARED);
			} else
				fflags &= htons(~FINDERINFO_ISHARED);

            memcpy(adp + FINDERINFO_FRFLAGOFF, &fflags, 2);
		}
	}
#endif
	else
		return -1;

	return 0;
}

/* --------------
 * save file/folder ID in AppleDoubleV2 netatalk private parameters
 * return 1 if resource fork has been modified
 * return -1 on error.
 */
#if AD_VERSION == AD_VERSION2
int ad_setid(struct adouble *adp, const dev_t dev, const ino_t ino,
	     const u_int32_t id, const cnid_t did, const void *stamp)
{
    char *ade = NULL;
	if ((adp->ad_flags == AD_VERSION2)
	    && (adp->ad_options & ADVOL_CACHE)) {

		/* ad_getid depends on this to detect presence of ALL entries */
		ad_setentrylen(adp, ADEID_PRIVID, sizeof(id));
        ade = ad_entry(adp, ADEID_PRIVID);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_setid: failed to set ADEID_PRIVID\n");
            return -1;
        }
        memcpy(ade, &id, sizeof(id));

		ad_setentrylen(adp, ADEID_PRIVDEV, sizeof(dev_t));
		if ((adp->ad_options & ADVOL_NODEV)) {
			memset(ad_entry(adp, ADEID_PRIVDEV), 0,
			       sizeof(dev_t));
		} else {
            ade = ad_entry(adp, ADEID_PRIVDEV);
                if (ade == NULL) {
                    LOG(log_warning, logtype_default, "ad_setid: failed to set ADEID_PRIVDEV\n");
                    return -1;
            }
            memcpy(ade, &dev, sizeof(dev_t));
		}

		ad_setentrylen(adp, ADEID_PRIVINO, sizeof(ino_t));
        ade = ad_entry(adp, ADEID_PRIVINO);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_setid: failed to set ADEID_PRIVINO\n");
            return -1;
        }
        memcpy(ade, &ino, sizeof(ino_t));

		ad_setentrylen(adp, ADEID_DID, sizeof(did));
        ade = ad_entry(adp, ADEID_DID);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_setid: failed to set ADEID_DID\n");
            return -1;
        }
        memcpy(ade, &did, sizeof(did));

		ad_setentrylen(adp, ADEID_PRIVSYN, ADEDLEN_PRIVSYN);
        ade = ad_entry(adp, ADEID_PRIVSYN);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_setid: failed to set ADEID_PRIVSYN\n");
            return -1;
        }
        memcpy(ade, stamp, ADEDLEN_PRIVSYN);
		return 1;
	}
	return 0;
}

/* ----------------------------- */
/*
 * Retrieve stored file / folder. Callers should treat a return of CNID_INVALID (0) as an invalid value.
 */
u_int32_t ad_getid(struct adouble *adp, const dev_t st_dev,
		   const ino_t st_ino, const cnid_t did, const void *stamp)
{
	u_int32_t aint = 0;
	dev_t dev;
	ino_t ino;
	cnid_t a_did = 0;
	char temp[ADEDLEN_PRIVSYN];
    char *ade = NULL;

	/* look in AD v2 header
	 * note inode and device are opaques and not in network order
	 * only use the ID if adouble is writable for us.
	 */
	if (adp && (adp->ad_options & ADVOL_CACHE)
	    && (adp->ad_md->adf_flags & O_RDWR)
	    && (sizeof(dev_t) == ad_getentrylen(adp, ADEID_PRIVDEV))	/* One check to ensure ALL values are there */
	    ) {
        ade = ad_entry(adp, ADEID_PRIVDEV);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_getid: failed to retrieve ADEID_PRIVDEV\n");
            return CNID_INVALID;
        }
        memcpy(&dev, ade, sizeof(dev_t));
        ade = ad_entry(adp, ADEID_PRIVINO);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_getid: failed to retrieve ADEID_PRIVNO\n");
            return CNID_INVALID;
        }
        memcpy(&ino, ade, sizeof(ino_t));
        ade = ad_entry(adp, ADEID_PRIVSYN);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_getid: failed to retrieve ADEID_PRIVSYN\n");
            return CNID_INVALID;
        }
        memcpy(temp, ade, sizeof(temp));
        ade = ad_entry(adp, ADEID_DID);
        if (ade == NULL) {
            LOG(log_warning, logtype_default, "ad_getid: failed to retrieve ADEID_DID\n");
            return CNID_INVALID;
        }
        memcpy(&a_did, ade, sizeof(cnid_t));

		if (((adp->ad_options & ADVOL_NODEV) || dev == st_dev)
		    && ino == st_ino && (!did || a_did == 0 || a_did == did)
		    && (memcmp(stamp, temp, sizeof(temp)) == 0)) {
            ade = ad_entry(adp, ADEID_PRIVID);
            if (ade == NULL) {
                LOG(log_warning, logtype_default, "ad_getid: failed to retrieve ADEID_PRIVID\n");
                return CNID_INVALID;
            }
            memcpy(&aint, ade, sizeof(aint));
			return aint;
		}
	}
	return CNID_INVALID;
}

/* ----------------------------- */
u_int32_t ad_forcegetid(struct adouble *adp)
{
	u_int32_t aint = 0;
    char *ade = NULL;

	if (adp && (adp->ad_options & ADVOL_CACHE)) {
        ade = ad_entry(adp, ADEID_PRIVID);
        if (ade == NULL) {
            return CNID_INVALID;
        }
        memcpy(&aint, ade, sizeof(aint));
		return aint;
	}
    return CNID_INVALID;
}
#endif

/* -----------------
 * set resource fork filename attribute.
 */
int ad_setname(struct adouble *ad, const char *path)
{
	int len;
    char *ade = NULL;
	if ((len = strlen(path)) > ADEDLEN_NAME)
		len = ADEDLEN_NAME;
	if (path && ad_getentryoff(ad, ADEID_NAME)) {
		ad_setentrylen(ad, ADEID_NAME, len);
        ade = ad_entry(ad, ADEID_NAME);
        if (ade == NULL) {
            return -1;
        }
        memcpy(ade, path, len);
		return 1;
	}
	return 0;
}
