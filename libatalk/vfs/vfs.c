/*
    Copyright (c) 2004 Didier Gautheron
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include <stdio.h>

#include <atalk/afp.h>    
#include <atalk/adouble.h>
#include <atalk/vfs.h>
#include <atalk/ea.h>
#include <atalk/acl.h>
#include <atalk/logger.h>
#include <atalk/util.h>
#include <atalk/volume.h>
#include <atalk/directory.h>

struct perm {
    uid_t uid;
    gid_t gid;
};

typedef int (*rf_loop)(struct dirent *, char *, void *, int , mode_t );

/* ----------------------------- */
static int 
for_each_adouble(const char *from, const char *name, rf_loop fn, void *data, int flag, mode_t v_umask)
{
    char            buf[ MAXPATHLEN + 1];
    char            *m;
    DIR             *dp;
    struct dirent   *de;
    int             ret;
    

    if (NULL == ( dp = opendir( name)) ) {
        if (!flag) {
            LOG(log_error, logtype_afpd, "%s: opendir %s: %s", from, fullpathname(name),strerror(errno) );
            return -1;
        }
        return 0;
    }
    strlcpy( buf, name, sizeof(buf));
    strlcat( buf, "/", sizeof(buf) );
    m = strchr( buf, '\0' );
    ret = 0;
    while ((de = readdir(dp))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
                continue;
        }
        
        strlcat(buf, de->d_name, sizeof(buf));
        if (fn && (ret = fn(de, buf, data, flag, v_umask))) {
           closedir(dp);
           return ret;
        }
        *m = 0;
    }
    closedir(dp);
    return ret;
}

/*******************************************************************************
 * classic adouble format 
 *******************************************************************************/

static int netatalk_name(const char *name)
{
    return strcasecmp(name,".AppleDB") &&
        strcasecmp(name,".AppleDouble") &&
        strcasecmp(name,".AppleDesktop");
}

static int validupath_adouble(VFS_FUNC_ARGS_VALIDUPATH)
{
    return (vol->v_flags & AFPVOL_USEDOTS) ? 
        netatalk_name(name) && strcasecmp(name,".Parent"): name[0] != '.';
}                                           

/* ----------------- */
static int RF_chown_adouble(VFS_FUNC_ARGS_CHOWN)
{
    struct stat st;
    char        *ad_p;

    ad_p = vol->vfs->ad_path(path, ADFLAGS_HF );

    if ( stat( ad_p, &st ) < 0 )
        return 0; /* ignore */

    return chown( ad_p, uid, gid );
}

/* ----------------- */
static int RF_renamedir_adouble(VFS_FUNC_ARGS_RENAMEDIR)
{
    return 0;
}

/* ----------------- */
static int deletecurdir_adouble_loop(struct dirent *de, char *name, void *data _U_, int flag _U_, mode_t v_umask)
{
    struct stat st;
    int         err;
    
    /* bail if the file exists in the current directory.
     * note: this will not fail with dangling symlinks */
    
    if (stat(de->d_name, &st) == 0)
        return AFPERR_DIRNEMPT;

    if ((err = netatalk_unlink(name)))
        return err;

    return 0;
}

static int RF_deletecurdir_adouble(VFS_FUNC_ARGS_DELETECURDIR)
{
    int err;

    /* delete stray .AppleDouble files. this happens to get .Parent files
       as well. */
    if ((err = for_each_adouble("deletecurdir", ".AppleDouble", deletecurdir_adouble_loop, NULL, 1, vol->v_umask))) 
        return err;
    return netatalk_rmdir( ".AppleDouble" );
}

/* ----------------- */
static int adouble_setfilmode(const char * name, mode_t mode, struct stat *st, mode_t v_umask)
{
    return setfilmode(name, ad_hf_mode(mode), st, v_umask);
}

static int RF_setfilmode_adouble(VFS_FUNC_ARGS_SETFILEMODE)
{
    return adouble_setfilmode(vol->vfs->ad_path( name, ADFLAGS_HF ), mode, st, vol->v_umask);
}

/* ----------------- */
static int RF_setdirunixmode_adouble(VFS_FUNC_ARGS_SETDIRUNIXMODE)
{
    char *adouble = vol->vfs->ad_path( name, ADFLAGS_DIR );
    int  dropbox = vol->v_flags;

    if (dir_rx_set(mode)) {
        if (stickydirmode(ad_dir(adouble), DIRBITS | mode, dropbox, vol->v_umask) < 0 ) 
            return -1;
    }

    if (adouble_setfilmode(vol->vfs->ad_path( name, ADFLAGS_DIR ), mode, st, vol->v_umask) < 0) 
        return -1;

    if (!dir_rx_set(mode)) {
        if (stickydirmode(ad_dir(adouble), DIRBITS | mode, dropbox, vol->v_umask) < 0 ) 
            return  -1 ;
    }
    return 0;
}

/* ----------------- */
static int setdirmode_adouble_loop(struct dirent *de _U_, char *name, void *data, int flag, mode_t v_umask)
{
    mode_t hf_mode = *(mode_t *)data;
    struct stat st;

    if ( stat( name, &st ) < 0 ) {
        if (flag)
            return 0;
        LOG(log_error, logtype_afpd, "setdirmode: stat %s: %s", name, strerror(errno) );
    }
    else if (!S_ISDIR(st.st_mode)) {
        if (setfilmode(name, hf_mode , &st, v_umask) < 0) {
               /* FIXME what do we do then? */
        }
    }
    return 0;
}

static int RF_setdirmode_adouble(VFS_FUNC_ARGS_SETDIRMODE)
{
    int   dropbox = vol->v_flags;
    mode_t hf_mode = ad_hf_mode(mode);
    char  *adouble = vol->vfs->ad_path( name, ADFLAGS_DIR );
    char  *adouble_p = ad_dir(adouble);

    if (dir_rx_set(mode)) {
        if (stickydirmode(ad_dir(adouble), DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return -1;
    }

    if (for_each_adouble("setdirmode", adouble_p, setdirmode_adouble_loop, &hf_mode, vol_noadouble(vol), vol->v_umask))
        return -1;

    if (!dir_rx_set(mode)) {
        if (stickydirmode(ad_dir(adouble), DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return  -1 ;
    }
    return 0;
}

/* ----------------- */
static int setdirowner_adouble_loop(struct dirent *de _U_, char *name, void *data, int flag _U_, mode_t v_umask _U_)
{
    struct perm   *owner  = data;

    if ( chown( name, owner->uid, owner->gid ) < 0 && errno != EPERM ) {
         LOG(log_debug, logtype_afpd, "setdirowner: chown %d/%d %s: %s",
                owner->uid, owner->gid, fullpathname(name), strerror(errno) );
         /* return ( -1 ); Sometimes this is okay */
    }
    return 0;
}

static int RF_setdirowner_adouble(VFS_FUNC_ARGS_SETDIROWNER)
{
    int           noadouble = vol_noadouble(vol);
    char          *adouble_p;
    struct stat   st;
    struct perm   owner;
    
    owner.uid = uid;
    owner.gid = gid;

    adouble_p = ad_dir(vol->vfs->ad_path( name, ADFLAGS_DIR ));

    if (for_each_adouble("setdirowner", adouble_p, setdirowner_adouble_loop, &owner, noadouble, vol->v_umask)) 
        return -1;

    /*
     * We cheat: we know that chown doesn't do anything.
     */
    if ( stat( ".AppleDouble", &st ) < 0) {
        if (errno == ENOENT && noadouble)
            return 0;
        LOG(log_error, logtype_afpd, "setdirowner: stat %s: %s", fullpathname(".AppleDouble"), strerror(errno) );
        return -1;
    }
    if ( gid && gid != st.st_gid && chown( ".AppleDouble", uid, gid ) < 0 && errno != EPERM ) {
        LOG(log_debug, logtype_afpd, "setdirowner: chown %d/%d %s: %s",
            uid, gid,fullpathname(".AppleDouble"), strerror(errno) );
        /* return ( -1 ); Sometimes this is okay */
    }
    return 0;
}

/* ----------------- */
static int RF_deletefile_adouble(VFS_FUNC_ARGS_DELETEFILE)
{
	return netatalk_unlink(vol->vfs->ad_path( file, ADFLAGS_HF));
}

/* ----------------- */
static int RF_renamefile_adouble(VFS_FUNC_ARGS_RENAMEFILE)
{
    char  adsrc[ MAXPATHLEN + 1];
    int   err = 0;

    strcpy( adsrc, vol->vfs->ad_path( src, 0 ));
    if (unix_rename( adsrc, vol->vfs->ad_path( dst, 0 )) < 0) {
        struct stat st;

        err = errno;
        if (errno == ENOENT) {
	        struct adouble    ad;

            if (stat(adsrc, &st)) /* source has no ressource fork, */
                return 0;
            
            /* We are here  because :
             * -there's no dest folder. 
             * -there's no .AppleDouble in the dest folder.
             * if we use the struct adouble passed in parameter it will not
             * create .AppleDouble if the file is already opened, so we
             * use a diff one, it's not a pb,ie it's not the same file, yet.
             */
            ad_init(&ad, vol->v_adouble, vol->v_ad_options); 
            if (!ad_open(dst, ADFLAGS_HF, O_RDWR | O_CREAT, 0666, &ad)) {
            	ad_close(&ad, ADFLAGS_HF);
    	        if (!unix_rename( adsrc, vol->vfs->ad_path( dst, 0 )) ) 
                   err = 0;
                else 
                   err = errno;
            }
            else { /* it's something else, bail out */
	            err = errno;
	        }
	    }
	}
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
}

#ifdef HAVE_NFSv4_ACLS
static int RF_solaris_acl(VFS_FUNC_ARGS_ACL)
{
    static char buf[ MAXPATHLEN + 1];
    struct stat st;

    if ((stat(path, &st)) != 0)
	return -1;
    if (S_ISDIR(st.st_mode)) {
	if ((snprintf(buf, MAXPATHLEN, "%s/.AppleDouble",path)) < 0)
	    return -1;
	/* set acl on .AppleDouble dir first */
	if ((acl(buf, cmd, count, aces)) != 0)
	    return -1;
	/* now set ACL on ressource fork */
	if ((acl(vol->vfs->ad_path(path, ADFLAGS_DIR), cmd, count, aces)) != 0)
	    return -1;
    } else
	/* set ACL on ressource fork */
	if ((acl(vol->vfs->ad_path(path, ADFLAGS_HF), cmd, count, aces)) != 0)
	    return -1;

    return 0;
}

static int RF_solaris_remove_acl(VFS_FUNC_ARGS_REMOVE_ACL)
{
    int ret;
    static char buf[ MAXPATHLEN + 1];

    if (dir) {
	if ((snprintf(buf, MAXPATHLEN, "%s/.AppleDouble",path)) < 0)
	    return AFPERR_MISC;
	/* remove ACL from .AppleDouble/.Parent first */
	if ((ret = remove_acl(vol->vfs->ad_path(path, ADFLAGS_DIR))) != AFP_OK)
	    return ret;
	/* now remove from .AppleDouble dir */
	if ((ret = remove_acl(buf)) != AFP_OK)
	    return ret;
    } else
	/* remove ACL from ressource fork */
	if ((ret = remove_acl(vol->vfs->ad_path(path, ADFLAGS_HF))) != AFP_OK)
	    return ret;

    return AFP_OK;
}
#endif

/*********************************************************************************
 * sfm adouble format
 *********************************************************************************/
static int ads_chown_loop(struct dirent *de _U_, char *name, void *data, int flag _U_, mode_t v_umask _U_)
{
    struct perm   *owner  = data;
    
    if (chown( name , owner->uid, owner->gid ) < 0) {
        return -1;
    }
    return 0;
}

static int RF_chown_ads(VFS_FUNC_ARGS_CHOWN)
{
    struct        stat st;
    char          *ad_p;
    struct perm   owner;
    
    owner.uid = uid;
    owner.gid = gid;


    ad_p = ad_dir(vol->vfs->ad_path(path, ADFLAGS_HF ));

    if ( stat( ad_p, &st ) < 0 ) {
	/* ignore */
        return 0;
    }
    
    if (chown( ad_p, uid, gid ) < 0) {
    	return -1;
    }
    return for_each_adouble("chown_ads", ad_p, ads_chown_loop, &owner, 1, vol->v_umask);
}

/* --------------------------------- */
static int deletecurdir_ads1_loop(struct dirent *de _U_, char *name, void *data _U_, int flag _U_, mode_t v_umask _U_)
{
    return netatalk_unlink(name);
}

static int ads_delete_rf(char *name)
{
    int err;

    if ((err = for_each_adouble("deletecurdir", name, deletecurdir_ads1_loop, NULL, 1, 0))) 
        return err;
    /* FIXME 
     * it's a problem for a nfs mounted folder, there's .nfsxxx around
     * for linux the following line solve it.
     * but it could fail if rm .nfsxxx  create a new .nfsyyy :(
    */
    if ((err = for_each_adouble("deletecurdir", name, deletecurdir_ads1_loop, NULL, 1, 0))) 
        return err;
    return netatalk_rmdir(name);
}

static int deletecurdir_ads_loop(struct dirent *de, char *name, void *data _U_, int flag _U_, mode_t v_umask _U_)
{
    struct stat st;
    
    /* bail if the file exists in the current directory.
     * note: this will not fail with dangling symlinks */
    
    if (stat(de->d_name, &st) == 0) {
        return AFPERR_DIRNEMPT;
    }
    return ads_delete_rf(name);
}

static int RF_deletecurdir_ads(VFS_FUNC_ARGS_DELETECURDIR)
{
    int err;
    
    /* delete stray .AppleDouble files. this happens to get .Parent files as well. */
    if ((err = for_each_adouble("deletecurdir", ".AppleDouble", deletecurdir_ads_loop, NULL, 1, 0))) 
        return err;
    return netatalk_rmdir( ".AppleDouble" );
}

/* ------------------- */
struct set_mode {
    mode_t mode;
    struct stat *st;
};

static int ads_setfilmode_loop(struct dirent *de _U_, char *name, void *data, int flag _U_, mode_t v_umask)
{
    struct set_mode *param = data;

    return setfilmode(name, param->mode, param->st, v_umask);
}

static int ads_setfilmode(const char * name, mode_t mode, struct stat *st, mode_t v_umask)
{
    mode_t file_mode = ad_hf_mode(mode);
    mode_t dir_mode = file_mode;
    struct set_mode param;

    if ((dir_mode & (S_IRUSR | S_IWUSR )))
        dir_mode |= S_IXUSR;
    if ((dir_mode & (S_IRGRP | S_IWGRP )))
        dir_mode |= S_IXGRP;
    if ((dir_mode & (S_IROTH | S_IWOTH )))
        dir_mode |= S_IXOTH;	
    
	/* change folder */
	dir_mode |= DIRBITS;
    if (dir_rx_set(dir_mode)) {
        if (chmod( name,  dir_mode ) < 0)
            return -1;
    }
    param.st = st;
    param.mode = file_mode;
    if (for_each_adouble("setfilmode_ads", name, ads_setfilmode_loop, &param, 0, v_umask) < 0)
        return -1;

    if (!dir_rx_set(dir_mode)) {
        if (chmod( name,  dir_mode ) < 0)
            return -1;
    }

    return 0;
}

static int RF_setfilmode_ads(VFS_FUNC_ARGS_SETFILEMODE)
{
    return ads_setfilmode(ad_dir(vol->vfs->ad_path( name, ADFLAGS_HF )), mode, st, vol->v_umask);
}

/* ------------------- */
static int RF_setdirunixmode_ads(VFS_FUNC_ARGS_SETDIRUNIXMODE)
{
    char *adouble = vol->vfs->ad_path( name, ADFLAGS_DIR );
    char   ad_p[ MAXPATHLEN + 1];
    int dropbox = vol->v_flags;

    strlcpy(ad_p,ad_dir(adouble), MAXPATHLEN + 1);

    if (dir_rx_set(mode)) {

        /* .AppleDouble */
        if (stickydirmode(ad_dir(ad_p), DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return -1;

        /* .AppleDouble/.Parent */
        if (stickydirmode(ad_p, DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return -1;
    }

    if (ads_setfilmode(ad_dir(vol->vfs->ad_path( name, ADFLAGS_DIR)), mode, st, vol->v_umask) < 0)
        return -1;

    if (!dir_rx_set(mode)) {
        if (stickydirmode(ad_p, DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return  -1 ;
        if (stickydirmode(ad_dir(ad_p), DIRBITS | mode, dropbox, vol->v_umask) < 0) 
            return -1;
    }
    return 0;
}

/* ------------------- */
struct dir_mode {
    mode_t mode;
    int    dropbox;
};

static int setdirmode_ads_loop(struct dirent *de _U_, char *name, void *data, int flag, mode_t v_umask)
{

    struct dir_mode *param = data;
    int    ret = 0; /* 0 ignore error, -1 */

    if (dir_rx_set(param->mode)) {
        if (stickydirmode(name, DIRBITS | param->mode, param->dropbox, v_umask) < 0) {
            if (flag) {
                return 0;
            }
            return ret;
        }
    }
    if (ads_setfilmode(name, param->mode, NULL, v_umask) < 0)
        return ret;

    if (!dir_rx_set(param->mode)) {
        if (stickydirmode(name, DIRBITS | param->mode, param->dropbox, v_umask) < 0) {
            if (flag) {
                return 0;
            }
            return ret;
        }
    }
    return 0;
}

static int RF_setdirmode_ads(VFS_FUNC_ARGS_SETDIRMODE)
{
    char *adouble = vol->vfs->ad_path( name, ADFLAGS_DIR );
    char   ad_p[ MAXPATHLEN + 1];
    struct dir_mode param;

    param.mode = mode;
    param.dropbox = vol->v_flags;

    strlcpy(ad_p,ad_dir(adouble), sizeof(ad_p));

    if (dir_rx_set(mode)) {
        /* .AppleDouble */
        if (stickydirmode(ad_dir(ad_p), DIRBITS | mode, param.dropbox, vol->v_umask) < 0) 
            return -1;
    }

    if (for_each_adouble("setdirmode_ads", ad_dir(ad_p), setdirmode_ads_loop, &param, vol_noadouble(vol), vol->v_umask))
        return -1;

    if (!dir_rx_set(mode)) {
        if (stickydirmode(ad_dir(ad_p), DIRBITS | mode, param.dropbox, vol->v_umask) < 0 ) 
            return -1;
    }
    return 0;
}

/* ------------------- */
static int setdirowner_ads1_loop(struct dirent *de _U_, char *name, void *data, int flag _U_, mode_t v_umask _U_)
{
    struct perm   *owner  = data;

    if ( chown( name, owner->uid, owner->gid ) < 0 && errno != EPERM ) {
         LOG(log_debug, logtype_afpd, "setdirowner: chown %d/%d %s: %s",
                owner->uid, owner->gid, fullpathname(name), strerror(errno) );
         /* return ( -1 ); Sometimes this is okay */
    }
    return 0;
}

static int setdirowner_ads_loop(struct dirent *de _U_, char *name, void *data, int flag, mode_t v_umask _U_)
{
    struct perm   *owner  = data;

    if (for_each_adouble("setdirowner", name, setdirowner_ads1_loop, data, flag, 0) < 0)
        return -1;

    if ( chown( name, owner->uid, owner->gid ) < 0 && errno != EPERM ) {
         LOG(log_debug, logtype_afpd, "setdirowner: chown %d/%d %s: %s",
                owner->uid, owner->gid, fullpathname(name), strerror(errno) );
         /* return ( -1 ); Sometimes this is okay */
    }
    return 0;
}

static int RF_setdirowner_ads(VFS_FUNC_ARGS_SETDIROWNER)
{
    int           noadouble = vol_noadouble(vol);
    char          adouble_p[ MAXPATHLEN + 1];
    struct stat   st;
    struct perm   owner;
    
    owner.uid = uid;
    owner.gid = gid;

    strlcpy(adouble_p, ad_dir(vol->vfs->ad_path( name, ADFLAGS_DIR )), sizeof(adouble_p));

    if (for_each_adouble("setdirowner", ad_dir(adouble_p), setdirowner_ads_loop, &owner, noadouble, 0)) 
        return -1;

    /*
     * We cheat: we know that chown doesn't do anything.
     */
    if ( stat( ".AppleDouble", &st ) < 0) {
        if (errno == ENOENT && noadouble)
            return 0;
        LOG(log_error, logtype_afpd, "setdirowner: stat %s: %s", fullpathname(".AppleDouble"), strerror(errno) );
        return -1;
    }
    if ( gid && gid != st.st_gid && chown( ".AppleDouble", uid, gid ) < 0 && errno != EPERM ) {
        LOG(log_debug, logtype_afpd, "setdirowner: chown %d/%d %s: %s",
            uid, gid,fullpathname(".AppleDouble"), strerror(errno) );
        /* return ( -1 ); Sometimes this is okay */
    }
    return 0;
}

/* ------------------- */
static int RF_deletefile_ads(VFS_FUNC_ARGS_DELETEFILE)
{
    char *ad_p = ad_dir(vol->vfs->ad_path(file, ADFLAGS_HF ));

    return ads_delete_rf(ad_p);
}

/* --------------------------- */
static int RF_renamefile_ads(VFS_FUNC_ARGS_RENAMEFILE)
{
    char  adsrc[ MAXPATHLEN + 1];
    int   err = 0;

    strcpy( adsrc, ad_dir(vol->vfs->ad_path( src, 0 )));
    if (unix_rename( adsrc, ad_dir(vol->vfs->ad_path( dst, 0 ))) < 0) {
        struct stat st;

        err = errno;
        if (errno == ENOENT) {
	        struct adouble    ad;

            if (stat(adsrc, &st)) /* source has no ressource fork, */
                return 0;
            
            /* We are here  because :
             * -there's no dest folder. 
             * -there's no .AppleDouble in the dest folder.
             * if we use the struct adouble passed in parameter it will not
             * create .AppleDouble if the file is already opened, so we
             * use a diff one, it's not a pb,ie it's not the same file, yet.
             */
            ad_init(&ad, vol->v_adouble, vol->v_ad_options); 
            if (!ad_open(dst, ADFLAGS_HF, O_RDWR | O_CREAT, 0666, &ad)) {
            	ad_close(&ad, ADFLAGS_HF);

            	/* We must delete it */
            	RF_deletefile_ads(vol, dst );
    	        if (!unix_rename( adsrc, ad_dir(vol->vfs->ad_path( dst, 0 ))) ) 
                   err = 0;
                else 
                   err = errno;
            }
            else { /* it's something else, bail out */
	            err = errno;
	        }
	    }
	}
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
}

/*************************************************************************
 * osx adouble format 
 ************************************************************************/
static int validupath_osx(VFS_FUNC_ARGS_VALIDUPATH)
{
    return strncmp(name,"._", 2) && (
      (vol->v_flags & AFPVOL_USEDOTS) ? netatalk_name(name): name[0] != '.');
}             

/* ---------------- */
static int RF_renamedir_osx(VFS_FUNC_ARGS_RENAMEDIR)
{
    /* We simply move the corresponding ad file as well */
    char   tempbuf[258]="._";
    return rename(vol->vfs->ad_path(oldpath,0),strcat(tempbuf,newpath));
}

/* ---------------- */
static int RF_deletecurdir_osx(VFS_FUNC_ARGS_DELETECURDIR)
{
    return netatalk_unlink( vol->vfs->ad_path(".",0) );
}

/* ---------------- */
static int RF_setdirunixmode_osx(VFS_FUNC_ARGS_SETDIRUNIXMODE)
{
    return adouble_setfilmode(vol->vfs->ad_path( name, ADFLAGS_DIR ), mode, st, vol->v_umask);
}

/* ---------------- */
static int RF_setdirmode_osx(VFS_FUNC_ARGS_SETDIRMODE)
{
    return 0;
}

/* ---------------- */
static int RF_setdirowner_osx(VFS_FUNC_ARGS_SETDIROWNER)
{
	return 0;
}

/* ---------------- */
static int RF_renamefile_osx(VFS_FUNC_ARGS_RENAMEFILE)
{
    char  adsrc[ MAXPATHLEN + 1];
    int   err = 0;

    strcpy( adsrc, vol->vfs->ad_path( src, 0 ));

    if (unix_rename( adsrc, vol->vfs->ad_path( dst, 0 )) < 0) {
        struct stat st;

        err = errno;
        if (errno == ENOENT && stat(adsrc, &st)) /* source has no ressource fork, */
            return 0;
        errno = err;
        return -1;
    }
    return 0;
}

/********************************************************************************************
 * VFS chaining
 ********************************************************************************************/

/* 
 * Up until we really start stacking many VFS modules on top of one another or use
 * dynamic module loading like we do for UAMs, up until then we just stack VFS modules
 * via an fixed size array.
 * All VFS funcs must return AFP_ERR codes. When a func in the chain returns an error
 * this error code will be returned to the caller, BUT the chain in followed and all
 * following funcs are called in order to give them a chance.
 */

/* 
 * Currently the maximum will be:
 * main adouble module + EA module + ACL module + NULL = 4.
 * NULL is an end of array marker.
 */
static struct vfs_ops *vfs[4] = { NULL };

/* 
 * Define most VFS funcs with macros as they all do the same.
 * Only "ad_path" and "validupath" will NOT do stacking and only
 * call the func from the first module.
 */
#define VFS_MFUNC(name, args, vars) \
    static int vfs_ ## name(args) \
    { \
        int i = 0, ret = AFP_OK, err; \
        while (vfs[i]) { \
            if (vfs[i]->vfs_ ## name) { \
                err = vfs[i]->vfs_ ## name (vars); \
                if ((ret == AFP_OK) && (err != AFP_OK)) \
                    ret = err; \
            } \
            i ++; \
        } \
        return ret; \
    }

VFS_MFUNC(chown, VFS_FUNC_ARGS_CHOWN, VFS_FUNC_VARS_CHOWN)
VFS_MFUNC(renamedir, VFS_FUNC_ARGS_RENAMEDIR, VFS_FUNC_VARS_RENAMEDIR) 
VFS_MFUNC(deletecurdir, VFS_FUNC_ARGS_DELETECURDIR, VFS_FUNC_VARS_DELETECURDIR)
VFS_MFUNC(setfilmode, VFS_FUNC_ARGS_SETFILEMODE, VFS_FUNC_VARS_SETFILEMODE)
VFS_MFUNC(setdirmode, VFS_FUNC_ARGS_SETDIRMODE, VFS_FUNC_VARS_SETDIRMODE)
VFS_MFUNC(setdirunixmode, VFS_FUNC_ARGS_SETDIRUNIXMODE, VFS_FUNC_VARS_SETDIRUNIXMODE)
VFS_MFUNC(setdirowner, VFS_FUNC_ARGS_SETDIROWNER, VFS_FUNC_VARS_SETDIROWNER)
VFS_MFUNC(deletefile, VFS_FUNC_ARGS_DELETEFILE, VFS_FUNC_VARS_DELETEFILE)
VFS_MFUNC(renamefile, VFS_FUNC_ARGS_RENAMEFILE, VFS_FUNC_VARS_RENAMEFILE)
VFS_MFUNC(acl, VFS_FUNC_ARGS_ACL, VFS_FUNC_VARS_ACL)
VFS_MFUNC(remove_acl, VFS_FUNC_ARGS_REMOVE_ACL, VFS_FUNC_VARS_REMOVE_ACL)
VFS_MFUNC(ea_getsize, VFS_FUNC_ARGS_EA_GETSIZE, VFS_FUNC_VARS_EA_GETSIZE)
VFS_MFUNC(ea_getcontent, VFS_FUNC_ARGS_EA_GETCONTENT, VFS_FUNC_VARS_EA_GETCONTENT)
VFS_MFUNC(ea_list, VFS_FUNC_ARGS_EA_LIST, VFS_FUNC_VARS_EA_LIST)
VFS_MFUNC(ea_set, VFS_FUNC_ARGS_EA_SET, VFS_FUNC_VARS_EA_SET)
VFS_MFUNC(ea_remove, VFS_FUNC_ARGS_EA_REMOVE, VFS_FUNC_VARS_EA_REMOVE)

static char *vfs_path(const char *path, int flags)
{
    return vfs[0]->ad_path(path, flags);
}

static int vfs_validupath(VFS_FUNC_ARGS_VALIDUPATH)
{
    return vfs[0]->vfs_validupath(VFS_FUNC_VARS_VALIDUPATH);
}

/*
 * These function pointers get called from the lib users via vol->vfs->func.
 * These funcs are defined via the macros above.
 */
struct vfs_ops vfs_master_funcs = {
    vfs_path,
    vfs_validupath,
    vfs_chown,
    vfs_renamedir,
    vfs_deletecurdir,
    vfs_setfilmode,
    vfs_setdirmode,
    vfs_setdirunixmode,
    vfs_setdirowner,
    vfs_deletefile,
    vfs_renamefile,
    vfs_acl,
    vfs_remove_acl,
    vfs_ea_getsize,
    vfs_ea_getcontent,
    vfs_ea_list,
    vfs_ea_set,
    vfs_ea_remove
};

/* 
 * Primary adouble modules: default, osx, sfm
 */

static struct vfs_ops netatalk_adouble = {
    /* ad_path:           */ ad_path,
    /* validupath:        */ validupath_adouble,
    /* rf_chown:          */ RF_chown_adouble,
    /* rf_renamedir:      */ RF_renamedir_adouble,
    /* rf_deletecurdir:   */ RF_deletecurdir_adouble,
    /* rf_setfilmode:     */ RF_setfilmode_adouble,
    /* rf_setdirmode:     */ RF_setdirmode_adouble,
    /* rf_setdirunixmode: */ RF_setdirunixmode_adouble,
    /* rf_setdirowner:    */ RF_setdirowner_adouble,
    /* rf_deletefile:     */ RF_deletefile_adouble,
    /* rf_renamefile:     */ RF_renamefile_adouble,
};

static struct vfs_ops netatalk_adouble_osx = {
    /* ad_path:          */ ad_path_osx,
    /* validupath:       */ validupath_osx,
    /* rf_chown:         */ RF_chown_adouble,
    /* rf_renamedir:     */ RF_renamedir_osx,
    /* rf_deletecurdir:  */ RF_deletecurdir_osx,
    /* rf_setfilmode:    */ RF_setfilmode_adouble,
    /* rf_setdirmode:    */ RF_setdirmode_osx,
    /* rf_setdirunixmode:*/ RF_setdirunixmode_osx,
    /* rf_setdirowner:   */ RF_setdirowner_osx,
    /* rf_deletefile:    */ RF_deletefile_adouble,
    /* rf_renamefile:    */ RF_renamefile_osx,
};

/* samba sfm format. ad_path shouldn't be set her */
static struct vfs_ops netatalk_adouble_sfm = {
    /* ad_path:          */ ad_path_sfm,
    /* validupath:       */ validupath_adouble,
    /* rf_chown:         */ RF_chown_ads,
    /* rf_renamedir:     */ RF_renamedir_adouble,
    /* rf_deletecurdir:  */ RF_deletecurdir_ads,
    /* rf_setfilmode:    */ RF_setfilmode_ads,
    /* rf_setdirmode:    */ RF_setdirmode_ads,
    /* rf_setdirunixmode:*/ RF_setdirunixmode_ads,
    /* rf_setdirowner:   */ RF_setdirowner_ads,
    /* rf_deletefile:    */ RF_deletefile_ads,
    /* rf_renamefile:    */ RF_renamefile_ads,
};

/* 
 * Secondary vfs modules for Extended Attributes
 */

struct vfs_ops netatalk_ea_adouble = {
    /* ad_path:           */ NULL,
    /* validupath:        */ NULL,
    /* rf_chown:          */ NULL,
    /* rf_renamedir:      */ NULL,
    /* rf_deletecurdir:   */ NULL,
    /* rf_setfilmode:     */ NULL,
    /* rf_setdirmode:     */ NULL,
    /* rf_setdirunixmode: */ NULL,
    /* rf_setdirowner:    */ NULL,
    /* rf_deletefile:     */ ea_deletefile,
    /* rf_renamefile:     */ ea_renamefile,
    /* rf_acl:            */ NULL,
    /* rf_remove_acl      */ NULL,
    /* ea_getsize         */ get_easize,
    /* ea_getcontent      */ get_eacontent,
    /* ea_list            */ list_eas,
    /* ea_set             */ set_ea,
    /* ea_remove          */ remove_ea
};

#ifdef HAVE_SOLARIS_EAS
struct vfs_ops netatalk_ea_solaris = {
    /* ad_path:           */ NULL,
    /* validupath:        */ NULL,
    /* rf_chown:          */ NULL,
    /* rf_renamedir:      */ NULL,
    /* rf_deletecurdir:   */ NULL,
    /* rf_setfilmode:     */ NULL,
    /* rf_setdirmode:     */ NULL,
    /* rf_setdirunixmode: */ NULL,
    /* rf_setdirowner:    */ NULL,
    /* rf_deletefile:     */ NULL,
    /* rf_renamefile:     */ NULL,
    /* rf_acl:            */ NULL,
    /* rf_remove_acl      */ NULL,
    /* ea_getsize         */ sol_get_easize,
    /* ea_getcontent      */ sol_get_eacontent,
    /* ea_list            */ sol_list_eas,
    /* ea_set             */ sol_set_ea,
    /* ea_remove          */ sol_remove_ea
};
#endif

/* 
 * Tertiary attributes for ACLs
 */

#ifdef HAVE_NFSv4_ACLS
struct vfs_ops netatalk_solaris_acl_adouble = {
    /* ad_path:           */ NULL,
    /* validupath:        */ NULL,
    /* rf_chown:          */ NULL,
    /* rf_renamedir:      */ NULL,
    /* rf_deletecurdir:   */ NULL,
    /* rf_setfilmode:     */ NULL,
    /* rf_setdirmode:     */ NULL,
    /* rf_setdirunixmode: */ NULL,
    /* rf_setdirowner:    */ NULL,
    /* rf_deletefile:     */ NULL,
    /* rf_renamefile:     */ NULL,
    /* rf_acl:            */ RF_solaris_acl,
    /* rf_remove_acl      */ RF_remove_acl
};
#endif

/* ---------------- */
void initvol_vfs(struct vol *vol)
{
    vol->vfs = &vfs_master_funcs;

    /* Default adouble stuff */
    if (vol->v_adouble == AD_VERSION2_OSX) {
        vfs[0] = &netatalk_adouble_osx;
    }
    else if (vol->v_adouble == AD_VERSION1_SFM) {
        vfs[0] = &netatalk_adouble_sfm;
    }
    else {
        vfs[0] = &netatalk_adouble;
    }

    /* Extended Attributes */
    if (vol->v_vfs_ea == AFPVOL_EA_SOLARIS) {

#ifdef HAVE_SOLARIS_EAS
        LOG(log_debug, logtype_afpd, "initvol_vfs: Enabling EA support with Solaris native EAs.");
        vfs[1] = &netatalk_ea_solaris;
#else
        LOG(log_error, logtype_afpd, "initvol_vfs: Can't enable Solaris EA support.");
        goto enable_adea;
#endif
    } else {
    enable_adea:
        /* default: AFPVOL_EA_AD */
        LOG(log_debug, logtype_afpd, "initvol_vfs: Enabling EA support with adouble files.");
        vfs[1] = &netatalk_ea_adouble;
    }

    /* ACLs */
#ifdef HAVE_NFSv4_ACLS
    vfs[2] = &netatalk_solaris_acl_adouble;
#endif
}
