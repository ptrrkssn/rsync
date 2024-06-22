/*
 * Generalized NFS4/ZFS/SMB/OSX Transport-neutral ACLs for Rsync
 * 
 * Author: Peter Eriksson <pen@lysator.liu.se>
 *
 * This defines a transport-neutral format for sending ACLs over the wire
 * in order to facilitate transfers of NFSv4 ACLs between different operating
 * systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * with this program; if not, visit the http://fsf.org website.
 */

#ifndef RSYNC_STDACLS_H
#define RSYNC_STDACLS_H 1

/*
 * ACL brands supported
 */

#define _SMB_ACL_BRAND_UNKNOWN            0
#define _SMB_ACL_BRAND_POSIX              1
#define _SMB_ACL_BRAND_NFS4               2

typedef enum {
  SMB_ACL_BRAND_UNKNOWN = _SMB_ACL_BRAND_UNKNOWN,
  SMB_ACL_BRAND_POSIX   = _SMB_ACL_BRAND_POSIX,
  SMB_ACL_BRAND_NFS4    = _SMB_ACL_BRAND_NFS4,
} SMB_ACL_BRAND_T;


/*
 * ACL types supported
 */
#define _SMB_ACL_TYPE_UNKNOWN             0
#define _SMB_ACL_TYPE_ACCESS              1 /* POSIX.1e */
#define _SMB_ACL_TYPE_DEFAULT             2 /* POSIX.1e */
#define _SMB_ACL_TYPE_NFS4                3 /* NFSv4/ZFS/Extended(OSX)/SMB */

typedef enum {
  SMB_ACL_TYPE_UNKNOWN  = _SMB_ACL_TYPE_UNKNOWN,
  SMB_ACL_TYPE_ACCESS   = _SMB_ACL_TYPE_ACCESS,
  SMB_ACL_TYPE_DEFAULT  = _SMB_ACL_TYPE_DEFAULT,
  SMB_ACL_TYPE_NFS4     = _SMB_ACL_TYPE_NFS4,
} SMB_ACL_TYPE_T;



/*
 * ACE (ACL Entry) permissions, tags and types supported
 */

/* POSIX.1e uses PERM_R, PERM_W and PERM_X permissions (bits 0-2) */
#define _SMB_ACE_PERM_X                   (1<<0)  /* Execute / Traverse */
#define _SMB_ACE_PERM_W                   (1<<1)  /* Write Data / Add File */
#define _SMB_ACE_PERM_R                   (1<<2)  /* Read Data / List Directory */
#define SMB_ACE_PERM_POSIX_BITS           (7<<0)

/* NFSv4 ACLs uses the three POSIX permissions, plus the ones below (bits 3-13) */
#define _SMB_ACE_PERM_AD                  (1<<3)  /* Append Data / Add Subdirectory */
#define _SMB_ACE_PERM_REA                 (1<<4)  /* Read Extended(Named) Attributes */
#define _SMB_ACE_PERM_WEA                 (1<<5)  /* Write Extended(Named) Attributes */
#define _SMB_ACE_PERM_DC                  (1<<6)  /* Delete Child */
#define _SMB_ACE_PERM_RA                  (1<<7)  /* Read Attributes */
#define _SMB_ACE_PERM_WA                  (1<<8)  /* Write Attributes */
#define _SMB_ACE_PERM_D                   (1<<9)  /* Delete */
#define _SMB_ACE_PERM_RC                  (1<<10) /* Read ACL */
#define _SMB_ACE_PERM_WDAC                (1<<11) /* Write ACL */
#define _SMB_ACE_PERM_WO                  (1<<12) /* Write Owner */
#define _SMB_ACE_PERM_S                   (1<<13) /* Synchronize */
#define SMB_ACE_PERM_NFS4_BITS            ((1<<14)-1)

/* NFSv4 ACE tags (bits 14-16) */
#define _SMB_ACE_TAG_UNDEFINED            (0<<14)
#define _SMB_ACE_TAG_USER_OBJ             (1<<14)
#define _SMB_ACE_TAG_USER                 (2<<14)
#define _SMB_ACE_TAG_GROUP_OBJ            (3<<14)
#define _SMB_ACE_TAG_GROUP                (4<<14)
#define _SMB_ACE_TAG_OTHER                (5<<14) /* POSIX.1e */
#define _SMB_ACE_TAG_MASK                 (6<<14) /* POSIX.1e */
#define _SMB_ACE_TAG_EVERYONE             (7<<14)
#define SMB_ACE_TAG_BITS                  (7<<14)

/* NFSv4 ACE types (bits 17-18) */
#define _SMB_ACE_TYPE_ALLOW               (0<<17)
#define _SMB_ACE_TYPE_DENY                (1<<17)
#define _SMB_ACE_TYPE_AUDIT               (2<<17)
#define _SMB_ACE_TYPE_ALARM               (3<<17)
#define SMB_ACE_TYPE_BITS                 (3<<17)

/* NFSv4 ACE flags (19-25) */
#define _SMB_ACE_FLAG_OI                  (1<<19) /* Object(File) Inherit */
#define _SMB_ACE_FLAG_CI                  (1<<20) /* Container(Directory) Inherit */ 
#define _SMB_ACE_FLAG_NI                  (1<<21) /* No Propagate Inherit */
#define _SMB_ACE_FLAG_IO                  (1<<22) /* Inherit Only */
#define _SMB_ACE_FLAG_I                   (1<<23) /* Inherited */
#define _SMB_ACE_FLAG_SA                  (1<<24) /* Successful Access */
#define _SMB_ACE_FLAG_FA                  (1<<25) /* Failed Access */
#define SMB_ACE_FLAG_BITS                 (127<<19)

/* Top 6 bits are reserved for now (26-31) */
#define SMB_ACE_VALID_BITS                ((1<<26)-1)

typedef uint32 SMB_ACE_BITS_T;

typedef enum {
  SMB_ACE_PERM_X                   = _SMB_ACE_PERM_X,
  SMB_ACE_PERM_W                   = _SMB_ACE_PERM_W,
  SMB_ACE_PERM_R                   = _SMB_ACE_PERM_R,
  SMB_ACE_PERM_AD                  = _SMB_ACE_PERM_AD,
  SMB_ACE_PERM_REA                 = _SMB_ACE_PERM_REA,
  SMB_ACE_PERM_WEA                 = _SMB_ACE_PERM_WEA,
  SMB_ACE_PERM_DC                  = _SMB_ACE_PERM_DC,
  SMB_ACE_PERM_RA                  = _SMB_ACE_PERM_RA,
  SMB_ACE_PERM_WA                  = _SMB_ACE_PERM_WA,
  SMB_ACE_PERM_D                   = _SMB_ACE_PERM_D,
  SMB_ACE_PERM_RC                  = _SMB_ACE_PERM_RC,
  SMB_ACE_PERM_WDAC                = _SMB_ACE_PERM_WDAC,
  SMB_ACE_PERM_WO                  = _SMB_ACE_PERM_WO,
  SMB_ACE_PERM_S                   = _SMB_ACE_PERM_S,
} SMB_ACE_PERM_T;

typedef enum {
  SMB_ACE_TAG_UNDEFINED            = _SMB_ACE_TAG_UNDEFINED,
  SMB_ACE_TAG_USER_OBJ             = _SMB_ACE_TAG_USER_OBJ,
  SMB_ACE_TAG_USER                 = _SMB_ACE_TAG_USER,
  SMB_ACE_TAG_GROUP_OBJ            = _SMB_ACE_TAG_GROUP_OBJ,
  SMB_ACE_TAG_GROUP                = _SMB_ACE_TAG_GROUP,
  SMB_ACE_TAG_OTHER                = _SMB_ACE_TAG_OTHER,
  SMB_ACE_TAG_MASK                 = _SMB_ACE_TAG_MASK,
  SMB_ACE_TAG_EVERYONE             = _SMB_ACE_TAG_EVERYONE,
} SMB_ACE_TAG_T;

typedef enum {
  SMB_ACE_TYPE_ALLOW               = _SMB_ACE_TYPE_ALLOW,
  SMB_ACE_TYPE_DENY                = _SMB_ACE_TYPE_DENY,
  SMB_ACE_TYPE_AUDIT               = _SMB_ACE_TYPE_AUDIT,
  SMB_ACE_TYPE_ALARM               = _SMB_ACE_TYPE_ALARM,
} SMB_ACE_TYPE_T;

typedef enum {
  SMB_ACE_FLAG_OI                  = _SMB_ACE_FLAG_OI,
  SMB_ACE_FLAG_CI                  = _SMB_ACE_FLAG_CI,
  SMB_ACE_FLAG_NI                  = _SMB_ACE_FLAG_NI,
  SMB_ACE_FLAG_IO                  = _SMB_ACE_FLAG_IO,
  SMB_ACE_FLAG_I                   = _SMB_ACE_FLAG_I,
  SMB_ACE_FLAG_SA                  = _SMB_ACE_FLAG_SA,
  SMB_ACE_FLAG_FA                  = _SMB_ACE_FLAG_FA,
} SMB_ACE_FLAG_T;

typedef struct {
	uint32_t rsync;
	uint32_t impl;
} SMB_ACEMAP_T;

#define SMB_ACEMAP_ENTRIES(m)    (sizeof(m)/sizeof(m[0]))

#endif
