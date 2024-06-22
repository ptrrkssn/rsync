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

#define _RSYNC_ACL_BRAND_UNKNOWN            0
#define _RSYNC_ACL_BRAND_POSIX              1
#define _RSYNC_ACL_BRAND_NFS4               2

typedef enum {
  RSYNC_ACL_BRAND_UNKNOWN = _RSYNC_ACL_BRAND_UNKNOWN,
  RSYNC_ACL_BRAND_POSIX   = _RSYNC_ACL_BRAND_POSIX,
  RSYNC_ACL_BRAND_NFS4    = _RSYNC_ACL_BRAND_NFS4,
} RSYNC_ACL_BRAND_T;


/*
 * ACL types supported
 */
#define _RSYNC_ACL_TYPE_UNKNOWN             0
#define _RSYNC_ACL_TYPE_ACCESS              1 /* POSIX.1e */
#define _RSYNC_ACL_TYPE_DEFAULT             2 /* POSIX.1e */
#define _RSYNC_ACL_TYPE_NFS4                3 /* NFSv4/ZFS/Extended(OSX)/SMB */

typedef enum {
  RSYNC_ACL_TYPE_UNKNOWN  = _RSYNC_ACL_TYPE_UNKNOWN,
  RSYNC_ACL_TYPE_ACCESS   = _RSYNC_ACL_TYPE_ACCESS,
  RSYNC_ACL_TYPE_DEFAULT  = _RSYNC_ACL_TYPE_DEFAULT,
  RSYNC_ACL_TYPE_NFS4     = _RSYNC_ACL_TYPE_NFS4,
} RSYNC_ACL_TYPE_T;



/*
 * ACE (ACL Entry) permissions, tags and types supported
 */

/* POSIX.1e uses PERM_R, PERM_W and PERM_X permissions (bits 0-2) */
#define _RSYNC_ACE_PERM_X                   (1<<0)  /* Execute / Traverse */
#define _RSYNC_ACE_PERM_W                   (1<<1)  /* Write Data / Add File */
#define _RSYNC_ACE_PERM_R                   (1<<2)  /* Read Data / List Directory */
#define RSYNC_ACE_PERM_POSIX_BITS           (7<<0)

/* NFSv4 ACLs uses the three POSIX permissions, plus the ones below (bits 3-13) */
#define _RSYNC_ACE_PERM_AD                  (1<<3)  /* Append Data / Add Subdirectory */
#define _RSYNC_ACE_PERM_REA                 (1<<4)  /* Read Extended(Named) Attributes */
#define _RSYNC_ACE_PERM_WEA                 (1<<5)  /* Write Extended(Named) Attributes */
#define _RSYNC_ACE_PERM_DC                  (1<<6)  /* Delete Child */
#define _RSYNC_ACE_PERM_RA                  (1<<7)  /* Read Attributes */
#define _RSYNC_ACE_PERM_WA                  (1<<8)  /* Write Attributes */
#define _RSYNC_ACE_PERM_D                   (1<<9)  /* Delete */
#define _RSYNC_ACE_PERM_RC                  (1<<10) /* Read ACL */
#define _RSYNC_ACE_PERM_WDAC                (1<<11) /* Write ACL */
#define _RSYNC_ACE_PERM_WO                  (1<<12) /* Write Owner */
#define _RSYNC_ACE_PERM_S                   (1<<13) /* Synchronize */
#define RSYNC_ACE_PERM_NFS4_BITS            ((1<<14)-1)

/* NFSv4 ACE tags (bits 14-16) */
#define _RSYNC_ACE_TAG_UNDEFINED            (0<<14)
#define _RSYNC_ACE_TAG_USER_OBJ             (1<<14)
#define _RSYNC_ACE_TAG_USER                 (2<<14)
#define _RSYNC_ACE_TAG_GROUP_OBJ            (3<<14)
#define _RSYNC_ACE_TAG_GROUP                (4<<14)
#define _RSYNC_ACE_TAG_OTHER                (5<<14) /* POSIX.1e */
#define _RSYNC_ACE_TAG_MASK                 (6<<14) /* POSIX.1e */
#define _RSYNC_ACE_TAG_EVERYONE             (7<<14)
#define RSYNC_ACE_TAG_BITS                  (7<<14)

/* NFSv4 ACE types (bits 17-18) */
#define _RSYNC_ACE_TYPE_ALLOW               (0<<17)
#define _RSYNC_ACE_TYPE_DENY                (1<<17)
#define _RSYNC_ACE_TYPE_AUDIT               (2<<17)
#define _RSYNC_ACE_TYPE_ALARM               (3<<17)
#define RSYNC_ACE_TYPE_BITS                 (3<<17)

/* NFSv4 ACE flags (19-25) */
#define _RSYNC_ACE_FLAG_OI                  (1<<19) /* Object(File) Inherit */
#define _RSYNC_ACE_FLAG_CI                  (1<<20) /* Container(Directory) Inherit */ 
#define _RSYNC_ACE_FLAG_NI                  (1<<21) /* No Propagate Inherit */
#define _RSYNC_ACE_FLAG_IO                  (1<<22) /* Inherit Only */
#define _RSYNC_ACE_FLAG_I                   (1<<23) /* Inherited */
#define _RSYNC_ACE_FLAG_SA                  (1<<24) /* Successful Access */
#define _RSYNC_ACE_FLAG_FA                  (1<<25) /* Failed Access */
#define RSYNC_ACE_FLAG_BITS                 (127<<19)

/* Top 6 bits are reserved for now (26-31) */
#define RSYNC_ACE_VALID_BITS                ((1<<26)-1)

typedef uint32 RSYNC_ACE_BITS_T;

typedef enum {
  RSYNC_ACE_PERM_X                   = _RSYNC_ACE_PERM_X,
  RSYNC_ACE_PERM_W                   = _RSYNC_ACE_PERM_W,
  RSYNC_ACE_PERM_R                   = _RSYNC_ACE_PERM_R,
  RSYNC_ACE_PERM_AD                  = _RSYNC_ACE_PERM_AD,
  RSYNC_ACE_PERM_REA                 = _RSYNC_ACE_PERM_REA,
  RSYNC_ACE_PERM_WEA                 = _RSYNC_ACE_PERM_WEA,
  RSYNC_ACE_PERM_DC                  = _RSYNC_ACE_PERM_DC,
  RSYNC_ACE_PERM_RA                  = _RSYNC_ACE_PERM_RA,
  RSYNC_ACE_PERM_WA                  = _RSYNC_ACE_PERM_WA,
  RSYNC_ACE_PERM_D                   = _RSYNC_ACE_PERM_D,
  RSYNC_ACE_PERM_RC                  = _RSYNC_ACE_PERM_RC,
  RSYNC_ACE_PERM_WDAC                = _RSYNC_ACE_PERM_WDAC,
  RSYNC_ACE_PERM_WO                  = _RSYNC_ACE_PERM_WO,
  RSYNC_ACE_PERM_S                   = _RSYNC_ACE_PERM_S,
} RSYNC_ACE_PERM_T;

typedef enum {
  RSYNC_ACE_TAG_UNDEFINED            = _RSYNC_ACE_TAG_UNDEFINED,
  RSYNC_ACE_TAG_USER_OBJ             = _RSYNC_ACE_TAG_USER_OBJ,
  RSYNC_ACE_TAG_USER                 = _RSYNC_ACE_TAG_USER,
  RSYNC_ACE_TAG_GROUP_OBJ            = _RSYNC_ACE_TAG_GROUP_OBJ,
  RSYNC_ACE_TAG_GROUP                = _RSYNC_ACE_TAG_GROUP,
  RSYNC_ACE_TAG_OTHER                = _RSYNC_ACE_TAG_OTHER,
  RSYNC_ACE_TAG_MASK                 = _RSYNC_ACE_TAG_MASK,
  RSYNC_ACE_TAG_EVERYONE             = _RSYNC_ACE_TAG_EVERYONE,
} RSYNC_ACE_TAG_T;

typedef enum {
  RSYNC_ACE_TYPE_ALLOW               = _RSYNC_ACE_TYPE_ALLOW,
  RSYNC_ACE_TYPE_DENY                = _RSYNC_ACE_TYPE_DENY,
  RSYNC_ACE_TYPE_AUDIT               = _RSYNC_ACE_TYPE_AUDIT,
  RSYNC_ACE_TYPE_ALARM               = _RSYNC_ACE_TYPE_ALARM,
} RSYNC_ACE_TYPE_T;

typedef enum {
  RSYNC_ACE_FLAG_OI                  = _RSYNC_ACE_FLAG_OI,
  RSYNC_ACE_FLAG_CI                  = _RSYNC_ACE_FLAG_CI,
  RSYNC_ACE_FLAG_NI                  = _RSYNC_ACE_FLAG_NI,
  RSYNC_ACE_FLAG_IO                  = _RSYNC_ACE_FLAG_IO,
  RSYNC_ACE_FLAG_I                   = _RSYNC_ACE_FLAG_I,
  RSYNC_ACE_FLAG_SA                  = _RSYNC_ACE_FLAG_SA,
  RSYNC_ACE_FLAG_FA                  = _RSYNC_ACE_FLAG_FA,
} RSYNC_ACE_FLAG_T;

typedef struct {
	uint32_t rsync;
	uint32_t impl;
} RSYNC_ACEMAP_T;

#define RSYNC_ACEMAP_ENTRIES(m)    (sizeof(m)/sizeof(m[0]))

#endif
