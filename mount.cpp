/*
 * mount.C of CEG433/633 File Sys Project
 * pmateti@wright.edu   */

#include "fs33types.hpp"

/* Limitations:
 1. No volume is mounted more than once:  see whereMounted.
 2. No mount point is used more than once: see whatIsMountedAt.
 3. No check is made that a new mount is made on the path to cwd.  */

MountEntry * mtab = 0;		// ptr to the latest mount entry
VNIN cwdVNIN = mkVNIN(0, 0);	// VNIN -- volume# i#

MountEntry::MountEntry(VNIN awhich, VNIN awhere)
{
  which = awhich;
  where = awhere;
  next = mtab;
  mtab = this;
}

MountEntry::~MountEntry()
{
  if (mtab == this)
    mtab =  mtab->next;
}

VNIN MountEntry::rootVNIN()
{
  return TODO("MountEntry::rootVNIN");
}

VNIN MountEntry::whatIsMountedAt(VNIN vnin)
{
  return TODO("MountEntry::whatIsMountedAt");
}

/* Two loops because there can be a pile of mounts, as in at pnm mount
 * V2, again at pnm mount V4, then V5, ... */

VNIN MountEntry::whereMounted(VNIN vnin)
{
  return TODO("MountEntry::whereMounted");
}

/* post:: Return the VNIN of leafnm[] in the context of vnin;; pre:
 * leafnm != 0 && leafnm[0] != 0 && leafnm has no '/', vnin may be
 * a mount point;; */

VNIN MountEntry::leafNameVNIN(byte *leafnm, VNIN vnin)
{
  return TODO("MountEntry::leafNameVNIN");
}

VNIN MountEntry::parentOf(VNIN vnin)
{
  return leafNameVNIN((byte *) "..", whereMounted(vnin));
}

/* pre:: pathnm[] is a relative or absolute path name string;; post::
 * Return the VNIN of pathnm relative to vnin;;  */

VNIN MountEntry::pathNameVNIN(byte *pathnm, VNIN vnin)
{
  return TODO("MountEntry::pathNameVNIN");
}

uint MountEntry::isDir(VNIN vnin)
{
  return TODO("MountEntry::isDir");
}

void MountEntry::iPathName(VNIN vnin)
{
  TODO("MountEntry::iPathName");
}

byte *MountEntry::pathName(VNIN vnin)
{
  TODO("MountEntry::pathName");
  return 0;
}

/* pre:: pnm != 0, leafnm may == 0;; post:: Return the vi-number of
 * the last parent dir appearing in the pathname pnm.  Return value
 * will be 0 if pnm is invalid.  If leafnm != 0, set *leafnm to point
 * to the leaf name;; */

VNIN MountEntry::lastParentDir(byte *pnm, byte **leafnm)
{
  return TODO("MountEntry::lastParentDir");
}

VNIN MountEntry::createFile(byte *pnm, uint isdir)
{
  return TODO("MountEntry::createFile");
}

/* pre,post:: For youTODO; */

uint MountEntry::write33file(byte *fs33name, byte *unixFilePath)
{
  return TODO("MountEntry::write33file");
}

/* pre,post:: For youTODO; */

uint MountEntry::read33file(byte *unixFilePath, byte *fs33name)
{
  return TODO("MountEntry::read33file");
}

uint MountEntry::copy33file(byte *to33name, byte *from33name)
{
  return TODO("MountEntry::copy33file");
}

/* pre:: pnm != 0, pnm[0] != 0;; post:: Remove the file (ord/dir)
 * named pnm[] from this directory.  Do not delete if it is dot or
 * dotdot.  Do not delete if it is a non-empty dir.  ;; */

uint MountEntry::rm(byte *pathnm, uint freeInodeFlag)
{
  return TODO("MountEntry::rm");
}

uint MountEntry::move(byte *srcPathName, byte *dstPathName)
{
  return TODO("MountEntry::move");
}

VNIN MountEntry::umount(byte *mountPath, uint volNumber)
{
  return TODO("MountEntry::umount");
}

/* pre:: volNumber > 0, mountPath != 0, mountPath[0] != 0;; post::
 * mount the disk of the given number on the mount point
 * mountPath[];;  */

VNIN MountEntry::mount(uint volNumber, byte *mountPath)
{
  return TODO("MountEntry::mount");
}

/* Print the mount table. Return the number of entries in the table.  */

uint MountEntry::print()
{
  return TODO("MountEntry::print");
}

/* Assigns to the global cwdVNIN, if ok. */

VNIN MountEntry::setCwd(byte *pnm)
{
  return TODO("MountEntry::setCwd");
}

/* -eof- */
