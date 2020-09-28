/*
 * directory.C of CEG 433/633 File Sys Project
 * pmateti@wright.edu
 */

#include "fs33types.hpp"

#define iNumber(ptr) (*(ulong *) (ptr + strlen((char *)ptr) + 1))

/* pre:: pfv must point to a proper file volume, in should be > 0;;
 * post:: Construct a directory object, parent == 0 means that on the
 * disk image no changes are made, otherwise yes.
 */

Directory:: Directory(FileVolume * pfv, uint in, uint parent)
{
  fv = pfv;
  dirf = 0;
  dirEntry = 0;
  nInode = in;
  if (parent == 0)
    return;

  fv->fbvInodes.setBit(in, 0); // the inode is in-use
  fv->inodes.setType(in, iTypeDirectory);
  addLeafName((byte *) ".", in);
  addLeafName((byte *) "..", parent);
}

Directory:: ~Directory()
{
  this->namesEnd();
}

/* pre:: dirEntry/dirf may or may not be 0;; post:: Get the next file
 * name + i-number pair from this directory.  Returns ptr to dirEntry,
 * which is a private data member.  Returns 0 when there are no more
 * entries. */

byte * Directory::nextName()
{
  if (dirf == 0)
    dirf = new File(fv, nInode);
  if (dirEntry == 0)
    dirEntry = new byte		// area of mem for file name + i-num
      [fv->superBlock.fileNameLengthMax + 1 + fv->superBlock.iWidth];

  byte * bp = dirEntry;
  while ((*bp = dirf->getNextByte()) != 0)
    bp++ ;
  if (bp == dirEntry)		// end of directory
    return 0;

  for (uint i = 0; i < fv->superBlock.iWidth; i++) // deposit the i-number
    *++bp = dirf->getNextByte();
  return dirEntry;
}

/* Must be called after invocation(s) of nextName(). */

void Directory::namesEnd()
{
  if (dirf) delete dirf;
  if (dirEntry) delete dirEntry;
  dirf = 0;
  dirEntry = 0;
}

/* pre:: in may or may not be in this directory;; post:: If in is in
 * this dir, set dirEntry[] so that it contains the file name +
 * i-number. If in is not there, dirEntry[0] == 0. */

byte * Directory::nameOf(uint in)
{
  byte *bp = 0;
  while ((bp = nextName()) != 0) {
    if (in == iNumber(bp))
      break;
  }
  namesEnd();
  return bp;
}

/* pre:: ;; post:: Search directory and set dirEntry matching with
 * leafnm.  Return inumber.  Callers wish to use dirf and dirEntry
 * further; do not do namesEnd(). */

uint Directory::setDirEntry(byte *leafnm)
{
  if (leafnm == 0 || leafnm[0] == 0)
    return 0;

  uint nbToMatch = 1 + strlen((char *) leafnm), result = 0;
  for (byte * bp = 0; (bp = nextName());) {
    if (memcmp(bp, leafnm, nbToMatch) == 0) {
      result = iNumber(bp);
      break;
    }
  }
  return result;
}

uint  Directory::iNumberOf(byte *leafnm)
{
  uint in = setDirEntry(leafnm);
  namesEnd();
  return in;
}

uint okNameSyntax(byte *nm)
{
  return
    nm != 0			// null pointer?
    && nm[0] != 0		// empty "" nm?
    && isAlphaNumDot(nm[0])	// invalid begin char for name?
    && index((char *) nm, '/') == 0	// nm contains a slash?
    ;
}

/* pre:: none;; post:: Add file name newName with its inode number in
 * to this directory. */

void Directory::addLeafName(byte *newName, uint in)
{
  if (in == 0 || okNameSyntax(newName) == 0)
    return;

  // if name is too long, truncate it
  uint newNameLength = strlen((char *) newName);
  if (newNameLength > fv->superBlock.fileNameLengthMax - 1) {
    newNameLength = fv->superBlock.fileNameLengthMax - 1;
    newName[newNameLength] = 0;
  }

  if (setDirEntry(newName) == 0) {
    memcpy(dirEntry, newName, newNameLength + 1);	// append NUL also
    memcpy(dirEntry + newNameLength + 1, &in, fv->superBlock.iWidth);
    dirf->appendBytes
      (dirEntry, newNameLength + 1 + fv->superBlock.iWidth);
  }
  namesEnd();
}

/* pre:: in is valid;; post:: List the directory inode in's content in
 * a manner similar to Unix ls -lia. If printfFlag != 0, output it to
 * stdout.  Return the total number of files.  */

uint Directory::lsPrivate(uint in, uint printfFlag)
{
  uint nFiles = 0;
  Directory *d = new Directory(fv, in, 0);
  for (byte *bp = 0; (bp = d->nextName()); nFiles++) {
    uint in = iNumber(bp);
    if (printfFlag) {
      byte c = (d->fv->inodes.getType(in) == iTypeDirectory? 'd' : '-');
      printf("%7d %crw-rw-rw-    1 yourName yourGroup %7d Jul 15 12:34 %s\n",
	     in, c, d->fv->inodes.getFileSize(in), bp);
    }
  }
  delete d;
  return nFiles - 2;		// -2 because of "." and ".."
}

uint Directory::ls()
{
  return lsPrivate(nInode, 1);	// 1 ==> printf it
}

uint Directory::createFile(byte *leafnm, uint dirFlag)
{
  uint in = iNumberOf(leafnm);
  if (in  == 0) {
    in = fv->inodes.getFree();
    if (in > 0) {
      addLeafName(leafnm, in);
      if (dirFlag)
	delete new Directory(fv, in, nInode);
      else
	fv->inodes.setType(in, iTypeOrdinary);
    }
  }
  return in;
}

/* Do not delete if it is dot or dotdot.  Do not delete if it is a
 * non-empty dir. */

uint Directory::deleteFile(byte *leafnm, uint freeInodeFlag)
{
  if (strcmp((char *) leafnm, ".") == 0 ||
      strcmp((char *) leafnm, "..") == 0) return 0;

  uint in = setDirEntry(leafnm);
  if (in > 0) {
    dirf->deletePrecedingBytes
      (1 + strlen((char *) leafnm) + fv->superBlock.iWidth);
    if (freeInodeFlag) fv->inodes.setFree(in);
  }
  return in;
}

/* pre:: pn is a dir inode, leafnm != 0, leafnm[0] != 0;; post:: Move
 * file named leafnm whose current parent is pn into this directory.;;
 */

uint Directory::moveFile(uint pn, byte * leafnm)
{
  return TODO("Directory::moveFile");
}

// -eof-
