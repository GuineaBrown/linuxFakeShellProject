/*
 * volume.C of CEG433/633 File Sys Project
 * pmateti@wright.edu
 */

/*
 * This is an implementation of a P0 FileVolume--it assumes there is
 * only one active volume and a volume has only one (root) directory.
 *
 * In later projects, volumes can have subdirectories and there may be
 * more than one active volume. File operations in that context may
 * need some or all of the following pieces of information.
 *
 * * inumber of directory in which destination lies.
 * * volume number where source file is located.
 * * inumber of directory containing source file.
 *
 */

#include "fs33types.hpp"

/* pre:: Valid psimDisk ;; post:: On the simulated disk identified by
 * psimDisk, construct a new file volume with nInodes and of
 * iHeight. */

FileVolume::FileVolume(SimDisk * psimDisk,
		       uint nInodes, uint iHeight, uint nSecPerBlock)
{
  simDisk = psimDisk;
  memset(&superBlock, 0, sizeof(superBlock));
  if (nInodes == 0 || iHeight < 3 || nSecPerBlock == 0
      || simDisk->nBytesPerSector < sizeof(superBlock))		// too small
    return;

  superBlock.nTotalBlocks = simDisk->nSectorsPerDisk / nSecPerBlock;
  superBlock.nBytesPerBlock = nSecPerBlock * simDisk->nBytesPerSector;
  superBlock.nSecPerBlock = nSecPerBlock;
  superBlock.fileNameLengthMax = psimDisk->nBytesPerSector;	// for now
  superBlock.nBlocksFbvBlocks =
    fbvBlocks.create(this, superBlock.nTotalBlocks, 1);

  superBlock.nBlocksFbvInodes =
    fbvInodes.create(this, nInodes, 1 + superBlock.nBlocksFbvBlocks);
  inodes.create
      (this, 1 + superBlock.nBlocksFbvBlocks + superBlock.nBlocksFbvInodes,
       nInodes, iHeight);

  superBlock.nBlockBeginFiles =
      superBlock.nBlockBeginInodes + superBlock.nBlocksOfInodes;

  byte *bp = new byte[superBlock.nBytesPerBlock];
  memcpy(bp, &superBlock, sizeof(superBlock));
  writeBlock(0, bp);		// write it as block# 0
  delete bp;

  this->root = new Directory(this, 1, 1);
}

// superBlock validity check; can be more elaborate
uint FileVolume::isOK()
{
  return
    (superBlock.nBytesPerBlock ==
     superBlock.nSecPerBlock * simDisk->nBytesPerSector)
    && (superBlock.nTotalBlocks ==
	simDisk->nSectorsPerDisk / superBlock.nSecPerBlock)
    && (superBlock.nBlockBeginFiles ==
	superBlock.nBlockBeginInodes + superBlock.nBlocksOfInodes) ;
}


/* pre:: diskName!=0 && diskNumber==0 or diskName==0 && diskNumber >
 * 0;; post:: Verify that there already is a file volume properly
 * made, and if so re-create the file volume object;; */

FileVolume::FileVolume(uint diskNumber)
{
  memset(&superBlock, 0, sizeof(superBlock));
  simDisk = new SimDisk(0, diskNumber);
  if (simDisk->nSectorsPerDisk == 0)
    return;			// invalid simDisk

  // set this->superBlock from block/sector# 0 of simDisk
  byte *bp = new byte[simDisk->nBytesPerSector];
  simDisk->readSector(0, bp);
  memcpy(&superBlock, bp, sizeof(superBlock));
  delete bp;

  if (isOK() == 0) {
    memset(&superBlock, 0, sizeof(superBlock));
    return;
  }

  fbvBlocks.reCreate(this, superBlock.nTotalBlocks, 1);
  fbvInodes.reCreate(this, superBlock.nInodes,
		     1 + superBlock.nBlocksFbvBlocks);
  inodes.reCreate(this);
}

FileVolume::~FileVolume()
{
  delete simDisk;
}

File * FileVolume::findFile(byte * leafnm)
{
  uint in = this->root->iNumberOf(leafnm);
  File * newf = (in == 0? 0 : new File(this, in));
  return newf;
}

/* pre,post:: For youTODO; */

uint FileVolume::write33file(byte *unixFilePath, byte *fs33leaf)
{
  int unixFd = open((char *) unixFilePath, O_RDONLY);
  if (unixFd < 0) return 0;

  this->root->deleteFile(fs33leaf, 1);  // name may already exist, try deleting

  uint in = this->root->createFile(fs33leaf, 0);

  uint bsz = superBlock.nBytesPerBlock, nBytesWritten = 0, nr;
  File * newf = (in == 0? 0 : new File(this, in));
  if (newf != 0) {
    byte * buf = new byte[bsz];
    for (; (nr = read(unixFd, buf, bsz)); nBytesWritten += nr)
      newf->appendOneBlock(buf, nr);
    delete buf;
    delete newf;
  }
  close(unixFd);
  return nBytesWritten;
}

/* pre,post:: For youTODO; */

uint FileVolume::read33file(byte *fs33leaf, byte *unixFilePath)
{
  int unixFd = creat((char *) unixFilePath, 0600);
  if (unixFd < 0) return 0;

  uint bsz = superBlock.nBytesPerBlock, nBytesWritten = 0, nr, nw, i;
  File * newf = findFile(fs33leaf);
  if (newf != 0) {
    byte * buf = new byte[bsz];
    for (i = 0; (nr = newf->readBlock(i++, buf)); nBytesWritten += nw)
      nw = write(unixFd, buf, nr);
    delete buf;
    delete newf;
  }
  close(unixFd);
  return nBytesWritten;
}

/* pre:: pnm != 0, pnm[0] != 0;; post:: Create a new file named pnm[],
 * and return its i-number.  If one already exists with that name,
 * just return its inumber.  */

File * FileVolume::createFile(byte *pnm, uint dirFlag)
{
  uint fin = 0;
  File * f = findFile(pnm);
  if (f != 0) {
    fin = f->nInode;
  } else {
    fin = this->root->createFile(pnm, dirFlag);
    f =  new File(this, fin);
  }
  return f;
}

/* pre:: pnm != 0, pnm[0] != 0;; post:: Remove the file (ordinary or
 * dir) named pnm[] from this directory. ;; */

uint FileVolume::deleteFile(byte *leafnm)
{
  uint in = this->root->deleteFile(leafnm, 1);
  return in;
}

uint FileVolume::copy33file(byte *srcleaf, byte *dstleaf)
{
  uint nBytesWritten = 0, nr, i;
  uint fwbsz = this->superBlock.nBytesPerBlock;
  File * fi = this->findFile(srcleaf), * fo;
  if (fi != 0 && this->inodes.getType(fi->nInode) == iTypeOrdinary) {
    this->deleteFile(dstleaf);
    fo = this->createFile(dstleaf, 0);
    if (fo != 0) {
      byte * buf = new byte[fwbsz];
      for (i = 0; (nr = fi->readBlock(i++, buf)); nBytesWritten += nr)
        fo->appendBytes(buf, nr); // diff vol, so do not use appendOneBlock
      delete buf;
      delete fo;
    }
    delete fi;
  }
  return nBytesWritten;
}

uint FileVolume::move(uint din, byte *dstleaf,
		      uint wn, uint jn, byte *srcleaf)
{
  return TODO("FileVolume::move");
}

uint FileVolume::rdwrBlock(uint nBlock, void *p, uint writeFlag)
{
  uint nbps = simDisk->nBytesPerSector;
  uint nSecPerBlock = superBlock.nBytesPerBlock / nbps;
  uint nSector = nBlock * nSecPerBlock;
  uint nbytes = 0;

  while (nSecPerBlock > 0) {
    nbytes += (writeFlag
	       ? simDisk->writeSector(nSector, p)
	       : simDisk->readSector(nSector, p));
    p = (byte *) p + nbps;
    nSector ++;
    nSecPerBlock --;
  }
  return nbytes;
}

uint FileVolume::writeBlock(uint nBlock, void *p)
{
  return rdwrBlock(nBlock, p, 1);
}


uint FileVolume::readBlock(uint nBlock, void *p)
{
  return rdwrBlock(nBlock, p, 0);
}

uint FileVolume::getFreeBlock()
{
  uint bn = fbvBlocks.getFreeBit();
  if (bn > 0) {
    uint bsz = superBlock.nBytesPerBlock;
    byte * buffer = new byte[bsz];
    memset(buffer, 0, bsz);
    writeBlock(bn, buffer);
    delete buffer;
  }
  return bn;
}

// -eof-
