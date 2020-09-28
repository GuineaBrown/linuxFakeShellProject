/* 
 * file.C of CEG 433/633 File Sys Project
 * pmateti@wright.edu
 */

#include "fs33types.hpp"

/* pre:: pfv != 0, ptr to a proper file volume;; post:: Create a new
 * file object.  in == 0 => Get a free i-node, file mode is write
 * only.  in > 0 => Use in as its nInode, file mode is
 * read/write.;; */

File::File(FileVolume * pfv, uint in)
{
  fv = pfv;
  nInode = (in > 0 ? in : fv->inodes.getFree());
  bsz = fv->superBlock.nBytesPerBlock;

  // Caution: In mid-read-byte-by-byte do not do readBlock or writeBlock
  // directly.
  fileBuf = new byte[bsz];
  nBlocksSoFar = 0;
  nBytesInFileBuf = 0;
  xNextByte = 0;
}


File::~File()
{
  delete fileBuf;
}

/* pre:: bp[] is at least nBytesPerBlock long;; post:: Deposit into
 * bp[] the content of nx-th block of file.  Return the number of
 * bytes so deposited that belong to this file. */

uint File::readBlock(uint nx, void * bp)
{
  uint bn = fv->inodes.getBlockNumber(nInode, nx);
  if (bn == 0) return 0;	// !(0 <= nx < blocks in this file)

  fv->readBlock(bn, bp);

  uint nb = fv->inodes.getFileSize(nInode) - nx * bsz;
  if (nb > bsz) nb = bsz;
  return nb;
}

uint File::writeBlock(uint nBlock, void * p)
{
  uint bn = fv->inodes.getBlockNumber(nInode, nBlock);
  if (bn == 0) return 0;

  return fv->writeBlock(bn, p);
}

/* pre:: p != 0, 0 < iz <= nBytesPerBlock ;; post:: Append the p[0
 * .. iz-1] as a block at the end of this file.  Return the number of
 * bytes so written. */

uint File::appendOneBlock(void * p, uint iz)
{
  uint bn = fv->getFreeBlock();
  if (bn == 0) iz = 0;
  else {
    memcpy(fileBuf, p, iz);
    fv->writeBlock(bn, fileBuf);
    fv->inodes.addBlockNumber(nInode, bn);
    fv->inodes.incFileSize(nInode, iz);
  }
  return iz;
}

uint File::fillLastBlock(byte * newContentBp, uint nBytes)
{
  uint fileSize = fv->inodes.getFileSize(nInode);
  uint nFragmentSize = fileSize % bsz;
  if (nFragmentSize == 0) return 0;

  uint nToFill = bsz - nFragmentSize;
  if (nToFill > nBytes) nToFill = nBytes;
  uint nBlocks = (fileSize + bsz - 1) / bsz; // fileSize > 0 => nBlocks > 0
  readBlock(nBlocks - 1, fileBuf);
  memcpy(fileBuf + nFragmentSize, newContentBp, nToFill);
  writeBlock(nBlocks - 1, fileBuf);
  fv->inodes.setFileSize(nInode, fileSize + nToFill);
  return nToFill;
}

/* pre:: 0 <= nBytes, can be larger than bsz;; post:: To this file,
 * append content[0..nBytes-1].  */

uint File::appendBytes(byte * content, uint nBytes)
{
  if (content == 0 || nBytes == 0)
    return 0;

  uint nWritten = 0, nb = fillLastBlock(content, nBytes);

  for (;;) {
    nWritten += nb;
    content += nb;
    nBytes -= nb;
    if (nBytes == 0)
      break;
    nb = (nBytes > bsz ? bsz : nBytes);
    appendOneBlock(content, nb);
  }
  return nWritten;
}

/* pre:: ;; post:: If this file reading has not exhausted all its
 * content, return the next byte, otherwise 0. */

uint File::getNextByte()
{
  if (xNextByte == nBytesInFileBuf) {
    xNextByte = 0;
    nBytesInFileBuf = readBlock(nBlocksSoFar++, fileBuf);
  }
  return (xNextByte < nBytesInFileBuf? fileBuf[xNextByte++] : 0);
}

/* pre:: nBlocksSoFar >= 1, bsz >= nBytes > 0;; post:: Delete nBytes
 * from the file preceding the current position (fromx);; Caution: May
 * cross over block boundaries. NB: Only caller: Directory::
 * deleteFile().  */

uint File::deletePrecedingBytes(uint nBytes)
{
  uint fromx = (nBlocksSoFar - 1) * bsz + xNextByte;
  uint fileSize = fv->inodes.getFileSize(nInode);
  uint nBytesToShiftLeft = fileSize - fromx;
  if (fromx < nBytes) nBytes = fromx;
  uint tox = fromx - nBytes;	// byte index relative to file
  uint toBlockx = tox % bsz;	// byte index relative to localBuf
  uint toBlockNum = tox / bsz;
  byte * localBuf = new byte[bsz];

  readBlock(toBlockNum, localBuf);
  while (nBytesToShiftLeft-- > 0) {
    localBuf[toBlockx++] = getNextByte();
    if (toBlockx == bsz) {
      writeBlock(toBlockNum++, localBuf);
      toBlockx = 0;
    }
  }
  if (toBlockx > 0) writeBlock(toBlockNum, localBuf);
  if (fileSize % bsz == nBytes) {
    fv->inodes.setLastBlockNumber(nInode, 0); // free last block
  }
  fv->inodes.setFileSize(nInode, fileSize - nBytes);
  delete localBuf;
  return nBytes;
}

// -eof-
