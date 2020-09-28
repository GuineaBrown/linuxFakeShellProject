/*
 * fs33types.hpp of CEG 433/633 File Sys Project
 * pmateti@wright.edu
 */

#include <stdio.h>		// not all these are needed every where,
#include <string.h>		// but we take the simple way out
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

typedef unsigned char byte;
typedef unsigned short int ushort;
typedef unsigned int uint;
typedef unsigned long int ulong;

enum { LabelSZ = 15, SectorsMAX = 2048, BytesPerSectorMAX = 4096 };

uint TODO();
uint TODO(char * p);
uint bytesNeeded(uint);
ulong unpackNumber(void * p, uint width);
void * packNumber(void * p, ulong n, uint width);
uint isAlphaNumDot(char c);

class FileVolume;		// forward declaration

class SimDisk {
public:
  byte name[LabelSZ + 1];
  uint nSectorsPerDisk;
  uint nBytesPerSector;
  uint simDiskNum;

  SimDisk(byte * simDiskName, uint diskNumber);
  uint isOK();
  uint writeSector(uint nSector, void * p);
  uint readSector(uint nSector, void * p);
  FileVolume * make33fv(uint nInodes, uint htInode, uint nSecPerBlock);
  FileVolume * make33fv();

private:
  int makeDiskImage();
  int openDiskImage(uint mode);

  class DiskParams {
  public:
    uint maxfnm, nInodes, iHeight;
  } diskParams;
};

class SuperBlock {		// RAM resident
public:
  uint nTotalBlocks;
  uint nBytesPerBlock;		// must == nSecPerBlock * nBytesPerSector
  uint nSecPerBlock;
  uint nBlocksFbvBlocks;	// #blocks occupied by fbv of blocks
  uint nBlocksFbvInodes;	// #blocks occupied by fbv of inodes

  uint nBlockBeginInodes;	// where do the i-nodes begin?
  uint nBlocksOfInodes;		// #blocks on disk occupied by i-nodes
  uint inodesPerBlock;		// one block will contain this many inodes
  uint nInodes;			// total number of inodes
  uint iWidth;			// inode size on disk == iWidth * iHeight
  uint iHeight;			// iHeight includes size, and type fields
  uint iDirect;			// 0 <= iIndirect <= 3

  uint nBlockBeginFiles;	// == nBlockBeginInodes + nBlocksInode  
  uint fileNameLengthMax;
};

class BitVector {
public:
  uint create(FileVolume * fv, uint nBits, uint nBeginBlock);
  uint reCreate(FileVolume * fv, uint nBits, uint nBeginBlock);
  uint getBit(uint indexOfBit);
  void setBit(uint indexOfBit, uint newValue);
  uint getFreeBit();

private:
  uint nBits;			// #bits in this vector
  uint nBlockBegin;		// at what block does the vector begin?
  byte *bitVector;		// ptr to one block-long area of mem
  FileVolume * fv;
};

enum {iTypeOrdinary = 1,  iTypeDirectory = 2, iTypeSoftLink = 3};

class Inodes {
public:
  uint create(FileVolume * fv, uint nBegin, uint nInodes, uint htInode);
  uint reCreate(FileVolume * fv);	// in == i-node number
  uint getFree();
  uint setFree(uint in);
  uint getBlockNumber(uint in, uint nth);
  uint addBlockNumber(uint in, uint bn);
  uint setLastBlockNumber(uint in, uint bn);
  uint getFileSize(uint in);
  uint setFileSize(uint in, uint sz);
  uint incFileSize(uint in, int increment);
  uint getType(uint in);
  uint setType(uint in, uint value);
  uint show(uint in);

private:
  uint * uintbuffer;		// inodes from one block
  FileVolume * fv;

  uint *getInode(uint in, uint * ne);	// return ptr to inode in
  uint putInode(uint in);
  uint getEntry(uint in, uint x);
  uint setEntry(uint in, uint x, uint tp);
  uint getBlockNumberTripleIndirect(uint bn, uint nth);
  uint getBlockNumberDoubleIndirect(uint bn, uint nth);
  uint getBlockNumberSingleIndirect(uint bn, uint nth);
  uint setSingleIndirect(uint * pbn, uint nu, uint bn);
  uint setDoubleIndirect(uint * pbn, uint nu, uint bn);
  uint setTripleIndirect(uint * pbn, uint nu, uint bn);
};

class File {
public:
  uint nInode;			// inode number of this file

  File(FileVolume * fv, uint nInode);
  ~File();
  uint readBlock(uint xthBlock, void * p);
  uint writeBlock(uint xthBlock, void * p);
  uint getNextByte();
  uint appendOneBlock(void * p, uint iz);
  uint appendBytes(byte *newContent, uint nBytes);
  uint deletePrecedingBytes(uint howManyBytes);

private:
				// bsz is tentatively added, TBD
  uint bsz;			// == fv->superBlock.nBytesPerBlock
  uint nBlocksSoFar;
  byte * fileBuf;		// buffer for read/writes
  uint nBytesInFileBuf;
  uint xNextByte;		// index of next byte in fileBuf
  FileVolume * fv;

  uint fillLastBlock(byte *newContentBp, uint nBytes);
};

class Directory {
public:
  uint nInode;			// inode number of this directory
  byte * dirEntry;		// area of mem for file name + i-num

  Directory(FileVolume * fv, uint in, uint parent);
  ~Directory();
  uint iNumberOf(byte *leafnm);
  byte * nameOf(uint in);
  void addLeafName(byte * leafnm, uint in);
  uint createFile(byte * leafnm, uint dirFlag);
  uint deleteFile(byte * leafnm, uint releaseFlag);
  uint moveFile(uint pn, byte * leafnm);
  uint ls();

  FileVolume * fv;

private:
  File * dirf;			// this dir viewed as a normal file

  void namesEnd();		// done with file names
  byte * nextName();
  uint setDirEntry(byte * name);
  uint lsPrivate(uint in, uint printfFlag);
};

class FileVolume {
public:
  SimDisk * simDisk;
  SuperBlock superBlock;
  BitVector fbvBlocks;
  BitVector fbvInodes;
  Inodes inodes;
  Directory * root;

  FileVolume(SimDisk * simDisk, uint nInodes, uint szInode, uint nSecPerBlock);
  FileVolume(uint diskNumber);
  ~FileVolume();
  uint isOK();
  File * findFile(byte * leafnm);
  uint read33file(byte * fs33leafnm, byte * unixFilePath);
  uint write33file(byte * unixFilePath, byte * fs33leafnm);
  uint copy33file(byte * from33leafnm, byte * to33leafnm);
  uint deleteFile(byte * fs33leafnm);
  uint move(uint pn, byte * srcleafnm, uint wn, uint jn, byte * dstleafnm);
  File * createFile(byte * leafnm, uint dirFlag);
  uint writeBlock(uint nBlock, void * p);
  uint readBlock(uint nBlock, void * p);
  uint getFreeBlock();

private:
  uint rdwrBlock(uint nBlock, void *p, uint writeFlag);
};

// VNIN -- volume# i#
typedef unsigned long VNIN;
#define mkVNIN(x, y) (VNIN) (x << 16 | y)
#define volumeNumber(a) (uint)(a >> 16)
#define inodeNumber(a) (uint)(a & 0xFFFF)

class MountEntry {
public:
  MountEntry(VNIN which, VNIN where);
  ~MountEntry();
  byte * pathName(VNIN vnjn);
  VNIN pathNameVNIN(byte *pathnm, VNIN vnjn);
  uint move(byte * srcPathName, byte * dstPathName);
  VNIN createFile(byte *fs33name, uint dirFlag);
  uint write33file(byte *unixFilePath, byte *fs33name);
  uint read33file(byte * fs33leafnm, byte * unixFilePath);
  uint copy33file(byte *from33name, byte *to33name);
  uint rm(byte *pathnm, uint freeInodeFlag);
  VNIN setCwd(byte * pnm);
  VNIN mount(uint volNumber, byte * mountPath);
  VNIN umount(byte * mountPath, uint volNumber);
  VNIN rootVNIN();
  uint print();

 private:
  VNIN which;			// num of volume mounted, i# == 1
  VNIN where;			// above volume is mounted here
  MountEntry * next;		// stack

  VNIN whatIsMountedAt(VNIN mp);
  VNIN whereMounted(VNIN vnin);
  uint isDir(VNIN vnin);
  VNIN leafNameVNIN(byte * leafName, VNIN vnin);
  VNIN lastParentDir(byte *pnm, byte ** leafnm);
  VNIN parentOf(VNIN vnjn);
  void iPathName(VNIN vnjn);
};

// -eof-
