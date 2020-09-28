/*
 * simdisk.C -- simulated disk of WSU/CEG433/Mateti/
 * pmateti@wright.edu
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "fs33types.hpp"

/* pre:: mode == O_RDONLY or mode == O_WRONLY | O_CREAT;; post::
 * Systematically make up a name for the disk image file, open the/a file
 * with that pathname, and return its file descriptor.  Returned value
 * can be 0, or negative.;; */

int SimDisk::openDiskImage(uint mode)
{
  char tfnm[1024];
  sprintf(tfnm, "%s.dsk", this->name);
  return open(tfnm, mode, 0600);
}

/* pre:: none;; post:: A file named "%s.dsk", where %s stands for the
 * name is created.  Return its file descriptor.  This file
 * will be of size nBytesPerSector x nSectorsPerDisk in bytes, all set
 * to zero.
 */

int SimDisk::makeDiskImage()
{
  int fd = openDiskImage(O_WRONLY | O_CREAT);
  if (fd < 3)
    return fd;

  byte * buf = new byte [nBytesPerSector];
  memset(buf, 0, nBytesPerSector);
  for (uint i = nSectorsPerDisk; i--;)
    write(fd, buf, nBytesPerSector);
  close(fd);
  delete buf;
  return fd;
}

/* pre:: diskName!=0 && diskNumber==0 or diskName==0 && diskNumber > 0
 * ;; post:: On success, a binary file named this->name[] will be created in
 * the current working directory.  It will be of size nSectorsPerDisk
 * * nBytesPerSector.  "Failure" is defined as one or more of the
 * following happening: invalid arguments, a file create/write/close
 * fails */

SimDisk::SimDisk(byte * diskName, uint diskNumber)
{
  char line[1024];
  uint nargs = 0;
  simDiskNum = 0;

  if (diskName != 0) diskNumber = 255 + 1; // assuming a max of 255 disks

  FILE *f = fopen("diskParams.dat", "r");
  if (f != 0) {
    for (uint dn = 1; dn <= diskNumber; dn ++) {
      if (fgets(line, 1024, f) == 0) {
        break;                  // end of file
      }
      if (line[0] == '#') {
        continue;               // comment line;
      }
      nargs = sscanf(line, "%s %u %u %u %u %u\n",
                     name, &nSectorsPerDisk, &nBytesPerSector,
                     &diskParams.maxfnm, &diskParams.nInodes,
                     &diskParams.iHeight);
      if (nargs < 6) {
        break;                  // end of file
      }
      if (diskName != 0 && strcmp((char *)this->name, (char *)diskName) == 0
	  || dn == diskNumber) {
	simDiskNum = dn;
	break;			// found it
      }
    }
    fclose(f);
  }
  if (simDiskNum == 0 ||
      !(0 < nSectorsPerDisk && nSectorsPerDisk <= SectorsMAX &&
	0 < nBytesPerSector && nBytesPerSector <= BytesPerSectorMAX)) {
    nSectorsPerDisk = 0;	// robust
    return;
  }

  int fd = openDiskImage(O_RDONLY), exists = (fd >= 3); // already exists?
  if (exists) {
    struct stat statBuf;
    fstat(fd, &statBuf);
   close(fd);		    // file exists, but is it a valid simDisk?
     exists = (uint) statBuf.st_size == nSectorsPerDisk * nBytesPerSector;
  }
  if (! exists) {
    fd = makeDiskImage();
    if (fd < 3) nSectorsPerDisk = 0; // robust
  }
}

uint SimDisk::readSector(uint nSector, void *p)
{
  if (p == 0 || nSector >= nSectorsPerDisk)
    return 0;
  int fd = openDiskImage(O_RDONLY);
  lseek(fd, nBytesPerSector * nSector, SEEK_SET);
  read(fd, p, nBytesPerSector);
  close(fd);
  return nBytesPerSector;
}

uint SimDisk::writeSector(uint nSector, void *p)
{
  if (p == 0 || nSector >= nSectorsPerDisk)
    return 0;
  int fd = openDiskImage(O_WRONLY);
  lseek(fd, nBytesPerSector * nSector, SEEK_SET);
  write(fd, p, nBytesPerSector);
  close(fd);
  return nBytesPerSector;
}

/* "Find" a file volume previously made. */

FileVolume *SimDisk::make33fv()
{
  return nSectorsPerDisk > 0
    ? new FileVolume(this,
                     diskParams.nInodes,
                     diskParams.iHeight,
                     1) : 0;
}

/* -eof- */
