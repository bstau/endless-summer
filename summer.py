#!/usr/bin/env python
#
# This is a tool that recursively calculates and stores the checksums of files
# on disk. The storage is designed for historical analysis of files, and
# detection of data loss and corruption.
#
# Data will be stored in "summer.db", in the working directory.
#
# Usage:
#  summer.py /directory [/or/file ...]

import collections
import hashlib
import os
import random
import signal
import sqlite3
import sys
import threading
import time
import Queue

BLKSIZE = 10485760
CLEAR_LINE = '\r                                                 \r'
HASHES = {alg: getattr(hashlib, alg)() for alg in ('md5', 'sha1', 'sha256')}

class FileInfo(collections.namedtuple('FileInfo',
                    'filename atime mtime size hashes')):
  """Used for sending file details from hashing to the DB thread."""


class AtomicInt(object):
  """Used to collect file statistics between threads."""

  def __init__(self, value=0):
    self.value = value
    self.lock = threading.Lock()

  def __iadd__(self, increment):
    with self.lock:
      self.value += int(increment)
    return self

  def __str__(self):
    with self.lock:
      return str(self.value)


def hash_file(filename):
  """Calculate the MD5, SHA-1 and SHA-256 digests of a file."""

  mtime = os.stat(filename).st_mtime
  with open(filename, 'rb') as f:
    when = time.time()
    data = None
    n = 0
    while data != '':
      data = f.read(BLKSIZE)
      n += len(data)
      [h.update(data) for h in HASHES.itervalues()]

  return FileInfo(
    filename=filename,
    atime=when,
    mtime=mtime,
    size=n,
    hashes={k: v.digest() for k, v in HASHES.iteritems()})


def HashingThread(inqueue, dbqueue, scan_done, hashcount, abort):
  while not (abort.is_set() or (scan_done.is_set() and inqueue.empty())):
    try:
      hsh, f = inqueue.get(True, 0.5)
      try:
        absolute = os.path.realpath(f)

        if not os.path.isfile(absolute):
          # Don't hash block devices etc.
          continue

        try:
          info = hash_file(absolute)
          dbqueue.put(info)
        except IOError:
          # Ignore things we don't have access to or the like.
          pass
      finally:
        hashcount += 1
        inqueue.task_done()
    except Queue.Empty:
      pass
    except Exception, e:
      print e


def DBThread(dbqueue, db, work_done, abort):
  while not (dbqueue.empty() and work_done.is_set()) and not abort.is_set():
    try:
      info = dbqueue.get(True, 0.5)
      try:
        c = db.cursor()
        c.execute('''INSERT INTO observations
                     (filename, scantime, filesize, filetime, md5, sha1, sha256)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
          (info.filename,
          info.atime,
          info.size,
          info.mtime,
          buffer(info.hashes['md5']),
          buffer(info.hashes['sha1']),
          buffer(info.hashes['sha256'])))
        db.commit()
      finally:
        dbqueue.task_done()

    except Queue.Empty:
      pass
    except Exception, e:
      print e


def ScannerThread(f, inqueue, scancount, abort):
  if os.path.isdir(f):
    for root, dirs, files in os.walk(f, topdown=False):
      for f in files:
        inqueue.put((random.randint(0, 256), os.path.join(root, f)))
        scancount += 1
        if abort.is_set(): return
  else:
    inqueue.put((random.randint(0, 256), f))
    scancount += 1


def OpenDB(filename):
  db = sqlite3.connect(filename, timeout=5, check_same_thread=False)

  # Check that we can read from the observations table. Or set up the schema.
  c = db.cursor()
  try:
    c.execute('''SELECT filename, scantime, filetime, filesize,
                     md5, sha1, sha256 FROM observations LIMIT 1''')
  except sqlite3.OperationalError:
    # We have no schema.
    c.execute('''CREATE TABLE observations (
      filename TEXT NOT NULL,
      scantime DATETIME NOT NULL,
      filesize INT64 NOT NULL,
      filetime DATETIME NOT NULL,
      md5 BLOB,
      sha1 BLOB,
      sha256 BLOB,
      PRIMARY KEY (filename, scantime)
    )''')
    c.execute('CREATE INDEX FilesBySha256 ON observations (sha256)')
    c.execute('CREATE INDEX FilesByMd5 ON observations (md5)')

  return db


def main(argv):
  db = OpenDB('summer.db')
  scancount = AtomicInt()
  hashcount = AtomicInt()
  inqueue = Queue.PriorityQueue()
  dbqueue = Queue.Queue()

  scan_done = threading.Event()
  work_done = threading.Event()
  abort = threading.Event()

  # Set up the signal handlers so we can cleanly terminate.
  signal.signal(signal.SIGINT, lambda a, b: abort.set())

  # Start doing a directory scan; plenty of seeking I/O which might be on
  # different partitions; split it into parallel threads. Potentially some
  # gains here by sharding by filesystem.
  scan_threads = [threading.Thread(
    target=ScannerThread, name='Scanner', args=(f, inqueue, scancount, abort))
    for f in argv]

  sys.stderr.write('Scanning directories...')
  [s.start() for s in scan_threads]

  # The database doesn't handle concurrent writes well; we'll serialise DB
  # work via a queue into a single thread.
  db_thread = threading.Thread(
    target=DBThread, name='DBWriter', args=(dbqueue, db, work_done, abort))
  db_thread.start()

  # Start a bunch of I/O-limited threads that hash files in the queue.
  hash_threads = [threading.Thread(
    target=HashingThread, name='Hasher',
    args=(inqueue, dbqueue, scan_done, hashcount, abort)) for i in range(10)]
  [h.start() for h in hash_threads]

  # Display a cute little progress bar.
  n = 0
  while any([s.is_alive() for s in scan_threads]):
    if abort.is_set(): return
    sys.stderr.write('\rScanning directories' + ('.' * n) + (' ' * (3 - n)))
    time.sleep(0.2)
    n = (n + 1) % 4

  # Wait for the directory scan to complete.
  [s.join() for s in scan_threads]
  scan_done.set()

  # While we're hashing data, show a progress update. First, clear the
  # previous status update.
  sys.stderr.write(CLEAR_LINE)
  while any([h.is_alive() for h in hash_threads]):
    if abort.is_set(): return
    sys.stderr.write('\rHashed %s of %s files..' % (hashcount, scancount))
    time.sleep(0.2)

  # Wait for the hashing threads to complete.
  sys.stderr.write(CLEAR_LINE)
  sys.stderr.write('\rCleaning up...')
  inqueue.join()
  [h.join() for h in hash_threads]

  # Now tell the DB thread that we're done.
  work_done.set()
  dbqueue.join()
  db_thread.join()
  sys.stderr.write(CLEAR_LINE)


if __name__ == '__main__':
  main(sys.argv[1:])
