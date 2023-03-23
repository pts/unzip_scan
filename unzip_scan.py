#! /bin/sh
# by pts@fazekas.hu at Sat Oct 27 11:54:15 CEST 2018

""":" # unzip_scan.py: extract and scan truncated ZIP files

type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
type python2   >/dev/null 2>&1 && exec python2   -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1

This script needs Python 2.4, 2.5, 2.6 or 2.7. Python 3.x won't work.

Typical usage: cat myfile.zip | ./unzip_scan.py -t -
"""

import calendar
import os
import struct
import time
import sys
import zlib


class UnreadableFile(object):
  """A file-like object with .unread method to push bytes back."""

  __slots__ = ('_f', '_sf', '_unread', '_ui')

  def __init__(self, f, header=None):
    if not callable(getattr(f, 'read', None)):
      raise TypeError
    self._f = self._sf = f
    self._unread = ''
    self._ui = 0
    if header is not None:
      header = str(header)
      self._unread = header

  def unread(self, data):
    """Next .read(...) will read data first."""
    data = str(data)
    if data:
      if self._ui >= ((len(self._unread) + len(data)) >> 1):
        # This is slow, it copies the string.
        self._unread = self._unread[self._ui:] + data
        self._ui = 0
      else:
        self._unread += data  # This is slow, it copies the string.

  def read(self, size):
    if size <= 0:
      return ''
    unread, ui = self._unread, self._ui
    j = len(unread) - ui
    if not j:
      return self._f.read(size)
    elif j > size:
      result = self._unread[ui : ui + size]
      self._ui = ui + size
      return result
    elif j == size:
      result = unread[ui:]
      self._unread, self._ui = '', 0
      return result
    else:
      result = unread[ui:]
      self._unread = ''
      self._ui = 0
      return result + self._f.read(size - j)

  def skip(self, size):
    """Returns the actual number of bytes skipped."""
    if size <= 0:
      return 0
    ui = self._ui
    i = len(self._unread) - ui
    if i:
      if size < i:
        self._ui = ui + size
        return size
      self._unread, self._ui = '', 0
    sf = self._sf
    if sf and i < size:  # Try to seek forward.
      assert sf is self._f
      try:
        ofs = sf.tell()
        ofs2 = ofs + (size - i)
        sf.seek(0, 2)
        # TODO(pts): Remember sf_size across calls.
        sf_size = sf.tell()
      except OSError:  # Maybe the file is not seekable.
        ofs = ofs2 = sf_size = None
        self._sf = None  # Mark file as unseekable, don't try seeking again.
      if ofs2 is not None:
        ofs3 = min(sf_size, ofs2)
        sf.seek(ofs3, 0)
        return ofs3 - ofs
    f = self._f
    while i < size:
      j = min(65536, size - i)
      data = f.read(j)
      ld = len(data)
      i += ld
      if ld < j:
        break
    return i


def convert_fat_gmt_to_timestamp(date_value, time_value):
  """Converts a FAT filesystem date and time in GMT to a Unix timestamp."""
  if date_value & ~0xffff:
    raise ValueError
  if time_value & ~0xffff:
    raise ValueError
  year = 1980 + (date_value >> 9)
  month = (date_value >> 5) & 15
  day = date_value & 31
  hour = time_value >> 11
  minute = (time_value >> 5) & 63
  second = (time_value & 31) << 1  # Always even.
  if not (1 <= month <= 12 and 1 <= day <= 31 and
          hour < 24 and minute < 60 and second < 60):
    raise ValueError
  tm = (year, month, day, hour, minute, second)
  ts = calendar.timegm(tm)
  tm2 = time.gmtime(ts)[:6]
  if tm != tm2:
    raise ValueError('Invalid date: %d-%02d-%02d' % tm[:3])
  return ts


def format_info(info):
  def format_value(v):
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, float):
      if abs(v) < 1e15 and int(v) == v:  # Remove the trailing '.0'.
        return int(v)
      return repr(v)
    if isinstance(v, (int, long)):
      return str(v)
    if isinstance(v, str):
      # Faster than a regexp if there are no matches.
      return (v.replace('%', '%25').replace('\0', '%00').replace('\n', '%0A')
              .replace(' ', '%20'))
    raise TypeError(type(v))
  output = ['format=%s' % format_value(info.get('format') or '?')]
  # TODO(pts): Display brands list.
  output.extend(
      ' %s=%s' % (k, format_value(v))
      for k, v in sorted(info.iteritems())
      if k != 'f' and k != 'format' and
      not isinstance(v, (tuple, list, dict, set)))
  filename = info.get('f')
  if filename is not None:
    if '\n' in filename or '\0' in filename:
      raise ValueError('Invalid byte in filename: %r' % filename)
    output.append(' f=%s' % filename)  # Emit ` f=' last.
  output.append('\n')
  return ''.join(output)


def does_file_exist(filename, size, mtime):
  import stat
  try:
    st = os.stat(filename)
  except OSError:
    return False
  return (stat.S_ISREG(st.st_mode) and st.st_size == size and
          int(st.st_mtime) == int(mtime))


EXTRA_ZIP64 = 0x0001
EXTRA_UPATH = 0x7075
EXTRA_UNIX = 0x000d
EXTRA_TIME = 0x5455

METHODS = {
    0: 'uncompressed',
    8: 'flate',
}


def scan_zip(f, do_extract=False, do_skip=False, do_skipover=False,
             only_filenames=None):
  # Based on: https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.4.TXT (2014-10-01).
  # Based on (EXTRA_*): https://fossies.org/linux/unzip/proginfo/extrafld.txt (2008-07-17).

  def is_filename_matching(filename):
    # !! Match and extract directories recursively.
    return only_filenames is None or filename in only_filenames

  pre_data = ''
  while 1:
    if len(pre_data) < 8:
      data = pre_data + f.read(8 - len(pre_data))
    else:
      assert len(pre_data) == 8
      data = pre_data
    pre_data = ''
    if data[:3] in ('PK\1', 'PK\5', 'PK\6', 'PK\7'):
      break
    assert data.startswith('PK\3\4') and len(data) >= 8, repr(data)
    data += f.read(22)  # Local file header.
    assert len(data) == 30
    # crc32 is of the uncompressed, decrypted file. We ignore it.
    (version, flags, method, mtime_time, mtime_date, crc32, compressed_size,
     uncompressed_size, filename_size, extra_field_size,
    ) = struct.unpack('<4xHHHHHlLLHH', data)
    #print [version, flags, method, mtime_time, mtime_date, crc32, compressed_size, uncompressed_size, filename_size, extra_field_size]
    assert method in (0, 8), method  # See meanings in METHODS.
    if flags & 8:  # Data descriptor comes after file contents.
      if method == 8:
        assert crc32 == compressed_size == uncompressed_size == 0, (crc32, compressed_size, uncompressed_size, method)
        crc32 = compressed_size = uncompressed_size = None
      elif method == 0:
        if uncompressed_size == 0:
          uncompressed_size = compressed_size
        assert crc32 == 0 and compressed_size == uncompressed_size, (crc32, compressed_size, uncompressed_size, method)
        crc32 = None
      else:
        assert 0, method
    filename = f.read(filename_size)
    assert len(filename) == filename_size
    extra_field = f.read(extra_field_size)
    assert len(extra_field) == extra_field_size
    # mtime_time is in local time, but we don't know the time zone, so we
    # assume GMT for simplicity. Thus we can be off by 24 hours.
    atime = mtime = convert_fat_gmt_to_timestamp(mtime_date, mtime_time)
    # Unfortunately we are not able to extract the Unix permission bits
    # (st_mode & 07777, including whether the file is executable), because
    # that's stored in the external attributes field within the central
    # directory header ('PK\1\2'), only if version made by (also in the
    # central directory header) is Unix.
    #
    # !! Process the central directory header to extract permissions.
    #
    # Extra field 0x7855 and 0x7875 have UID and GID, but not permissions.
    # Info-ZIP 3.0 zip(1) emits only extra fields 0x5455 and 0x7875.

    is_zip64 = False
    i = 0
    while i < extra_field_size:
      assert i + 4 <= extra_field_size
      efe_id, efe_size = struct.unpack('<HH', extra_field[i : i + 4])
      i += 4
      assert i + efe_size <= extra_field_size
      efe_data = buffer(extra_field, i, efe_size)
      assert len(efe_data) == efe_size
      i += efe_size
      #print 'EF 0x%x %d %r' % (efe_id, len(efe_data), str(efe_data))
      if efe_id == EXTRA_UPATH:  # Unicode (UTF-8) pathname.
        assert len(efe_data) >= 6
        assert efe_data[0] == '\x01'  # Version.
        filename = efe_data[5:]  # UTF-8.
      elif efe_id == EXTRA_UNIX:
        assert len(efe_data) >= 8
        atime, mtime = struct.unpack('<LL', efe_data[:8])
      elif efe_id == EXTRA_TIME:
        assert len(efe_data) >= 1, [efe_id, len(efe_size), str(efe_data)]
        efe_flags, = struct.unpack('>B', efe_data[0])
        assert not efe_flags & ~7
        fi = 1
        if efe_flags & 1:  # mtime (last modification time) in GMT.
          assert len(efe_data) >= fi + 4
          atime = mtime = struct.unpack('<L', efe_data[fi : fi + 4])[0]
          fi += 4
        if efe_flags & 2:  # atime (last access time) in GMT.
          assert len(efe_data) >= fi + 4
          atime, = struct.unpack('<L', efe_data[fi : fi + 4])
          if not efe_flags & 1:
            mtime = atime
          fi += 4
        if efe_flags & 4:  # crtime (creation time) in GMT, mostly on macOS.
          assert len(efe_data) >= fi + 4
          fi += 4
        assert fi == len(efe_data)
      elif efe_id == EXTRA_ZIP64:
        assert len(efe_data) >= 16
        uncompressed_size, compressed_size = struct.unpack('<QQ', efe_data[:16])
        if uncompressed_size == 0 and method == 0:  # Shouldn't happen.
          uncompressed_size = compressed_size
        is_zip64 = True
    assert method or compressed_size == uncompressed_size  # Both may be None.

    # Prevent overwriting global files for security.
    filename = filename.lstrip('/')
    is_dir = filename.endswith('/')  # Info-ZIP.
    if is_dir:
      assert crc32 in (0, None)
      assert compressed_size in (0, None)
      assert uncompressed_size in (0, None)
    is_matching = is_filename_matching(filename)
    info = {}
    info['f'] = filename.rstrip('/')
    if is_dir:
      info['is_dir'] = 1
      info['format'] = 'directory'
    else:
      info['size'] = uncompressed_size
      info['compressed_size'] = compressed_size
      if flags & 1:
        info['compressed_size'] -= 12
        info['is_encrypted'] = 1
      info['crc32'] = crc32
    info['mtime'] = mtime
    info['atime'] = atime
    # It's not info['codec'], because that would describe the contents of
    # the file (filename).
    info['method'] = METHODS[method]
    if compressed_size is None or crc32 is None:
      has_printed = False
    else:
      has_printed = True
      if is_matching:
        sys.stdout.write(format_info(info))
        sys.stdout.flush()

    if flags & 1:  # Encryption header.
      assert compressed_size >= 12
      data = f.read(12)
      assert len(data) == 12
      print 'ENCRYPTION_HEADER %r' % data
      compressed_size -= 12

    uf = None
    #print [[filename, mtime, uncompressed_size]]
    is_ok = False
    try:
      do_extract_this = do_extract and not is_dir and is_matching and not (
          do_skip and uncompressed_size is not None and mtime is not None and
          does_file_exist(filename, uncompressed_size, mtime))
      if do_extract_this:
        ni = filename.rfind('/')
        if ni >= 0:
          dirname = filename[:ni]
          if not os.path.isdir(dirname):
            os.makedirs(dirname)
        uf = open(filename, 'wb')
      else:
        uf = None
      i = uci = 0
      is_trunc = False
      if compressed_size is None:
        assert method == 8, method  # No other way to detect end of compressed data.
        zd = zlib.decompressobj(-15)
        while not zd.unused_data:
          data = f.read(65536)
          is_trunc = not data
          i += len(data)
          data = zd.decompress(data)
          if not data:
            break
          uci += len(data)
          if uf:
            uf.write(data)
          if is_trunc:
            break
        if uf:
          data = zd.flush()
          uci += len(data)
          if uf:
            uf.write(data)
        unused_data = zd.unused_data
        i -= len(unused_data)
        f.unread(unused_data)
      elif uf or uncompressed_size is None or not do_skipover:  # !! Test again.
        if method == 8:
          zd = zlib.decompressobj(-15)  # !! Where to check CRC? Here and also in crc32 above?
        while i < compressed_size:
          j = min(65536, compressed_size - i)
          data = f.read(j)
          is_trunc = len(data) != j
          #print 'COMPRESSED_DATA size=%d %r' % (len(data), data)
          i += j
          if method == 8:
            data = zd.decompress(data)
          #print 'UNCOMPRESSED_DATA size=%d %r' % (len(data), data)
          uci += len(data)
          #print 'UNCOMPRESSED_DATA size=%d total_size=%d' % (len(data), uci)
          assert uci <= uncompressed_size
          if uf:
            uf.write(data)
          if is_trunc:
            break
        if method == 8:  # This also works with compressed_size == 0.
          data = zd.flush()
          uci += len(data)
          if uf:
            uf.write(data)
          assert is_trunc or not zd.unused_data
      else:  # Skip over compressed bytes quickly, without decompressing them.
        assert compressed_size is not None
        assert uncompressed_size is not None
        assert not uf
        i += f.skip(compressed_size)
        uci += uncompressed_size
        is_trunc = i != compressed_size
      # Even if the ZIP archive is truncated, we keep the partial, but
      # longest possible member file on disk.
      assert not is_trunc, 'ZIP archive truncated within member file: %r' % filename
      assert compressed_size is None or i == compressed_size, (i, compressed_size)
      assert uncompressed_size is None or uci == uncompressed_size, (uci, uncompressed_size)
      if flags & 8:  # Data descriptor.
        data = f.read(24)
        assert len(data) == 24  # Actually, only 16 bytes in data descriptor, then 8 bytes in the next record.
        dd_signature, crc32, compressed_size, uncompressed_size, uncompressed_size_64 = struct.unpack('<4slLLQ', data)
        compressed_size_64, = struct.unpack('<8xQ8x', data)
        assert dd_signature == 'PK\x07\x08', [dd_signature]  # !! Missing (?) from some files.
        if is_zip64 or (i == compressed_size_64 and uci == uncompressed_size_64):  # 8-byte sizes.
          # For method == 0, the detection above is always correct. For
          # method == 8, it may fail with probability 2.**-64.
          compressed_size, uncompressed_size = compressed_size_64, uncompressed_size_64
        elif i == compressed_size and uci == uncompressed_size:
          pre_data = data[-8:]  # Unread the last 8 bytes.
        else:
          assert 0, 'Bad sizes in data descriptor: %r' % ((i, compressed_size, compressed_size_64, uci, uncompressed_size, uncompressed_size_64),)
      assert i == compressed_size, (i, compressed_size)
      assert uci == uncompressed_size, (uci, uncompressed_size)
      assert crc32 is not None
      zd = None  # Save memory.
      is_ok = True
    finally:
      if uf:
        uf.close()
        if is_ok:
          os.utime(filename, (atime, mtime))
        else:
          filename2 = filename + '.partial'
          try:
            os.rename(filename, filename2)
            is_rename_ok = True
          except OSError:
            is_rename_ok = False
          if is_rename_ok:
            print >>sys.stderr, 'warning: renamed partially extracted %r to %r' % (filename, filename2)
          else:
            print >>sys.stderr, 'warning: failed to rename partially extracted %r to %r' % (filename, filename2)
      uf = None  # Save memory.
    if is_dir:
      assert crc32 == 0, (crc32, compressed_size, uncompressed_size)
      assert uncompressed_size == 0, (crc32, compressed_size, uncompressed_size)
      if method == 8:
        # Some .zip files have 0 bytes uncompressed as 2 bytes compressed:
        # cdata = '\3\0'; assert len(cdata) == 2; assert zlib.decompress(cdata, -15) == ''.
        valid_compressed_sizes = (0, 2)
      else:
        valid_compressed_sizes = (0,)
      assert compressed_size in valid_compressed_sizes, (crc32, compressed_size, uncompressed_size, valid_uncompressed_sizes)
    if do_extract and is_dir and is_filename_matching(filename):
      try:
        os.mkdir(filename)
      except OSError:
        if not os.path.isdir(filename):
          raise
      os.utime(filename, (atime, mtime))
    if is_matching and not has_printed:
      if not is_dir:
        info['size'] = uncompressed_size
      info['compressed_size'] = compressed_size
      info['crc32'] = crc32
      # !! Print something earlier, even if asserts fail.
      sys.stdout.write(format_info(info))
      sys.stdout.flush()


def main(argv):
  if len(argv) < 2 or argv[1] == '--help':
    sys.stderr.write(
        'unzip_scan.py: Tool to extract and scan truncated ZIP files.\n'
        'This is free software, GNU GPL >=2.0. '
        'There is NO WARRANTY. Use at your risk.\n'
        'Usage: %s [<flag> ...] <archive.zip> [<member-filename> ...]\n'
        'Flags:\n'
        '-t|-v Just test archive.zip, don\'t extract any files.\n'
        '-w Skip extracting a file if it exists with same size and mtime.\n'
        '-e Quickly skip (forward seek) over unneeded archive parts.\n'
        '-l Same as -v -e.\n'
        % argv[0])
    sys.exit(1)
  i = 1
  do_extract = True
  do_skip = False
  do_skipover = False
  while i < len(argv):
    arg = argv[i]
    if not arg.startswith('-') or arg == '-':
      break
    i += 1
    if arg == '--':
      break
    elif arg in ('-t', '-v'):
      do_extract = False
    elif arg == '-w':  # Not an unzip(1) flag.
      do_skip = True
    elif arg == '-e':  # Not an unzip(1) flag.
      do_skipover = True
    elif arg == '-l':
      do_extract, do_skipover = False, True
    else:
      print >>sys.stderr, 'fatal: unknown flag: %s' % arg
      sys.exit(1)
  if i == len(argv):
    print >>sys.stderr, 'fatal: missing <archive.zip> argument'
    sys.exit(1)
  archive_filename = argv[i]
  i += 1
  if i == len(argv):
    only_filenames = None
  else:
    only_filenames = argv[i:]

  if archive_filename == '-':
    f, cf = sys.stdin, None
  else:
    cf = f = open(archive_filename, 'rb')
  try:
    scan_zip(UnreadableFile(f),
             do_extract=do_extract, do_skip=do_skip, do_skipover=do_skipover,
             only_filenames=only_filenames)
  finally:
    if cf:
      cf.close()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
