#! /usr/bin/python
#
# unzip_scan.py: Tool to extract and scan truncated ZIP files.
# by pts@fazekas.hu at Sat Oct 27 11:54:15 CEST 2018
#

import calendar
import os
import struct
import time
import sys
import zlib


class UnreadableFile(object):
  """A file-like object with .unread method to push bytes back."""

  __slots__ = ('_f', '_unread', '_ui')

  def __init__(self, f, header=None):
    if not callable(getattr(f, 'read', None)):
      raise TypeError
    self._f = f
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
      self._unread = ''
      self._ui = 0
      return result
    else:
      result = unread[ui:]
      self._unread = ''
      self._ui = 0
      return result + self._f.read(size - j)


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


EXTRA_UPATH = 0x7075
EXTRA_UNIX = 0x000d
EXTRA_TIME = 0x5455

METHODS = {
    0: 'uncompressed',
    8: 'flate',
}

def scan_zip(f, do_extract=False, only_filenames=None):  # Extracts the .iso from the .zip on the fly.
  # Based on: https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.4.TXT (2014-10-01).
  # Based on (EXTRA_*): https://fossies.org/linux/unzip/proginfo/extrafld.txt (2008-07-17).
  # !! Support ZIP64.

  def is_filename_matching(filename):
    return only_filenames is None or filename in only_filenames

  while 1:
    data = f.read(4)
    if data[:3] in ('PK\1', 'PK\5', 'PK\6'):
      break
    assert data[:4] == 'PK\3\4', repr(data)
    data = f.read(26)  # Local file header.
    assert len(data) == 26
    (version, flags, method, mtime_time, mtime_date, crc32, compressed_size,
     uncompressed_size, filename_size, extra_field_size,
    ) = struct.unpack('<HHHHHlLLHH', data)
    #print [version, flags, method, mtime_time, mtime_date, crc32, compressed_size, uncompressed_size, filename_size, extra_field_size]
    if flags & 8:  # Data descriptor comes after file contents.
      assert crc32 == compressed_size == uncompressed_size == 0
      crc32 = compressed_size = uncompressed_size = None
      assert method == 8  # No other way to detect end of compressed data.
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

    i = 0
    while i < extra_field_size:
      assert i + 4 <= extra_field_size
      efe_id, efe_size = struct.unpack('<HH', extra_field[i : i + 4])
      i += 4
      assert i + efe_size <= extra_field_size
      efe_data = buffer(extra_field, i, efe_size)
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
        assert len(efe_data) >= 8
        #assert efe_data[0] == '\x01'  # Version. Can be \x03 as well.
        # This is GMT.
        mtime, atime = struct.unpack('<LL', efe_data[1 : 9])
        # At efe_data[9 : 13] on macOS the file creation time is also
        # stored.

    # Prevent overwriting global files for security.
    filename = filename.lstrip('/')
    is_dir = filename.endswith('/')  # Info-ZIP.
    if is_dir:
      assert crc32 in (0, None)
      assert compressed_size in (0, None)
      assert uncompressed_size in (0, None)
    info = {}
    info['f'] = filename
    if is_dir:
      info['is_dir'] = 1
      info['format'] = 'directory'
    else:
      info['size'] = uncompressed_size
      info['compressed_size'] = compressed_size
      info['crc32'] = crc32
    info['mtime'] = mtime
    info['atime'] = atime
    # It's not info['codec'], because that would describe the contents of
    # the file (filename).
    info['method'] = METHODS[method]
    if compressed_size is None:
      has_printed = False
    else:
      has_printed = True
      sys.stdout.write(format_info(info))
      sys.stdout.flush()
    # !! How are directories represented in the .zip file?
    # !! Add efficient f.seek(..., 1) calls to skip bytes.
    uf = None
    #print [[filename, mtime, uncompressed_size]]
    assert method in (0, 8)
    try:
      if do_extract and not is_dir and is_filename_matching(filename):
        uf = open(filename, 'wb')
      else:
        uf = None
      if flags & 8:
        assert method == 8  # No other way to detect end of compressed data.
        zd = zlib.decompressobj(-15)
        i = uci = 0
        while not zd.unused_data:
          data = f.read(65536)
          assert data  # !! Better report EOF (with partial filename.) Everywhere.
          i += len(data)
          data = zd.decompress(data)
          if not data:  # !! Are we sure about EOF?
            break
          # !! How many bytes remaining?
          uci += len(data)
          if uf:
            uf.write(data)
        if uf:
          uf.write(zd.flush())
        unused_data = zd.unused_data
        i -= len(unused_data)
        f.unread(unused_data)
        data = f.read(16)
        assert len(data) == 16  # Data descriptor.
        dd_signature, crc32, compressed_size, uncompressed_size = struct.unpack('<4slLL', data)
        assert dd_signature == 'PK\x07\x08', [dd_signature]  # !! Missing (?) from some files.
        assert i == compressed_size
        assert uci == uncompressed_size
        # !! Write to file.
      else:  # !! Test again.
        # !! Don't extract when just viewing.
        if method == 8:
          zd = zlib.decompressobj(-15)  # !! Where to check CRC? Here and also in crc32 above?
        i = uci = 0
        while i < compressed_size:
          j = min(65536, compressed_size - i)
          data = f.read(j)
          assert len(data) == j
          #print 'DATA %d %r' % (len(data), data)
          i += j
          if method == 8:
            data = zd.decompress(data)
          uci += len(data)
          assert uci <= uncompressed_size
          if uf:
            uf.write(data)
        assert uci == uncompressed_size
        if uf and method == 8:
          uf.write(zd.flush())
      zd = None  # Save memory.
    finally:
      if uf:
        uf.close()
        os.utime(filename, (atime, mtime))
      uf = None  # Save memory.
    if is_dir:
      assert crc32 == 0
      assert compressed_size == 0
      assert uncompressed_size == 0
    if do_extract and is_dir and is_filename_matching(filename):
      try:
        os.mkdir(filename)
      except OSError:
        if not os.path.isdir(filename):
          raise
      os.utime(filename, (atime, mtime))
    if not has_printed:
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
        '-t Just test archive.zip, don\'t extract any files.\n' % argv[0])
    sys.exit(1)
  i = 1
  do_extract = True
  while i < len(argv):
    arg = argv[i]
    if not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      break
    elif arg in ('-t', '-v'):
      do_extract = False
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

  f = open(archive_filename, 'rb')
  try:
    scan_zip(UnreadableFile(f),
             do_extract=do_extract, only_filenames=only_filenames)
  finally:
    f.close()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
