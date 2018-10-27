unzip_scan.py: Tool to extract and scan truncated ZIP files.

unzip_scan.py is a command-line tool implemented in Python which can scan a
ZIP archive file sequentially, and display and extract its member files.
unzip_scan.py works even on truncated (e.g. partially downloaded) ZIP
archive files (for which Info-ZIP's unzip(1) tool fails).

Please note that as an alternative of unzip_scan.py, the 7z tool can also be
used to display (`7z l archive.zip') and extract (`7z x archive.zip')
truncated ZIP archive files.

__END__