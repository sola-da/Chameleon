'''
hash and date functions utils.
author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
'''
import hashlib
from datetime import datetime
from pytz import timezone
from time import strftime
from os import path
import shutil

BLOCK_SIZE = 4096

def md5(filename):
	hash_md5 = hashlib.md5()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(BLOCK_SIZE), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

def sha1(filename):
	hash_sha1 = hashlib.sha1()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(BLOCK_SIZE), b""):
			hash_sha1.update(chunk)
	return hash_sha1.hexdigest()

def sha256(filename):
	hash_sha256 = hashlib.sha256()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(BLOCK_SIZE), b""):
			hash_sha256.update(chunk)
	return hash_sha256.hexdigest()

def convert_UTC_to_CET(datetime_stamp, time_stamp_format):
	dt = datetime.strptime(datetime_stamp, time_stamp_format)
	dt_with_timezone = timezone('UTC').localize(dt)
	cet_dt = dt_with_timezone.astimezone(timezone('Europe/Berlin'))
	return cet_dt.strftime("%Y-%m-%dT%H:%M:%S")

# converts the datetime format to the format that is stored in the DB to
# be consistent with other entries.
def convert_datetime_format(datetime_stamp, time_stamp_format):
	dt = datetime.strptime(datetime_stamp, time_stamp_format)
	return dt.strftime("%Y-%m-%dT%H:%M:%S")

def move(src, dst):
	if not path.exists(path.join(dst, path.basename(src))):
		shutil.move(src, dst)

# returns filename from an absolute path with filename.
def name(ffile):
	return path.basename(ffile)
