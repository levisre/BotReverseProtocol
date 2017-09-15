# Cutwail/Pushdo Botnet Sinkhole
# Created by Levis (levintaeyeon@live.com)
# Sample SHA1: ea4eb1c1fe2be91f90807a69b95cff61dac022f5
# This sinkhole does eliminate botnet Beacon checking routine and CnC contacting to deliver new malware modules

from flask import Flask, request
import socket, logging, struct, base64, datetime
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from pymongo import MongoClient


app = Flask(__name__) 


# Config for MongoDB Connection
db = None
dbClient = None
MONGO_DBNAME = 'pushdo_client'
MONGO_USER = "pushdo"
MONGO_PWD = "123456"
MONGO_HOST = "192.168.162.139"

def initdb():
	global db, dbClient
	# Connection String
	CONN_STR = "mongodb://%s:%s@%s/%s" % (MONGO_USER, MONGO_PWD, MONGO_HOST, MONGO_DBNAME)
	dbClient = MongoClient(CONN_STR)
	db = dbClient[MONGO_DBNAME]

def insertdb(client_info):
	# Database Instance
	global db
	try:
		# Find if client exist
		item = db.bot_info.find_one({"_id": client_info["_id"]})
		client_info["last_active"] = datetime.datetime.now()
		if item is not None:
			# Update if client exist
			db.bot_info.update({"_id": item["_id"]}, {"$set": client_info})
		else:
			# Create new document for client and insert into db
			client_info["created_date"] = datetime.datetime.now()
			db.bot_info.insert(client_info)
	except Exception, ex:
		app.logger.info(str(ex))
	return False	

def makeClientInfo(req):
	# Generate a unique id
	bot_id = SHA.new("%s_%s" % (req.remote_addr, req.host)).hexdigest()
	client_info = {
	"_id": bot_id,
	"public_ip": req.remote_addr, 
	"active": True,
	"hostname": req.host,
	}
	return client_info


# Get Local IP
def getlocalIP():
	return socket.gethostbyname(socket.gethostname())

def getRandom(nByte):
	return Random.new().read(nByte)

def intToByteArray(i):
	return struct.pack("<I", i)

def byteArrayToInt(s):
	return struct.unpack("<I", putPadding(s))[0]

def byteArrayToHex(s):
	return "".join("%02X" % ord(i) for i in s)

# Mainly used to encrypt RC4 Key blob

# def rsaEncrypt(pubKeyPath, data):
# 	pubkeyFile = open(pubKeyPath, "r")
# 	encryptor = RSA.importKey(pubkeyFile.read())
# 	return encryptor.encrypt(data, None)[0]

# Building PKCS1 Blob
# Refs: http://winapi.freetechsecrets.com/win32/WIN32Building_a_Simple_Key_Blob.htm
# def buildPKCS1Blob(key):
# 	# Input Key is Big Endian, Windows System is Little Endian
# 	# convert key to Little Endian, Reverse order
# 	newKey = key[::-1]
# 	padding = 0
# 	type2 = 0x2
# 	# Whole block is 128 bytes
# 	# Subtract 3 bytes, 1 for Zero Padding, 1 for PKCS Type 0x2, 1 for End Padding
# 	randomPadding = getRandom(128 - 3 - len(newKey))
# 	fmtStr2 = "%dsb%dsbb" % (len(newKey),len(randomPadding))
# 	return struct.pack(fmtStr2, newKey, padding, randomPadding, type2, padding)


def putPadding(data):
	output = data
	remain = len(data) % 4
	if(remain != 0):
		for i in xrange(remain):
			output += "\x00"
		return output
	else:
		return output

# Build a SIMPLEKEYBLOB (Microsoft Cryptography KEYBLOB Format)
# References: https://msdn.microsoft.com/en-us/library/windows/desktop/aa375601(v=vs.85).aspx#simp_BLOB

# def constructBlob(key):					# KEYBLOB is PKCS #1 Type 2
# 	bType = 0x1 						# SIMPLEBLOB
# 	bVersion = 0x2 						# VERSION
# 	wReserved = 0x0000 					# PADDING
# 	BLOB_ALG_ID = 0x00006801	 		# ALG_ID RC4
# 	PUB_ALG_ID = 0x0000A400 			# ENCRYPT KEYBLOB by RSA
# 	keyLen = len(key)
# 	fmtStr = "<bbhII%ds" % keyLen
# 	return struct.pack(fmtStr, bType, bVersion, wReserved, BLOB_ALG_ID, PUB_ALG_ID, key )

# Simple checksum 
# Ripped from bot binary to C (see main.c) and converted to Python

def get_checksum(data):
	index = 0
	dataLen = len(data)
	table = []
	while (index < 256):
		counter = 8
		seed = index
		while(counter):
			if(seed & 1):
				seed = (seed >> 1) ^ 0xEDB88320;
			else:
				seed >>= 1
			counter -= 1
		table.append(seed)
		index += 1
	result = 0x0FFFFFFFF
	if(dataLen):
		i = 0
		while(dataLen):
			xorVal = ord(data[i])
			dataLen -= 1
			xorVal ^= result
			xorVal &= 0x0FF
			result >>= 8
			result ^= table[xorVal]
			i +=1
	return ~result & 0xFFFFFFFF

# Simple XOR cipher to encrypt data 
# Ripped from bot binary to C (see main.c) and converted to Python

def msgScramble(data, seed):
	paddingData = putPadding(data)
	dataLen = len(paddingData)
	i = 0
	v4 = (1664525 * seed + 1013904223) & 0xFFFFFFFF
	v5 = dataLen / 4
	result = ""
	if(v5 > 0):
		v9 = 4 * v5
		while(i<v5):
			element = byteArrayToInt(paddingData[i*4:i*4+4])
			element ^= v4
			v4 = (1664525 * v4 + 1013904223) & 0xFFFFFFFF
			i += 1
			result += intToByteArray(element)
	return result

# Craft Request Body, for testing only

# def requestBody(data, s1, s2,rsaBlob, blobLen):
# 	seed_1 = s1
# 	seed_2 = s2
# 	checksum = 0
# 	cipherBlob = struct.pack("<I%ds" % blobLen, blobLen, rsaBlob)
# 	scrambleBlob = msgScramble(cipherBlob, seed_2)
# 	checksum = get_checksum(scrambleBlob+data)
# 	dataLen = len(data)
# 	fmtStr = "<III%ds%ds" %(blobLen+4, dataLen)
# 	result = struct.pack(fmtStr, seed_1, seed_2, checksum, scrambleBlob, data)
# 	return result 

# Craft reponse body

def responseBody(data, s2, rsaBlob, blobLen):
	# This is constant
	# The bot gets this value and divide for 0x1ECB, if the remaining is 2, continuse
	# So the simplest method to make the condition always true is set the value to 0x1ECD (0x1ECB + 2)
	# 0x1ECD % 0x1ECB = 2
	seed_1 = 0x1ECD
	seed_2 = s2
	checksum = 0
	# RSABLOB size must be scrambled invidiually
	scrambleSize = msgScramble(intToByteArray(blobLen), seed_2)
	cipherBlob = struct.pack("%ds" % blobLen, rsaBlob)
	# Scramble rsablob
	scrambleBlob = msgScramble(cipherBlob, seed_2)
	# Then Put Scrambled blob size before scrambled RSABLOB
	scrambleBlob = scrambleSize + scrambleBlob
	# Get Checksum of whole blob (scrambled blob and encrypted data)
	checksum = get_checksum(scrambleBlob+data)
	dataLen = len(data)
	# 20 bytes padding
	padding = "\x00" * 20
	fmtStr = "<%dsIII%ds%ds" %(len(padding), blobLen+4, dataLen)
	result = struct.pack(fmtStr, padding, seed_1, seed_2, checksum, scrambleBlob, data)
	return result 

# Craft Data structure and transform to Base64
def craftData(plainData):
	# Fixed RC4 key, generated by main.c
	rc4Key = open("rc4plain.blob", "rb").read()[12:]
	# Encrypt plain data using rc4 with new generated key
	cipherData = ARC4.new(rc4Key).encrypt(plainData)
	seed_2 = byteArrayToInt(getRandom(4))
	keyBlob = open("session_rsa.blob", "rb").read()
#	pkBlob = buildPKCS1Blob(rc4Key)
#	keyBlob = constructBlob(rsaEncrypt("clientPub.pub",pkBlob))	
	# This response format is grabbed from binary file itself
	return "<img src=\"data:image/jpeg;base64, %s\" />" % base64.b64encode(responseBody(cipherData, seed_2, keyBlob, len(keyBlob)))

# Fake CnC Response
def msgCnC():
	# An invalid Header, when malware receive this it will exit loop and sleep for 1 day before performing the next action
	header = 0x401
	# Fulfill the Message blob
	badPadding = "\xBA\xAD\xF0\x0D"
	plainData = struct.pack("<I12s", header, badPadding*3)
	return craftData(plainData)

# lyuchta.org Response
def msgBeacon():
	# Dummy Padding
	badPadding = "\xBA\xAD\xF0\x0D"
	# 0x03 to elimilate the Loop of checking beacon
	plainData = struct.pack("<I12s", 0x3, badPadding*3)
	return craftData(plainData)

# Receive request from bot and return value
@app.route("/", methods=["POST", "GET"])
def index():
	# Beacon domain
	if "lyuchta.org" in request.url:
		if request.data != None:
			data = request.data
			fmtStr1 = "<III144s"
			fmtSize1 = struct.calcsize(fmtStr1)
			dataLen = len(data)
			remainLen = dataLen - fmtSize1
			# Extract data fields sent from client
			# Unluckily we have no private RSA Key to decrypt these data
			seed_1, seed_2, checksum, rsablob = struct.unpack(fmtStr1, data[:fmtSize1])
			fmtStr2 = "%ds" % remainLen
			encryptedData = struct.unpack(fmtStr2, data[fmtSize1:])[0]
			app.logger.debug("%s -> %s (BEACON),Seed_1:%08X,Seed_2:%08X,Checksum:%08X,KeyBlob:%s,Data:%s" % (request.remote_addr, request.url, seed_1, seed_2, checksum, byteArrayToHex(rsablob), byteArrayToHex(encryptedData)))
			# Write to database
			insertdb(makeClientInfo(request))
			return msgBeacon()
	# CnC or other domain, return dummy data
	else:
		app.logger.debug("%s -> %s (CONTROL),Data: %s" % (request.remote_addr, request.url, byteArrayToHex(request.data)))
		# Write to database
		insertdb(makeClientInfo(request))
		return msgCnC()

# Setup Logging and start Flask built-in server with desired port and local ip

def startServer():
	ip = getlocalIP()
	PORT = 80
	formatter = logging.Formatter("[%(asctime)s] - %(message)s")
	fileHandler = logging.FileHandler("client.log")
	# Log to File
	fileHandler.setFormatter(formatter)
	fileHandler.setLevel(logging.DEBUG)
	app.logger.addHandler(fileHandler)
	initdb()
	# Log to Console
	# streamHandler = logging.StreamHandler()
	# streamHandler.setFormatter(formatter)
	# streamHandler.setLevel(logging.DEBUG)
	# app.logger.addHandler(streamHandler)
	app.run(debug=True, host=ip, port=PORT, threaded=True)

# Unitest for Algorithm
# Because all of the algos were converted from C code, so i must set up this unittest to check whether they worked or not
# And happily to announce that they're working correctly. Yay!

# def unitTest():
# 	#rc4Key = getRandom(128)
# 	#rsablob = constructBlob(rc4Key)
# 	# These values a
# 	rsablob = "\x01\x02\x00\x00\x01\x68\x00\x00\x00\xA4\x00\x00\xC1\x01\x5F\x7F\xCD\x7B\x51\x1D\x2D\x95\xB6\x43\x30\xF7\x80\xCB\xF7\x57\x4C\x13\xDC\x31\x75\x2F\xF4\xA5\x23\xEE\x66\x55\x44\x94\x10\x33\xAF\x9B\x28\x9E\xAE\x47\x16\x1E\xD1\xB2\x87\x74\x7B\x64\x71\x6F\xFD\xB2\x6D\x73\x26\x54\x49\xA1\xE9\x6B\x35\x12\x9C\xD0\x24\x86\x69\xC4\xB5\xDB\x47\x77\x44\xA3\xE5\x31\xE1\x7B\xD3\x60\x3E\x18\xF6\xCE\x0E\x8E\x8E\xDD\x33\xD4\x4B\xCC\x1B\xE5\xF8\xE4\x6E\xC1\xFE\xBA\xB2\x1D\xD2\xAF\xB4\x90\x68\xC8\x8E\x88\x2B\x92\x86\x92\xDD\x63\x32\x4D\xA6\xA1\x93\x85\x58\x4B\x63\x39\x7A\xBB"
# 	seed_1 = byteArrayToInt("\xAD\x4B\x3E\x9B")
# 	seed_2 = byteArrayToInt("\xED\xCC\x38\x23")
# 	sample_data = "\xF3\xAA\xA6\x14\x7B\x87\xBA\xC4\x7B\xA8\x7C\x5C\xA5\x2D\x6E\x6F\x70\xBB\x54\xD5\x9A\x1D\xB4\x23\xE6\xBC\x36\xB2\x46\x0F\x03\x72\xCF\x04\x08\x95\xEE\x22\xF4\xC1\xD9\xA8\x81\x44\xB9\x83\x2A\x2F\xA4\x5C\x09\xDD\x0B\xEF\x3A\xE1\x33\xD9\xF9\x29\x9B\x67\xB4\x80\xF1\x5E\x72\x8A\xD6\x5D\xEA\x3C\x0B\xA9\x8F\x18\x8F\xF3\xE7\xCF\xBE\xF7\x7B\x28\x39\xDA\x69\x31\x8C\xAF\x26\x9C\x15\x39\x64\x26\xA1\xB7\xD6\xD4\xD6\x9F\xA2\xA3\x26\x17\x47\xDB\xA3\x82\x61\x49\x83\xFA\xB7\xCF\xB4\x4E\xC8\x90\xE4\xF6\xD0\x45\x4B\x09\x7E\x91\x5E\x24\x17\xA5\xFA\x88\x9F\x73\xA8\x8D\x41\xAC\xE3\xA7\xE7\xD7\x67\x59\xFD\x5A\xC9\xDD\xBA\xBC\x38\x7C\x75\xEC\x55\xDC\xA1\xA9\x76\x23\xCC\xF6\x0B\xEB\x8A\xC7\xB4\xD5\x84\x94\x85\x0A\x78\x16\xBF\x5F\x42\x7C\xAE\xAA\x53\x1F\xF9\x3D\x11\x49\x23\x50\xB1\xB4\xDF\x15\x07\xAC\x92\xE3\xBD\xC9\x44\xFD\x72\xDA\x57\x96\x3A\x94\x3C\x01\xDF\x29\x5B\x24\xB4\x57\x63\xF6\xDC\x4F\x0E\x90\x3C\xF1\xA6\xE6\x20\x9F\xE7\xFB\xE9\xFB\xED\xA8\x37\xEB\x04\xB4\xC2\x61\x77\xD2\x15\xB2\x6F\x3E\x0B\x25\xDB\x46\x5B\x8A\xD5\xD0\xD2\xDD\xBF\xC9\x31\x45\x59\x85\xFB\x61\x69\x16\xA1\xDD\xE1\xE3\x18\xBA\xAF\x14\x1E"
# 	response = requestBody(sample_data, seed_1, seed_2, rsablob, len(rsablob))
# 	f = open("msgblob.bin", "wb")
# 	f.write(response)
# 	f.close()
# 	craftData("This is plainText")

if __name__ == "__main__":
	# unitTest()
	startServer()
