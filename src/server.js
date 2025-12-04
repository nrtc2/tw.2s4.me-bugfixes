var fs = require("fs");
var http = require("http");
var querystring = require("querystring");
var url_parse = require("url");
var ws = require("ws");
var sql = require("better-sqlite3");
var cookieParser = require('cookie-parser');
var crypto = require("crypto");
var express = require("express");
var path = require("path"); // essential
const { notDeepEqual } = require("assert");
var anonymous = [] // so suspicious!

let customSettingsPath = process.argv[2];
var settings = JSON.parse(fs.readFileSync(
	(customSettingsPath && customSettingsPath.includes("/")) ? customSettingsPath :
	"../data/settings.json"
));

console.log("Starting server...");

var port = settings.port;
var muteDbPath = settings.db.chatMutePath;
var staticPath = "../client";

var db = sql(settings.db.path);


var pw_encryption = "sha512WithRSAEncryption";
function encryptHash(pass, salt) {
	if (!salt) {
		salt = crypto.randomBytes(10).toString("hex");
	}
	var hsh = crypto.createHmac(pw_encryption, salt).update(pass).digest("hex");
	var hash = pw_encryption + "$" + salt + "$" + hsh;
	return hash;
}

function checkHash(hash, pass) {
	if (typeof pass !== "string") return false;
	if (typeof hash !== "string") return false;
	hash = hash.split("$");
	if (hash.length !== 3) return false;
	return encryptHash(pass, hash[1]) === hash.join("$");
}



(function () {
	"use strict";

	// Serializes a value to a MessagePack byte array.
	//
	// data: The value to serialize. This can be a scalar, array or object.
	// options: An object that defined additional options.
	// - multiple: Indicates whether multiple values in data are concatenated to multiple MessagePack arrays.
	// - invalidTypeReplacement: The value that is used to replace values of unsupported types, or a function that returns such a value, given the original value as parameter.
	function serialize(data, options) {
		if (options && options.multiple && !Array.isArray(data)) {
			throw new Error("Invalid argument type: Expected an Array to serialize multiple values.");
		}
		const pow32 = 0x100000000;   // 2^32
		let floatBuffer, floatView;
		let array = new Uint8Array(128);
		let length = 0;
		if (options && options.multiple) {
			for (let i = 0; i < data.length; i++) {
				append(data[i]);
			}
		}
		else {
			append(data);
		}
		return array.subarray(0, length);

		function append(data, isReplacement) {
			switch (typeof data) {
				case "undefined":
					appendNull(data);
					break;
				case "boolean":
					appendBoolean(data);
					break;
				case "number":
					appendNumber(data);
					break;
				case "string":
					appendString(data);
					break;
				case "object":
					if (data === null)
						appendNull(data);
					else if (data instanceof Date)
						appendDate(data);
					else if (Array.isArray(data))
						appendArray(data);
					else if (data instanceof Uint8Array || data instanceof Uint8ClampedArray)
						appendBinArray(data);
					else if (data instanceof Int8Array || data instanceof Int16Array || data instanceof Uint16Array ||
						data instanceof Int32Array || data instanceof Uint32Array ||
						data instanceof Float32Array || data instanceof Float64Array)
						appendArray(data);
					else
						appendObject(data);
					break;
				default:
					if (!isReplacement && options && options.invalidTypeReplacement) {
						if (typeof options.invalidTypeReplacement === "function")
							append(options.invalidTypeReplacement(data), true);
						else
							append(options.invalidTypeReplacement, true);
					}
					else {
						throw new Error("Invalid argument type: The type '" + (typeof data) + "' cannot be serialized.");
					}
			}
		}

		function appendNull(data) {
			appendByte(0xc0);
		}

		function appendBoolean(data) {
			appendByte(data ? 0xc3 : 0xc2);
		}

		function appendNumber(data) {
			if (isFinite(data) && Math.floor(data) === data) {
				// Integer
				if (data >= 0 && data <= 0x7f) {
					appendByte(data);
				}
				else if (data < 0 && data >= -0x20) {
					appendByte(data);
				}
				else if (data > 0 && data <= 0xff) {   // uint8
					appendBytes([0xcc, data]);
				}
				else if (data >= -0x80 && data <= 0x7f) {   // int8
					appendBytes([0xd0, data]);
				}
				else if (data > 0 && data <= 0xffff) {   // uint16
					appendBytes([0xcd, data >>> 8, data]);
				}
				else if (data >= -0x8000 && data <= 0x7fff) {   // int16
					appendBytes([0xd1, data >>> 8, data]);
				}
				else if (data > 0 && data <= 0xffffffff) {   // uint32
					appendBytes([0xce, data >>> 24, data >>> 16, data >>> 8, data]);
				}
				else if (data >= -0x80000000 && data <= 0x7fffffff) {   // int32
					appendBytes([0xd2, data >>> 24, data >>> 16, data >>> 8, data]);
				}
				else if (data > 0 && data <= 0xffffffffffffffff) {   // uint64
					// Split 64 bit number into two 32 bit numbers because JavaScript only regards
					// 32 bits for bitwise operations.
					let hi = data / pow32;
					let lo = data % pow32;
					appendBytes([0xd3, hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
				}
				else if (data >= -0x8000000000000000 && data <= 0x7fffffffffffffff) {   // int64
					appendByte(0xd3);
					appendInt64(data);
				}
				else if (data < 0) {   // below int64
					appendBytes([0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0]);
				}
				else {   // above uint64
					appendBytes([0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
				}
			}
			else {
				// Float
				if (!floatView) {
					floatBuffer = new ArrayBuffer(8);
					floatView = new DataView(floatBuffer);
				}
				floatView.setFloat64(0, data);
				appendByte(0xcb);
				appendBytes(new Uint8Array(floatBuffer));
			}
		}

		function appendString(data) {
			let bytes = encodeUtf8(data);
			let length = bytes.length;

			if (length <= 0x1f)
				appendByte(0xa0 + length);
			else if (length <= 0xff)
				appendBytes([0xd9, length]);
			else if (length <= 0xffff)
				appendBytes([0xda, length >>> 8, length]);
			else
				appendBytes([0xdb, length >>> 24, length >>> 16, length >>> 8, length]);

			appendBytes(bytes);
		}

		function appendArray(data) {
			let length = data.length;

			if (length <= 0xf)
				appendByte(0x90 + length);
			else if (length <= 0xffff)
				appendBytes([0xdc, length >>> 8, length]);
			else
				appendBytes([0xdd, length >>> 24, length >>> 16, length >>> 8, length]);

			for (let index = 0; index < length; index++) {
				append(data[index]);
			}
		}

		function appendBinArray(data) {
			let length = data.length;

			if (length <= 0xf)
				appendBytes([0xc4, length]);
			else if (length <= 0xffff)
				appendBytes([0xc5, length >>> 8, length]);
			else
				appendBytes([0xc6, length >>> 24, length >>> 16, length >>> 8, length]);

			appendBytes(data);
		}

		function appendObject(data) {
			let length = 0;
			for (let key in data) {
				if (data[key] !== undefined) {
					length++;
				}
			}

			if (length <= 0xf)
				appendByte(0x80 + length);
			else if (length <= 0xffff)
				appendBytes([0xde, length >>> 8, length]);
			else
				appendBytes([0xdf, length >>> 24, length >>> 16, length >>> 8, length]);

			for (let key in data) {
				let value = data[key];
				if (value !== undefined) {
					append(key);
					append(value);
				}
			}
		}

		function appendDate(data) {
			let sec = data.getTime() / 1000;
			if (data.getMilliseconds() === 0 && sec >= 0 && sec < 0x100000000) {   // 32 bit seconds
				appendBytes([0xd6, 0xff, sec >>> 24, sec >>> 16, sec >>> 8, sec]);
			}
			else if (sec >= 0 && sec < 0x400000000) {   // 30 bit nanoseconds, 34 bit seconds
				let ns = data.getMilliseconds() * 1000000;
				appendBytes([0xd7, 0xff, ns >>> 22, ns >>> 14, ns >>> 6, ((ns << 2) >>> 0) | (sec / pow32), sec >>> 24, sec >>> 16, sec >>> 8, sec]);
			}
			else {   // 32 bit nanoseconds, 64 bit seconds, negative values allowed
				let ns = data.getMilliseconds() * 1000000;
				appendBytes([0xc7, 12, 0xff, ns >>> 24, ns >>> 16, ns >>> 8, ns]);
				appendInt64(sec);
			}
		}

		function appendByte(byte) {
			if (array.length < length + 1) {
				let newLength = array.length * 2;
				while (newLength < length + 1)
					newLength *= 2;
				let newArray = new Uint8Array(newLength);
				newArray.set(array);
				array = newArray;
			}
			array[length] = byte;
			length++;
		}

		function appendBytes(bytes) {
			if (array.length < length + bytes.length) {
				let newLength = array.length * 2;
				while (newLength < length + bytes.length)
					newLength *= 2;
				let newArray = new Uint8Array(newLength);
				newArray.set(array);
				array = newArray;
			}
			array.set(bytes, length);
			length += bytes.length;
		}

		function appendInt64(value) {
			// Split 64 bit number into two 32 bit numbers because JavaScript only regards 32 bits for
			// bitwise operations.
			let hi, lo;
			if (value >= 0) {
				// Same as uint64
				hi = value / pow32;
				lo = value % pow32;
			}
			else {
				// Split absolute value to high and low, then NOT and ADD(1) to restore negativity
				value++;
				hi = Math.abs(value) / pow32;
				lo = Math.abs(value) % pow32;
				hi = ~hi;
				lo = ~lo;
			}
			appendBytes([hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
		}
	}

	// Deserializes a MessagePack byte array to a value.
	//
	// array: The MessagePack byte array to deserialize. This must be an Array or Uint8Array containing bytes, not a string.
	// options: An object that defined additional options.
	// - multiple: Indicates whether multiple concatenated MessagePack arrays are returned as an array.
	function deserialize(array, options) {
		const pow32 = 0x100000000;   // 2^32
		let pos = 0;
		if (array instanceof ArrayBuffer) {
			array = new Uint8Array(array);
		}
		if (typeof array !== "object" || typeof array.length === "undefined") {
			throw new Error("Invalid argument type: Expected a byte array (Array or Uint8Array) to deserialize.");
		}
		if (!array.length) {
			throw new Error("Invalid argument: The byte array to deserialize is empty.");
		}
		if (!(array instanceof Uint8Array)) {
			array = new Uint8Array(array);
		}
		let data;
		if (options && options.multiple) {
			// Read as many messages as are available
			data = [];
			while (pos < array.length) {
				data.push(read());
			}
		}
		else {
			// Read only one message and ignore additional data
			data = read();
		}
		return data;

		function read() {
			const byte = array[pos++];
			if (byte >= 0x00 && byte <= 0x7f) return byte;   // positive fixint
			if (byte >= 0x80 && byte <= 0x8f) return readMap(byte - 0x80);   // fixmap
			if (byte >= 0x90 && byte <= 0x9f) return readArray(byte - 0x90);   // fixarray
			if (byte >= 0xa0 && byte <= 0xbf) return readStr(byte - 0xa0);   // fixstr
			if (byte === 0xc0) return null;   // nil
			if (byte === 0xc1) throw new Error("Invalid byte code 0xc1 found.");   // never used
			if (byte === 0xc2) return false;   // false
			if (byte === 0xc3) return true;   // true
			if (byte === 0xc4) return readBin(-1, 1);   // bin 8
			if (byte === 0xc5) return readBin(-1, 2);   // bin 16
			if (byte === 0xc6) return readBin(-1, 4);   // bin 32
			if (byte === 0xc7) return readExt(-1, 1);   // ext 8
			if (byte === 0xc8) return readExt(-1, 2);   // ext 16
			if (byte === 0xc9) return readExt(-1, 4);   // ext 32
			if (byte === 0xca) return readFloat(4);   // float 32
			if (byte === 0xcb) return readFloat(8);   // float 64
			if (byte === 0xcc) return readUInt(1);   // uint 8
			if (byte === 0xcd) return readUInt(2);   // uint 16
			if (byte === 0xce) return readUInt(4);   // uint 32
			if (byte === 0xcf) return readUInt(8);   // uint 64
			if (byte === 0xd0) return readInt(1);   // int 8
			if (byte === 0xd1) return readInt(2);   // int 16
			if (byte === 0xd2) return readInt(4);   // int 32
			if (byte === 0xd3) return readInt(8);   // int 64
			if (byte === 0xd4) return readExt(1);   // fixext 1
			if (byte === 0xd5) return readExt(2);   // fixext 2
			if (byte === 0xd6) return readExt(4);   // fixext 4
			if (byte === 0xd7) return readExt(8);   // fixext 8
			if (byte === 0xd8) return readExt(16);   // fixext 16
			if (byte === 0xd9) return readStr(-1, 1);   // str 8
			if (byte === 0xda) return readStr(-1, 2);   // str 16
			if (byte === 0xdb) return readStr(-1, 4);   // str 32
			if (byte === 0xdc) return readArray(-1, 2);   // array 16
			if (byte === 0xdd) return readArray(-1, 4);   // array 32
			if (byte === 0xde) return readMap(-1, 2);   // map 16
			if (byte === 0xdf) return readMap(-1, 4);   // map 32
			if (byte >= 0xe0 && byte <= 0xff) return byte - 256;   // negative fixint
			//console.debug("msgpack array:", array);
			throw new Error("Invalid byte value '" + byte + "' at index " + (pos - 1) + " in the MessagePack binary data (length " + array.length + "): Expecting a range of 0 to 255. This is not a byte array.");
		}

		function readInt(size) {
			let value = 0;
			let first = true;
			while (size-- > 0) {
				if (first) {
					let byte = array[pos++];
					value += byte & 0x7f;
					if (byte & 0x80) {
						value -= 0x80;   // Treat most-significant bit as -2^i instead of 2^i
					}
					first = false;
				}
				else {
					value *= 256;
					value += array[pos++];
				}
			}
			return value;
		}

		function readUInt(size) {
			let value = 0;
			while (size-- > 0) {
				value *= 256;
				value += array[pos++];
			}
			return value;
		}

		function readFloat(size) {
			let view = new DataView(array.buffer, pos + array.byteOffset, size);
			pos += size;
			if (size === 4)
				return view.getFloat32(0, false);
			if (size === 8)
				return view.getFloat64(0, false);
		}

		function readBin(size, lengthSize) {
			if (size < 0) size = readUInt(lengthSize);
			let data = array.subarray(pos, pos + size);
			pos += size;
			return data;
		}

		function readMap(size, lengthSize) {
			if (size < 0) size = readUInt(lengthSize);
			let data = {};
			while (size-- > 0) {
				let key = read();
				data[key] = read();
			}
			return data;
		}

		function readArray(size, lengthSize) {
			if (size < 0) size = readUInt(lengthSize);
			let data = [];
			while (size-- > 0) {
				data.push(read());
			}
			return data;
		}

		function readStr(size, lengthSize) {
			if (size < 0) size = readUInt(lengthSize);
			let start = pos;
			pos += size;
			return decodeUtf8(array, start, size);
		}

		function readExt(size, lengthSize) {
			if (size < 0) size = readUInt(lengthSize);
			let type = readUInt(1);
			let data = readBin(size);
			switch (type) {
				case 255:
					return readExtDate(data);
			}
			return { type: type, data: data };
		}

		function readExtDate(data) {
			if (data.length === 4) {
				let sec = ((data[0] << 24) >>> 0) +
					((data[1] << 16) >>> 0) +
					((data[2] << 8) >>> 0) +
					data[3];
				return new Date(sec * 1000);
			}
			if (data.length === 8) {
				let ns = ((data[0] << 22) >>> 0) +
					((data[1] << 14) >>> 0) +
					((data[2] << 6) >>> 0) +
					(data[3] >>> 2);
				let sec = ((data[3] & 0x3) * pow32) +
					((data[4] << 24) >>> 0) +
					((data[5] << 16) >>> 0) +
					((data[6] << 8) >>> 0) +
					data[7];
				return new Date(sec * 1000 + ns / 1000000);
			}
			if (data.length === 12) {
				let ns = ((data[0] << 24) >>> 0) +
					((data[1] << 16) >>> 0) +
					((data[2] << 8) >>> 0) +
					data[3];
				pos -= 8;
				let sec = readInt(8);
				return new Date(sec * 1000 + ns / 1000000);
			}
			throw new Error("Invalid data length for a date value.");
		}
	}

	// Encodes a string to UTF-8 bytes.
	function encodeUtf8(str) {
		// Prevent excessive array allocation and slicing for all 7-bit characters
		let ascii = true, length = str.length;
		for (let x = 0; x < length; x++) {
			if (str.charCodeAt(x) > 127) {
				ascii = false;
				break;
			}
		}

		// Based on: https://gist.github.com/pascaldekloe/62546103a1576803dade9269ccf76330
		let i = 0, bytes = new Uint8Array(str.length * (ascii ? 1 : 4));
		for (let ci = 0; ci !== length; ci++) {
			let c = str.charCodeAt(ci);
			if (c < 128) {
				bytes[i++] = c;
				continue;
			}
			if (c < 2048) {
				bytes[i++] = c >> 6 | 192;
			}
			else {
				if (c > 0xd7ff && c < 0xdc00) {
					if (++ci >= length)
						throw new Error("UTF-8 encode: incomplete surrogate pair");
					let c2 = str.charCodeAt(ci);
					if (c2 < 0xdc00 || c2 > 0xdfff)
						throw new Error("UTF-8 encode: second surrogate character 0x" + c2.toString(16) + " at index " + ci + " out of range");
					c = 0x10000 + ((c & 0x03ff) << 10) + (c2 & 0x03ff);
					bytes[i++] = c >> 18 | 240;
					bytes[i++] = c >> 12 & 63 | 128;
				}
				else bytes[i++] = c >> 12 | 224;
				bytes[i++] = c >> 6 & 63 | 128;
			}
			bytes[i++] = c & 63 | 128;
		}
		return ascii ? bytes : bytes.subarray(0, i);
	}

	// Decodes a string from UTF-8 bytes.
	function decodeUtf8(bytes, start, length) {
		// Based on: https://gist.github.com/pascaldekloe/62546103a1576803dade9269ccf76330
		let i = start, str = "";
		length += start;
		while (i < length) {
			let c = bytes[i++];
			if (c > 127) {
				if (c > 191 && c < 224) {
					if (i >= length)
						throw new Error("UTF-8 decode: incomplete 2-byte sequence");
					c = (c & 31) << 6 | bytes[i++] & 63;
				}
				else if (c > 223 && c < 240) {
					if (i + 1 >= length)
						throw new Error("UTF-8 decode: incomplete 3-byte sequence");
					c = (c & 15) << 12 | (bytes[i++] & 63) << 6 | bytes[i++] & 63;
				}
				else if (c > 239 && c < 248) {
					if (i + 2 >= length)
						throw new Error("UTF-8 decode: incomplete 4-byte sequence");
					c = (c & 7) << 18 | (bytes[i++] & 63) << 12 | (bytes[i++] & 63) << 6 | bytes[i++] & 63;
				}
				else throw new Error("UTF-8 decode: unknown multibyte start 0x" + c.toString(16) + " at index " + (i - 1));
			}
			if (c <= 0xffff) str += String.fromCharCode(c);
			else if (c <= 0x10ffff) {
				c -= 0x10000;
				str += String.fromCharCode(c >> 10 | 0xd800)
				str += String.fromCharCode(c & 0x3FF | 0xdc00)
			}
			else throw new Error("UTF-8 decode: code point 0x" + c.toString(16) + " exceeds UTF-16 reach");
		}
		return str;
	}

	// The exported functions
	let msgpack = {
		serialize: serialize,
		deserialize: deserialize,

		// Compatibility with other libraries
		encode: serialize,
		decode: deserialize
	};

	global.msgpack = msgpack;

})();
function mask_ip(ip) {
	if (ip.includes(':')) {
		// ipv6
		return ip.replace(/^([0-9a-fA-F]+):.+$/, "$1:X:X:X:X:X:X:X");
	} else {
		// ipv4
		return ip.replace(/^(\d+)\.\d+\.\d+\.\d+$/, "$1.X.X.X");
	}
}
const WHITELIST_FILE = settings.db.whitelistPath

function loadWhitelist() {
	try {
		return JSON.parse(fs.readFileSync(WHITELIST_FILE));
	} catch {
		return [false, []];
	}
}

function saveWhitelist(data) {
	fs.writeFileSync(WHITELIST_FILE, JSON.stringify(data, null, 2));
}
function isWhitelisted(username) {
    const [enabled, users] = loadWhitelist();
    if (!enabled) return true; // whitelist disabled, allow all
    return users.includes(username);
}
var httpServer;
async function runserver() {
	var twrApp = express();
	twrApp.use(express.urlencoded({ extended: true }));
	twrApp.use(express.json());
	twrApp.use(cookieParser());

	httpServer = http.createServer(twrApp);

	// 1. Admin POST routes first (dynamic)
	function requireAuth(req, res, next) {
		const token = req.cookies?.admin_session;
		if (!token) return res.status(403).send("Not Authenticated")
		next();
	}


	function createAdminRequest(actionPath, handler, opts = { noR: false, get: false }) {
		const useAuth = !opts.noR;
		if (useAuth) {
			twrApp.post(`/admin/${actionPath}`, requireAuth, handler);
		} else {
			twrApp.post(`/admin/${actionPath}`, handler);
		}
		if (opts.get) {
			if (useAuth) {
				twrApp.get(`/admin/${actionPath}`, requireAuth, handler);
			} else {
				twrApp.get(`/admin/${actionPath}`, handler);
			}
		}
	}



	createAdminRequest('credentials', (req, res) => {

		const { username, password } = req.body;
		if (!username || !password) return res.json({ success: false });

		const user = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username);
		if (!user) return res.json({ success: false });

		const isValid = checkHash(user.password, password);
		if (!isValid) return res.json({ success: false });

		const isAuthenticated = settings.adminList.includes(username)
		if (!isAuthenticated) return res.json({ success: false })
		const token = crypto.randomBytes(16).toString('hex');
		res.cookie('admin_session', token, {
			maxAge: 7 * 24 * 60 * 60 * 1000,
			httpOnly: true,
			path: '/admin',
			sameSite: 'lax',
			secure: false
		});

		res.json({ success: true });
	}, { noR: true });

	createAdminRequest('check', (req, res) => {
		const token = req.cookies?.admin_session;

		if (!token) {
			return res.json({ authenticated: false });
		}
		res.json({ authenticated: true });
	}, { noR: true });
	// BEGIN
	createAdminRequest('uptime', (req, res) => {
		const token = req.cookies?.admin_session;

		if (!token) {
			return res.json({ authenticated: false });
		}

		const uptimeSeconds = process.uptime();
		res.json({ authenticated: true, uptime: uptimeSeconds });
	}, { get: true });
	createAdminRequest('logout', (req, res) => {
		const token = req.cookies?.admin_session;

		if (!token) {
			return res.json({ authenticated: false });
		}
		res.clearCookie('admin_session', { path: '/admin' });
		res.json({ refresh: true })
	}, { get: true })

	createAdminRequest('remote', (req, res) => {
		const script = req.body.script;
		const clientId = req.body.id;

		// if broadcasting to all, skip id_not_found
		if (clientId === "all") {
			// send to all connected clients
			broadcast(encodeMsgpack({ rs: script }));

			return res.json({ success: true, broadcast: true });
		}

		// otherwise, normal single-client handling
		const ws = clients[clientId?.toString()];
		if (!ws) {
			return res.status(400).json({ id_not_found: true });
		}

		try {
			send(ws, encodeMsgpack({ rs: script }));
			res.json({ success: true });
		} catch (err) {
			res.status(500).json({ success: false, error: err.message });
		}
	});

	function buildUserResponse(user, req) {
		const client = Object.values(clients).find(c => c.sdata?.authUser === user.username);
		const online = !!client;

		let where = null;
		if (client) {
			const ns = client.sdata.connectedWorldNamespace;
			const name = client.sdata.connectedWorldName;

			if (ns === 'textwall' && name === 'main') {
				where = '';
			} else {
				const pathParts = [];
				if (ns !== 'textwall') pathParts.push(ns);
				if (name !== 'main') pathParts.push(name);
				where = '~' + pathParts.join('/');
			}
		}

		const worldsData = db.prepare("SELECT * FROM worlds WHERE id=? OR namespace=?").all(user.username, user.username);
		const serverHost = req.headers.host;

		const worlds = worldsData.map(world => {
			const url = world.namespace === 'main'
				? `http://${serverHost}/~${user.username}`
				: `http://${serverHost}/~${user.username}/${world.namespace}`;
			return { [world.name]: url, id: world.id, attr: JSON.parse(world.attributes) };
		});

		return {
			user: user.username,
			online,
			where,
			id: user.id,
			date_joined: user.date_joined,
			worlds
		};
	}

	// single
	createAdminRequest('user', (req, res) => {
		const user_id = req.query.id;
		const username = req.query.name;

		let user;

		if (user_id) {
			user = db.prepare("SELECT * FROM users WHERE id=?").get(user_id);
		} else if (username) {
			user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
		} else {
			return res.json({ noquery: true });
		}

		if (!user) return res.json({ notfound: true });

		res.json(buildUserResponse(user, req));
	}, { get: true });

	// search


	const PAGE_SIZE = 10
	createAdminRequest('user/search', (req, res) => {
		const q = req.query.q || '';
		const page = parseInt(req.query.page) || 1;
		const pageSize = PAGE_SIZE;

		// Count total matching users
		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM users WHERE username LIKE ?")
			.get(`%${q}%`).count;

		const totalPages = Math.ceil(totalItems / pageSize);

		// Fetch only the requested page
		const users = db.prepare("SELECT * FROM users WHERE username LIKE ? LIMIT ? OFFSET ?")
			.all(`%${q}%`, pageSize, (page - 1) * pageSize);

		res.json({
			page,
			pageSize,
			totalItems,
			totalPages,
			data: users.map(u => buildUserResponse(u, req))
		});
	}, { get: true });

	// oldest
	createAdminRequest('user/oldest', (req, res) => {
		const page = parseInt(req.query.page) || 1;

		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
		const totalPages = Math.ceil(totalItems / PAGE_SIZE);
		if (page < 1 || page > totalPages) return res.json({ invalid_page: true });

		const offset = (page - 1) * PAGE_SIZE;
		const users = db.prepare("SELECT * FROM users ORDER BY date_joined ASC LIMIT ? OFFSET ?")
			.all(PAGE_SIZE, offset);

		res.json({
			page,
			PAGE_SIZE,
			totalItems,
			totalPages,
			data: users.map(u => buildUserResponse(u, req))
		});
	}, { get: true });

	// newest
	createAdminRequest('user/newest', (req, res) => {
		const page = parseInt(req.query.page) || 1;

		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
		const totalPages = Math.ceil(totalItems / PAGE_SIZE);
		if (page < 1 || page > totalPages) return res.json({ invalid_page: true });

		const offset = (page - 1) * PAGE_SIZE;
		const users = db.prepare("SELECT * FROM users ORDER BY date_joined DESC LIMIT ? OFFSET ?")
			.all(PAGE_SIZE, offset);

		res.json({
			page,
			PAGE_SIZE,
			totalItems,
			totalPages,
			data: users.map(u => buildUserResponse(u, req))
		});
	}, { get: true });

	// alphabetically
	createAdminRequest('user/alphabetic', (req, res) => {
		const page = parseInt(req.query.page) || 1;

		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
		const totalPages = Math.ceil(totalItems / PAGE_SIZE);
		if (page < 1 || page > totalPages) return res.json({ invalid_page: true });

		const offset = (page - 1) * PAGE_SIZE;
		const users = db.prepare("SELECT * FROM users ORDER BY username ASC LIMIT ? OFFSET ?")
			.all(PAGE_SIZE, offset);

		res.json({
			page,
			PAGE_SIZE,
			totalItems,
			totalPages,
			data: users.map(u => buildUserResponse(u, req))
		});
	}, { get: true });



	createAdminRequest('worlds', async (req, res) => {
		const page = parseInt(req.query.page) || 1; // default page 1
		const PAGE_SIZE = 10; // items per page

		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM worlds").get().count;
		const totalPages = Math.ceil(totalItems / PAGE_SIZE);

		if (page > totalPages || page < 1) {
			return res.json({ invalid_page: true });
		}

		const offset = (page - 1) * PAGE_SIZE;

		const worlds = db.prepare("SELECT * FROM worlds LIMIT ? OFFSET ?").all(PAGE_SIZE, offset);
		const serverHost = req.headers.host;

		const transformed = worlds.map(world => {
			const attributes = JSON.parse(world.attributes);
			let link = world.namespace === 'textwall'
				? `http://${serverHost}`
				: world.name === 'main'
					? `http://${serverHost}/~${world.namespace}`
					: `http://${serverHost}/~${world.namespace}/${world.name}`;

			return {
				id: world.id,
				namespace: world.namespace,
				name: world.name,
				attributes,
				link
			};
		});

		res.json({
			page,
			PAGE_SIZE,
			totalItems,
			totalPages,
			data: transformed
		});
	}, { get: true });
	createAdminRequest('worlds/search', async (req, res) => {
		const q = req.query.q || '';
		const page = parseInt(req.query.page) || 1;
		const PAGE_SIZE = 10;

		// Count total matching worlds
		const totalItems = db.prepare("SELECT COUNT(*) AS count FROM worlds WHERE namespace LIKE ? OR name LIKE ?")
			.get(`%${q}%`, `%${q}%`).count;
		const totalPages = Math.ceil(totalItems / PAGE_SIZE);

		if (page > totalPages || page < 1) {
			return res.json({ invalid_page: true });
		}

		const offset = (page - 1) * PAGE_SIZE;

		const worlds = db.prepare("SELECT * FROM worlds WHERE namespace LIKE ? OR name LIKE ? LIMIT ? OFFSET ?")
			.all(`%${q}%`, `%${q}%`, PAGE_SIZE, offset);

		const serverHost = req.headers.host;

		const transformed = worlds.map(world => {
			const attributes = JSON.parse(world.attributes);
			let link = world.namespace === 'textwall'
				? `http://${serverHost}`
				: world.name === 'main'
					? `http://${serverHost}/~${world.namespace}`
					: `http://${serverHost}/~${world.namespace}/${world.name}`;

			return {
				id: world.id,
				namespace: world.namespace,
				name: world.name,
				attributes,
				link
			};
		});

		res.json({
			page,
			PAGE_SIZE,
			totalItems,
			totalPages,
			data: transformed
		});
	}, { get: true });

	function buildConnectionResponse(client) {
		const s = client.sdata;
		if (!s) return null;

		const prsTil = function (idx) {
			const titles = [
				"black", "grey", "light grey", "light pink", "red", "orange", "brown", "yellow",
				"light green", "green", "light blue", "blue", "dark blue", "purple", "dark purple",
				"dark red", "dark green", "dark teal", "teal", "indigo", "periwinkle", "pink",
				"dark brown", "burgundy", "pale yellow", "light teal", "lavender", "pale purple",
				"magenta", "beige", "dark grey"
			];
			return titles[idx] || 'black';
		};


		return {
			username: s.authUser || '-',
			id: s.clientId,
			authenticated: !!s.isAuthenticated,
			worlds: [], // implement later
			xy: { x: s.cursorX || 0, y: s.cursorY || 0 },
			anonymous: !!s.cursorAnon,
			date_connected: s.connectTime ? new Date(s.connectTime * 1000).toISOString() : null,
			color_index: prsTil(s.cursorColor || ''),
			where: s.connectedWorldNamespace && s.connectedWorldName
				? `~${s.connectedWorldNamespace}/${s.connectedWorldName}`
				: '',
			isAdmin: s.isAdmin
		};
	}
	createAdminRequest('active', (req, res) => {
		const page = parseInt(req.query.page) || 1;
		const pageSize = parseInt(req.query.pageSize) || 10;

		const allClients = Object.values(clients).filter(c => c.sdata);

		const totalItems = allClients.length;
		const totalPages = Math.ceil(totalItems / pageSize);

		const start = (page - 1) * pageSize;
		const end = start + pageSize;

		const data = allClients.slice(start, end)
			.map(buildConnectionResponse)
			.filter(Boolean);

		res.json({ page, pageSize, totalItems, totalPages, data });
	}, { get: true });
	createAdminRequest('uptime', (req, res) => {
		res.json({ u: process.uptime() })
	}, { get: true })
	createAdminRequest('active/all', (req, res) => {
		const allClients = Object.values(clients).filter(c => c.sdata);

		const data = allClients
			.map(buildConnectionResponse)
			.filter(Boolean);

		res.json({ data });
	}, { get: true });

	createAdminRequest('active/search', (req, res) => {
		const q = (req.query.q || '').toLowerCase();
		const page = parseInt(req.query.page) || 1;
		const pageSize = parseInt(req.query.pageSize) || 10;

		const allClients = Object.values(clients).filter(c => c.sdata);

		// Filter by username
		const filtered = allClients
			.filter(c => (c.sdata.authUser || '-').toLowerCase().includes(q));

		const totalItems = filtered.length;
		const totalPages = Math.ceil(totalItems / pageSize);

		const start = (page - 1) * pageSize;
		const end = start + pageSize;

		const data = filtered.slice(start, end)
			.map(buildConnectionResponse)
			.filter(Boolean);

		res.json({ page, pageSize, totalItems, totalPages, data });
	}, { get: true });
	createAdminRequest("whitelist/add", (req, res) => {
		const { user } = req.body;
		if (!user) return res.status(400).send("Missing 'user'");
		const wl = loadWhitelist();
		if (!wl[1].includes(user)) wl[1].push(user);
		saveWhitelist(wl);
		res.json(wl);
	})
	createAdminRequest("whitelist/remove", (req, res) => {
		const { user } = req.body;
		if (!user) return res.status(400).send("Missing 'user'");
		const wl = loadWhitelist();
		wl[1] = wl[1].filter(u => u !== user);
		saveWhitelist(wl);
		res.json(wl);
	})
	createAdminRequest("whitelist/toggle", (req, res) => {
		const { toggle } = req.body;
		const wl = loadWhitelist();
		wl[0] = Boolean(toggle);
		saveWhitelist(wl);
		res.json(wl);
	})
	createAdminRequest("whitelist/list", (req, res) => {
		const wl = loadWhitelist();
		res.json(wl);
	}, {get: true})
	const adminPath = path.join(__dirname, "../admin");
	twrApp.use("/admin", express.static(adminPath));
	/*twrApp.get(/^\/admin(\/.*)?$/, (req, res) => {
		const requestedFile = path.join(adminPath, req.path.replace("/admin/", ""));

		// express will resolve against root and prevent escaping it
		res.sendFile(rel, { root: adminPath }, (err) => {
			if (err) {
				return res.sendFile('index.html', { root: adminPath });
			}
		});
	});*/
	if (settings.useStatic) {
		twrApp.use(express.static(staticPath));
	}

	twrApp.get(/^\/(?!admin(\/|$)).*$/, (req, res) => {
		res.sendFile('index.html', { root: staticPath });
	});

	httpServer.listen(port, function () {
		var addr = httpServer.address();
		console.log("TWR server is hosted on " + addr.address + ":" + addr.port);
	});

	init_ws();
}


function is_whole_number(x) {
	var isNumber = typeof x === "number" && !isNaN(x) && isFinite(x)
	if (isNumber) {
		return x === Math.trunc(x)
	}
	return false
}


var ipConnLim = {};



var wss;
var objects = {};

function broadcast(data, exclusion) {
	wss.clients.forEach(function (ws) {
		if (ws == exclusion) return;
		send(ws, data);
	});
}
function send(ws, data) {
	try {
		ws.send(data);
	} catch (e) {
		return;
	}
}

function constructChar(color, bold, italic, underline, strike) {
	var format = strike | underline << 1 | italic << 2 | bold << 3;
	var n = format * 31 + color;
	return String.fromCharCode(n + 192);
}

function parseChar(chr) {
	var col = chr % 31;
	var format = Math.floor(chr / 31);
	return {
		color: col,
		bold: (format & 8) == 8,
		italic: (format & 4) == 4,
		underline: (format & 2) == 2,
		strike: (format & 1) == 1
	};
}

function validateUsername(str) {
	if (str.length < 1 || str.length > 64) return false;
	var validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
	for (var i = 0; i < str.length; i++) {
		var chr = str[i];
		if (!validChars.includes(chr)) return false;
	}
	return true;
}

function generateToken() {
	var set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+";
	var str = "";
	for (var i = 0; i < 48; i++) {
		str += set[Math.floor(Math.random() * set.length)];
	}
	return str;
}

function san_nbr(x) {
	if (typeof x === "bigint") x = Number(x);
	if (typeof x === "boolean") x = x ? 1 : 0;
	if (typeof x === "string") x = Number(x);
	if (!isFinite(x)) x = 0;
	x = Math.trunc(Math.max(Math.min(x, 9007199254740991), -9007199254740991));
	return x;
}


var onlineCount = 0;


var chunkCache = {};
var modifiedChunks = {};

function commitChunks() {
	db.prepare("BEGIN");
	for (var t in modifiedChunks) {
		var tup = t.split(",");
		var worldId = parseInt(tup[0]);
		var chunkX = parseInt(tup[1]);
		var chunkY = parseInt(tup[2]);
		var data = chunkCache[t];
		var text = data.char.join("");
		var color = "";
		for (var i = 0; i < data.color.length; i++) {
			color += String.fromCharCode(data.color[i] + 192);
		}
		var prot = data.protected;
		if (data.exists) {
			db.prepare("UPDATE chunks SET text=?, colorFmt=?, protected=? WHERE world_id=? AND x=? AND y=?").run(text, color, Number(prot), worldId, chunkX, chunkY);
		} else {
			data.exists = true;
			//console.log(tup, worldId, chunkX, chunkY, text, color, prot);
			db.prepare("INSERT INTO chunks VALUES(?, ?, ?, ?, ?, ?)").run(worldId, chunkX, chunkY, text, color, Number(prot));
		}
		delete modifiedChunks[t];
	}
	db.prepare("COMMIT");
}

setInterval(function () {
	commitChunks();
}, 1000 * 10);

setInterval(function () {
	flushCache();
}, 1000 * 60 * 10);

function flushCache() {
	for (var t in chunkCache) {
		if (modifiedChunks[t]) continue;
		delete chunkCache[t];
	}
}

function getChunk(worldId, x, y, canCreate) {
	var tuple = worldId + "," + x + "," + y;
	if (chunkCache[tuple]) {
		return chunkCache[tuple];
	} else {
		var data = db.prepare("SELECT * FROM chunks WHERE world_id=? AND x=? AND y=?").get(worldId, x, y);
		if (data) {
			var colorRaw = data.colorFmt;
			var colorArray = [];
			for (var i = 0; i < colorRaw.length; i++) {
				colorArray.push(colorRaw[i].charCodeAt() - 192);
			}
			var cdata = {
				char: [...data.text],
				color: colorArray,
				protected: Boolean(data.protected),
				exists: true
			};
			chunkCache[tuple] = cdata;
			return cdata;
		} else {
			var cdata = {
				char: new Array(10 * 20).fill(" "),
				color: new Array(10 * 20).fill(0),
				protected: false
			};
			if (canCreate) {
				chunkCache[tuple] = cdata;
			}
			return cdata;
		}
	}
}
function writeChunk(worldId, x, y, idx, char, colorFmt, isMember) {
	if (char == 0 || (char >= 0xD800 && char <= 0xDFFF)) return false;
	var tuple = worldId + "," + x + "," + y;
	var chunk = getChunk(worldId, x, y, true);
	var prot = chunk.protected;
	if (prot && !isMember) return false;
	chunk.char[idx] = String.fromCodePoint(char);
	chunk.color[idx] = colorFmt;
	modifiedChunks[tuple] = true;
	return true;
}
function toggleProtection(worldId, x, y) {
	var tuple = worldId + "," + x + "," + y;
	var chunk = getChunk(worldId, x, y, true);
	chunk.protected = !chunk.protected;
	modifiedChunks[tuple] = true;
	return chunk.protected;
}
function clearChunk(worldId, x, y) {
	var tuple = worldId + "," + x + "," + y;
	var chunk = getChunk(worldId, x, y, false);
	if (!chunk.exists) return;
	for (var i = 0; i < chunk.char.length; i++) {
		chunk.char[i] = " ";
		chunk.color[i] = 0;
	}
	modifiedChunks[tuple] = true;
}

function sendOwnerStuff(ws, connectedWorldId, connectedWorldNamespace) {
	var memberList = db.prepare("SELECT * FROM members WHERE world_id=?").all(connectedWorldId);
	var normMemberList = [];
	for (var i = 0; i < memberList.length; i++) {
		normMemberList.push(memberList[i].username);
	}
	send(ws, encodeMsgpack({
		ml: normMemberList
	}));
	sendWorldList(ws, connectedWorldId, connectedWorldNamespace);
}

function sendWorldList(ws, connectedWorldId, connectedWorldNamespace, noPrivate) {
	var worldList = db.prepare("SELECT * FROM worlds WHERE namespace=? COLLATE NOCASE").all(connectedWorldNamespace);
	var normWorldList = [];
	for (var i = 0; i < worldList.length; i++) {
		var world = worldList[i];
		var wname = world.name;
		var attr = JSON.parse(world.attributes);
		if (noPrivate && attr.private) continue;
		normWorldList.push(wname, Boolean(attr.private));
	}

	send(ws, encodeMsgpack({
		wl: normWorldList
	}));
}

function editWorldAttr(worldId, prop, value) {
	var world = db.prepare("SELECT attributes FROM worlds WHERE id=?").get(worldId);
	if (!world) return;
	var attr = JSON.parse(world.attributes);
	attr[prop] = value;
	db.prepare("UPDATE worlds SET attributes=? WHERE id=?").run(JSON.stringify(attr), worldId);

	wss.clients.forEach(function (sock) {
		if (!sock || !sock.sdata) return;
		if (sock.sdata.connectedWorldId == worldId) {
			sock.sdata.worldAttr[prop] = Boolean(value);
		}
	});
}
function sendWorldAttrs(ws, world) {
	var attr = JSON.parse(world.attributes);
	send(ws, encodeMsgpack({ ro: Boolean(attr.readonly) }));
	send(ws, encodeMsgpack({ priv: Boolean(attr.private) }));
	send(ws, encodeMsgpack({ ch: Boolean(attr.hideCursors) }));
	send(ws, encodeMsgpack({ dc: Boolean(attr.disableChat) }));
	send(ws, encodeMsgpack({ dcl: Boolean(attr.disableColor) }));
	send(ws, encodeMsgpack({ db: Boolean(attr.disableBraille) }));
}

function evictClient(ws) {
	worldBroadcast(ws.sdata.connectedWorldId, encodeMsgpack({
		rc: ws.sdata.clientId
	}), ws);

	ws.sdata.connectedWorldNamespace = "textwall";
	ws.sdata.connectedWorldName = "main";
	ws.sdata.connectedWorldId = 1;
	ws.sdata.isMember = false;
	send(ws, encodeMsgpack({
		j: ["textwall", "main"]
	}));
	send(ws, encodeMsgpack({
		perms: 0
	}));
	send(ws, encodeMsgpack({
		b: [-1000000000000, 1000000000000, -1000000000000, 1000000000000]
	}));
	ws.sdata.isConnected = true;
	var worldInfo = db.prepare("SELECT * FROM worlds WHERE id=1").get();
	sendWorldAttrs(ws, worldInfo);
	var attr = JSON.parse(worldInfo.attributes);
	ws.sdata.worldAttr = attr;
	dumpCursors(ws);
}

function worldBroadcast(connectedWorldId, data, excludeWs) {
	wss.clients.forEach(function (sock) {
		if (!sock || !sock.sdata) return;
		if (sock == excludeWs) return;
		if (sock.sdata.connectedWorldId == connectedWorldId) {
			send(sock, data);
		}
	});
}

function dumpCursors(ws) {
	wss.clients.forEach(function (sock) {
		if (!sock || !sock.sdata) return;
		if (sock == ws) return;
		if (sock.sdata.connectedWorldId == ws.sdata.connectedWorldId) {
			send(ws, encodeMsgpack({
				cu: {
					id: sock.sdata.clientId,
					l: [sock.sdata.cursorX, sock.sdata.cursorY],
					c: sock.sdata.cursorColor,
					n: sock.sdata.cursorAnon ? "" : (sock.sdata.isAuthenticated ? sock.sdata.authUser : "")
				}
			}));
		}
	});
}

function encodeMsgpack(data) {
	try {
		return msgpack.encode(data);
	} catch (e) {
		return new Uint8Array([]);
	}
}

// number of packets per second
var rateLimits = {
	"j": 8,
	"r": 7,
	"ce": 22,
	"e": 77,
	"msg": 2,
	"register": 1,
	"login": 2,
	"token": 15,
	"logout": 5,
	"addmem": 5,
	"rmmem": 5,
	"deleteaccount": 1,
	"ro": 9,
	"priv": 9,
	"ch": 9,
	"dc": 9,
	"dcl": 9,
	"db": 9,
	"p": 9,
	"dw": 2,
	"namechange": 1,
	"passchange": 1,
	"c": 15,
	"ping": 60000000000000000000 // effectively unlimited
};
var rateLimitsByIp = {};
function isRateLimited(ip, packetType) {
	if (!rateLimits[packetType]) return false;
	let period = Math.floor(Date.now() / 1000);
	if (!rateLimitsByIp[ip]) {
		rateLimitsByIp[ip] = {};
	}
	if (!rateLimitsByIp[ip][packetType]) {
		rateLimitsByIp[ip][packetType] = [1, period];
		return false;
	}
	let ipLim = rateLimitsByIp[ip][packetType];
	let max = rateLimits[packetType];
	if (ipLim[1] == period) {
		if (ipLim[0] >= max) {
			return true;
		} else {
			ipLim[0]++;
			return false;
		}
	} else {
		ipLim[0] = 1;
		ipLim[1] = period;
		return false;
	}
}

var clientRecord = {};
var chatMutesByIP = {};
var chatMutesByUserIDs = {};
var muteMutated = false;
let clients = [];
let canvasMutesByIP = {};
let canvasMutesByUserIDs = {};
let fullMuteByIP = {};
let fullMuteByUserIDs = {};
let canvasMuteMutated = false;
let fullMuteMutated = false;

function clearClientRecord() {
	for (let c in clientRecord) {
		let cli = clientRecord[c];
		if (!cli.isConnected) {
			if (Date.now() - cli.connectTime > 1000 * 60 * 30) {
				delete clientRecord[c];
			}
		}
	}
}

function saveMutes() {
	fs.writeFileSync(muteDbPath, JSON.stringify({
		ip: chatMutesByIP,
		id: chatMutesByUserIDs
	}, null, "\t"));
}

function loadMutes() {
	var fileMuteData;
	try {
		fileMuteData = fs.readFileSync(muteDbPath);
	} catch (e) {
		console.error(e);
		console.log("No mutes file found");
		return; // no mutes...
	}
	var data = JSON.parse(fileMuteData);
	chatMutesByIP = data.ip;
	chatMutesByUserIDs = data.id;
}

loadMutes();
const canvasMuteDbPath = settings.db.canvasMutePath;

function saveCanvasMutes() {
	fs.writeFileSync(canvasMuteDbPath, JSON.stringify({
		ip: canvasMutesByIP,
		id: canvasMutesByUserIDs
	}, null, "\t"));
}

function loadCanvasMutes() {
	try {
		const data = JSON.parse(fs.readFileSync(canvasMuteDbPath));
		canvasMutesByIP = data.ip;
		canvasMutesByUserIDs = data.id;
	} catch (e) {
		console.error(e);
		console.log("No canvas mutes file found");
		return; // no canvas mutes...
	}
}
function canvasMuted(sdata) {
	if (!sdata) return false;

	let cli = clientRecord[sdata.clientId];
	if (!cli) return false;
	if (canvasMutesByUserIDs[cli.authUserId]) return true;
	if (canvasMutesByIP[cli.ipAddr]) return true;

	return false;
}

function fullyMuted(sdata) {
	if (!sdata) return false;

	let cli = clientRecord[sdata.clientId];
	if (!cli) return false;

	if (fullMuteByUserIDs[cli.authUserId]) return true;
	if (fullMuteByIP[cli.ipAddr]) return true;

	return false;
}
loadCanvasMutes();

let saveCanvasMuteInterval = setInterval(() => {
	if (canvasMuteMutated) {
		canvasMuteMutated = false;
		saveCanvasMutes();
	}
}, 5000);

let memClrInterval = setInterval(function () {
	clearClientRecord();
}, 1000 * 60);

let saveMuteInterval = setInterval(function () {
	if (muteMutated) {
		muteMutated = false;
		saveMutes();
	}
}, 1000 * 5);

function init_ws() {
	wss = new ws.Server({ server: httpServer });

	wss.on("connection", function (ws, req) {
		var ipAddr = ws._socket.remoteAddress;
		//console.log(ipAddr, JSON.stringify(req.headers))
		if (!ipAddr) return;
		if (ipAddr.startsWith("::ffff:")) {
			ipAddr = ipAddr.slice("::ffff:".length);
		}
		if (ipAddr == "127.0.0.1") {
			ipAddr = req.headers["x-real-ip"];//req.headers["CF-Connecting-IP"] || req.headers["cf-connecting-ip"];
			if (!ipAddr) ipAddr = Math.random().toString();
		}

		if (!ipConnLim[ipAddr]) {
			ipConnLim[ipAddr] = [0, 0, 0]; // connections, blocks placed in current second period, second period
		}

		var connObj = ipConnLim[ipAddr];

		if (connObj[0] >= 15) {
			ws.close();
			return;
		}

		console.log("New client:", ipAddr);
		connObj[0]++;


		onlineCount++;

		let clientId = Math.floor(Math.random() * 1000000000).toString();

		var sdata = {
			connectTime: Date.now(),
			ipAddr: ipAddr,
			isConnected: false,
			isAuthenticated: false,
			isMember: false,
			authUser: "",
			authUserId: 0,
			authToken: "",
			connectedWorldNamespace: "",
			connectedWorldName: "",
			connectedWorldId: 0,
			clientId: clientId,
			cursorX: 0,
			cursorY: 0,
			cursorColor: 0,
			cursorAnon: false,
			worldAttr: {},
			isAdmin: false,
		};

		clientRecord[clientId] = sdata;
		ws.sdata = sdata;
		send(ws, encodeMsgpack({ id: clientId }));
		sdata.isAdmin = settings.adminList.includes(sdata.authUser)
		send(ws, encodeMsgpack({ admin: sdata.isAdmin }));
		clients[ws.sdata.clientId] = ws;
		fs.readFile("../data/starter_scripts.json", "utf8", (err, data) => {
			if (err) return console.error("failed to read file:", err);

			try {
				const json = JSON.parse(data);
				send(ws, encodeMsgpack({ ces: json }));

			} catch (e) {
				console.error("failed to parse JSON:", e);
			}
		});
		ws.on("message", function (message, binary) {

			if (!binary) return;


			var per = Math.floor(Date.now() / 1000);
			if (connObj[2] == per) {
				if (connObj[1] >= 100) return;
			} else {
				connObj[1] = 0;
			}
			connObj[2] = per;
			connObj[1]++;


			var data;
			try {
				data = msgpack.decode(message);
			} catch (e) {
				return;
			}

			if (data == null) return;
			if (typeof data != "object") return;
			if (Array.isArray(data)) return;

			let packetType = Object.keys(data)[0];
			if (!packetType) return;

			if (isRateLimited(ipAddr, packetType)) {
				return;
			}


			if ("j" == packetType) {
				var world = data.j;

				if (!Array.isArray(world)) return;

				var namespace = world[0];
				var pathname = world[1];
				if (typeof namespace != "string") return;
				if (typeof pathname != "string") return;
				if (namespace.length > 64) return;
				if (pathname.length > 64) return;

				sdata.isMember = false;
				sdata.isConnected = false;
				sdata.worldAttr = {};
				const adminList = settings.adminList.map(a => a.toLowerCase());

				if (adminList.includes(namespace.toLowerCase())) {

					if (!sdata.isAuthenticated || sdata.authUser.toLowerCase() !== namespace.toLowerCase()) {
						send(ws, encodeMsgpack({ alert: "You are viewing an admin's wall." }));
					}

				}
				// if admin joins, send owner stuff
				// start
				if (sdata.isAuthenticated && adminList.includes(sdata.authUser.toLowerCase())) {
					sendOwnerStuff(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace);
				}
				fs.readFile("../data/on_world_scripts.json", "utf8", (err, data) => {
					if (err) return console.error("failed to read file:", err);

					try {
						const json = JSON.parse(data);
						send(ws, encodeMsgpack({ ows: json }));

					} catch (e) {
						console.error("failed to parse JSON:", e);
					}
				});
				send(ws, encodeMsgpack({
					online: onlineCount
				}));
				broadcast(encodeMsgpack({
					online: onlineCount
				}), ws);

				if (sdata.connectedWorldId) {
					worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
						rc: sdata.clientId
					}), ws);
				}


				var world = db.prepare("SELECT * FROM worlds WHERE namespace=? COLLATE NOCASE AND name=? COLLATE NOCASE").get(namespace, pathname);
				if (!world) {
					if (sdata.isAuthenticated && namespace.toLowerCase() == sdata.authUser.toLowerCase()) {
						var insertInfo = db.prepare("INSERT INTO 'worlds' VALUES(null, ?, ?, ?)").run(sdata.authUser, pathname, JSON.stringify({
							readonly: false,
							private: false,
							hideCursors: false,
							disableChat: false,
							disableColor: false,
							disableBraille: false
						})).lastInsertRowid;
						var worldInfo = db.prepare("SELECT * FROM worlds WHERE rowid=?").get(insertInfo);
						sdata.connectedWorldNamespace = worldInfo.namespace;
						sdata.connectedWorldName = worldInfo.name;
						sdata.connectedWorldId = worldInfo.id;
						send(ws, encodeMsgpack({
							j: [sdata.connectedWorldNamespace, sdata.connectedWorldName]
						}));
						send(ws, encodeMsgpack({
							perms: 2
						}));
						sdata.isMember = true;
						sdata.isConnected = true;
						sendOwnerStuff(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace);
						send(ws, encodeMsgpack({
							b: [-1000000000000, 1000000000000, -1000000000000, 1000000000000]
						}));
						sendWorldAttrs(ws, worldInfo);
						dumpCursors(ws);
						return;
					} else {
						evictClient(ws);
						return;
					}
				}

				var attr = JSON.parse(world.attributes);
				sdata.worldAttr = attr;

				sdata.connectedWorldNamespace = world.namespace;
				sdata.connectedWorldName = world.name;
				sdata.connectedWorldId = world.id;

				send(ws, encodeMsgpack({
					j: [sdata.connectedWorldNamespace, sdata.connectedWorldName]
				}));

				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (isOwner) {
					send(ws, encodeMsgpack({
						perms: 2
					}));
					sdata.isMember = true;

					sendOwnerStuff(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace);
				} else if (sdata.isAuthenticated) {
					var memberCheck = db.prepare("SELECT * FROM members WHERE username=? COLLATE NOCASE AND world_id=?").get(sdata.authUser, sdata.connectedWorldId);
					if (memberCheck) {
						send(ws, encodeMsgpack({
							perms: 1
						}));
						sdata.isMember = true;
					} else {
						if (attr.private) {
							evictClient(ws);
							return;
						}
						send(ws, encodeMsgpack({
							perms: 0
						}));
					}
					sendWorldList(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace, true);
				} else {
					if (attr.private) {
						evictClient(ws);
						return;
					}
					send(ws, encodeMsgpack({
						perms: 0
					}));
					sendWorldList(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace, true);
				}

				sendWorldAttrs(ws, world);

				send(ws, encodeMsgpack({
					b: [-1000000000000, 1000000000000, -1000000000000, 1000000000000]
				}));
				dumpCursors(ws);
				sdata.isConnected = true;
			} else if ("r" == packetType) {
				if (!sdata.isConnected) return;
				var regions = data.r;

				if (sdata.worldAttr.private && !sdata.isMember) return;

				if (!Array.isArray(regions)) return;

				var len = Math.floor(regions.length / 2);
				var chunks = [];
				if (len > 10 * 10 * 3) return;
				for (var i = 0; i < len; i++) {
					var x = san_nbr(regions[i * 2]);
					var y = san_nbr(regions[i * 2 + 1]);
					var cd = getChunk(sdata.connectedWorldId, x, y);
					var char = cd.char;
					var color = cd.color;
					var color2 = "";
					for (var z = 0; z < color.length; z++) {
						color2 += String.fromCharCode(color[z] + 192);
					}
					var prot = cd.protected;
					//console.log(char, color, prot);
					chunks.push(x, y, char, color2, prot);
				}
				send(ws, encodeMsgpack({
					chunks: chunks
				}));
			} else if ("ce" == packetType) { // cursor
				if (!sdata.isConnected) return;
				// never send if on anonymous mode
				if (anonymous.includes(sdata.clientId.toLowerCase())) return;
				if (sdata.worldAttr.private && !sdata.isMember) return;
				if (!sdata.isAuthenticated || !isWhitelisted(sdata.authUser)) {
					return;
				}

				if ("l" in data.ce) {
					var x = data.ce.l[0];
					var y = data.ce.l[1];
					sdata.cursorX = san_nbr(x);
					sdata.cursorY = san_nbr(y);
				}
				if ("c" in data.ce) {
					var col = san_nbr(data.ce.c);
					if (col >= 0 && col <= 31) {
						sdata.cursorColor = col;
					}
				}
				if ("n" in data.ce) {
					sdata.cursorAnon = Boolean(data.ce.n);
				}
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					cu: {
						id: sdata.clientId,
						l: [sdata.cursorX, sdata.cursorY],
						c: sdata.cursorColor,
						n: sdata.cursorAnon ? "" : (sdata.isAuthenticated ? sdata.authUser : "")
					}
				}), ws);
			} else if ("e" == packetType) { // write edit
				if (!sdata.isConnected) return;
				var edits = data.e;

				if (!Array.isArray(edits)) return;
				if (canvasMuted(sdata) && !settings.adminList.includes(sdata.authUser) && sdata.authUser !== "textwall") {
					// send an alert
					send(ws, encodeMsgpack({
						alert: "You are muted in canvas"
					}))
					return;
				}
				/*if (!sdata.isAuthenticated || !isWhitelisted(sdata.authUser)) {send(ws, encodeMsgpack({
						alert: "You are not authorized"
					}))
					return;}*/
		

				if (sdata.worldAttr.readonly && !sdata.isMember) return;
				if (sdata.worldAttr.private && !sdata.isMember) return;

				var resp = [];
				var ecount = 0;
				for (var i = 0; i < edits.length; i++) {
					var chunk = edits[i];
					if (!Array.isArray(chunk)) continue;
					var x = chunk[0];
					var y = chunk[1];

					if (typeof x != "number" || typeof y != "number") return;
					if (!Number.isInteger(x) || !Number.isInteger(y)) return;

					var obj = [];
					obj.push(x, y);
					resp.push(obj);
					for (var j = 0; j < Math.floor((chunk.length - 2) / 3); j++) {
						if (ecount > rateLimits.e) return;
						var chr = chunk[j * 3 + 2];
						var idx = chunk[j * 3 + 3];
						var colfmt = chunk[j * 3 + 4];

						if (!Number.isInteger(chr)) return;
						if (!Number.isInteger(idx)) return;
						if (!Number.isInteger(colfmt)) return;
						if (!(chr >= 1 && chr <= 1114111)) return;
						if (!(idx >= 0 && idx <= (20 * 10) - 1)) return;
						if (!(colfmt >= 0 && colfmt <= 960)) return;

						var stat = writeChunk(sdata.connectedWorldId, x, y, idx, chr, colfmt, sdata.isMember);
						if (stat) {
							obj.push(chr, idx, colfmt);
							ecount++;
						}
					}
				}

				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({

					e: {
						e: resp,
						clientId: sdata.clientId
					}
				}));
			} else if ("msg" == packetType) {
				var message = data.msg;

				if (typeof message != "string") return;
				if (message.length > 256) return;
				/*if (!sdata.isAuthenticated || !isWhitelisted(sdata.authUser)) {
					send(ws, encodeMsgpack({
						msg: ["[SERVER]", 4, "You are not authorized", true]
					}));
					return;
				}*/

				var nick = sdata.clientId;
				if (sdata.isAuthenticated) {
					nick = sdata.authUser;
				}
				if (sdata.worldAttr.disableChat && !sdata.isMember) {
					return;
				}

				if ((chatMutesByIP[sdata.ipAddr] || (sdata.isAuthenticated && chatMutesByUserIDs[sdata.authUserId])) && (sdata.authUser != "textwall") && (!settings.adminList.includes(sdata.authUser))) {
					send(ws, encodeMsgpack({
						msg: ["[SERVER]", 4, "You are muted", true]
					}));
					return;
				}

				let isCommand = false;
				let commandResponse = "***";
				if (settings.adminList.includes(sdata.authUser) && sdata.isAuthenticated) {
					let parts = message.trim().split(/\s+/);
					let command = parts[0].slice(1).toLowerCase();
					let args = parts.slice(1);
					if (message.startsWith("/")) {
						if (command === "anonymous") {
							// sussy among us
							isCommand = true;
							// admincheck
							if (!settings.adminList.map(a => a.toLowerCase()).includes(sdata.authUser.toLowerCase())) {
								commandResponse = "HAHA NO, YOU CANNOT GO ANONYMOUS!";

							} else {
								// decrease online count by 1 temporarily
								onlineCount--;
								broadcast(encodeMsgpack({
									online: onlineCount
								}), ws);
								worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
									rc: sdata.clientId
								}), ws);
								delete clients[sdata.clientId];
								setTimeout(() => { anonymous.push(sdata.clientId.toLowerCase()) }, 100);
								commandResponse = "ANONYMOUS MODE: ON";

							}

						} else if (command === "deanonymous") {
							// damn it
							isCommand = true;
							let idx = anonymous.indexOf(sdata.clientId.toLowerCase());
							if (idx !== -1) {
								onlineCount++;
								broadcast(encodeMsgpack({
									online: onlineCount
								}), ws);
								clients[sdata.clientId] = ws;
								anonymous.splice(idx, 1);
								commandResponse = "ANONYMOUS MODE: OFF";

							} else {
								commandResponse = "HEY, DUDE DON'T TRY TO BE SLICK!";
							}
						} else if (command === "announcement") {
							isCommand = true;
							var msg = args.join(" ").trim();
							if (!msg) {
								commandResponse = "SERIOUSLY?! WHAT DO YOU WANNA ANNOUNCE IF YOU DON'T GIVE ME A MESSAGE?";
							} else {

								// broadcast to all worlds
								broadcast(encodeMsgpack({
									msg: ["[ANNOUNCEMENT]", 2, msg, false]
								}));
								broadcast(encodeMsgpack({
									alert: msg
								}));
								commandResponse = "Announcement sent";
							}

						} else if (command === "newid") {
							isCommand = true;
							let oldId = sdata.clientId;
							let newId = parseInt(args[0], 0)
							if (!newId) {
								commandResponse = "HEY! YOU DIDN'T GIVE ME AN ID!";

							} else if (isNaN(newId)) {
								commandResponse = "HEY! THAT'S NOT A VALID ID!";
							} else {
								sdata.clientId = newId.toString();
								clientRecord[sdata.clientId] = sdata;
								delete clientRecord[oldId];
								worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
									rc: oldId
								}), ws);
								dumpCursors(ws);
								send(ws, encodeMsgpack({
									id: sdata.clientId
								}))
								commandResponse = `Your ID has changed to ${sdata.clientId}`;
							}
						} else if (command === "fakemsg") {
							isCommand = true;

							if (!args || args.length === 0) {
								commandResponse = "HEY! YOU DIDN'T GIVE ME ANY ARGUMENTS!";
							} else {

								let nick = args[0];
								if (!nick || typeof nick !== "string") {
									commandResponse = "HEY! INVALID NICKNAME!";
								} else {
									nick = nick.trim();
									if (!nick) {
										commandResponse = "HEY! INVALID NICKNAME!";
									} else if (nick.length > 48) {
										commandResponse = "HEY! THAT NAME IS TOO LONG!";
									} else {

										let color = args[1];
										if (color === undefined || isNaN(Number(color))) {
											commandResponse = "HEY! COLOR MUST BE A NUMBER!";
										} else {
											color = Number(color);


											let auth = args[2];
											if (typeof auth !== "string" || (auth.toLowerCase() !== "true" && auth.toLowerCase() !== "false")) {
												commandResponse = "HEY! AUTH MUST BE 'true' OR 'false'!";
											} else {
												auth = auth.toLowerCase() === "true";


												let msgParts = args.slice(3);
												let msg = msgParts.join(" ").trim();

												if (!msg) {
													commandResponse = "HEY! YOU DIDN'T GIVE ME A MESSAGE TO SEND!";
												} else if (msg.length > 255) {
													commandResponse = "HEY! YOUR MESSAGE IS TOO LONG!";
												} else {

													try {
														worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
															msg: [nick, color, msg, auth]
														}));
														commandResponse = "";
													} catch (err) {
														commandResponse = "ERROR: FAILED TO SEND MESSAGE! IT'S YOUR FAULT FOR SENDING SOMETHING WEIRD!";
														console.error(err);
													}
												}
											}
										}
									}
								}
							}
						}
					}

				}
				if (sdata.authUser == "textwall" && sdata.isAuthenticated || settings.adminList.includes(sdata.authUser)) {
					if (message.startsWith("/")) {
						let parts = message.trim().split(/\s+/);
						let command = parts[0].slice(1).toLowerCase();
						let args = parts.slice(1);
						if (command == "help") {
							isCommand = true;
							if (!settings.adminList.includes(sdata.authUser)) {
								commandResponse = `Commands: /mute [id]; /muteuser [name]; /unmute [id]; /unmuteuser [name]; /canvasmute [id]; /canvasmuteuser [name]; /canvasunmute [id]; /canvasunmuteuser [name]; /fullmute [id]; /fullmuteuser [name]; /fullunmute [id]; /fullunmuteuser [name]; /listmutes; /help`;
							} else {
								commandResponse = `Commands: /mute [id]; /muteuser [name]; /unmute [id]; /unmuteuser [name]; /canvasmute [id]; /canvasmuteuser [name]; /canvasunmute [id]; /canvasunmuteuser [name]; /fullmute [id]; /fullmuteuser [name]; /fullunmute [id]; /fullunmuteuser [name]; /listmutes; /fakemsg [nick] [colorindex] [auth] [msg]; /help; /anonymous; /deanonymous; /announcement [message]; /newid [id]`;
							}

						} else if (
							command == "mute" || command == "muteuser" ||
							command == "unmute" || command == "unmuteuser" ||
							command == "canvasmute" || command == "canvasmuteuser" ||
							command == "canvasunmute" || command == "canvasunmuteuser" ||
							command == "fullmute" || command == "fullmuteuser" ||
							command == "fullunmute" || command == "fullunmuteuser"
						) {
							isCommand = true;
							let target = args[0] || "";
							let foundCli = false;

							//
							// 🔹 CHAT MUTE
							//
							if (command == "mute") {
								let cli = clientRecord[target];
								if (cli) {
									chatMutesByIP[cli.ipAddr] = [Date.now(), cli.clientId];
									muteMutated = true;
									foundCli = true;
								}
							} else if (command == "muteuser") {
								for (let cid in clientRecord) {
									let cli = clientRecord[cid];
									if (cli && cli.authUser.toLowerCase() == target.toLowerCase()) {
										chatMutesByUserIDs[cli.authUserId] = [Date.now(), cli.authUser];
										muteMutated = true;
										foundCli = true;
									}
								}
							} else if (command == "unmute") {
								for (let m in chatMutesByIP) {
									if (chatMutesByIP[m][1] == target) {
										delete chatMutesByIP[m];
										muteMutated = true;
										foundCli = true;
									}
								}
							} else if (command == "unmuteuser") {
								for (let m in chatMutesByUserIDs) {
									if (chatMutesByUserIDs[m][1].toLowerCase() == target.toLowerCase()) {
										delete chatMutesByUserIDs[m];
										muteMutated = true;
										foundCli = true;
									}
								}
							}

							//
							// 🔹 CANVAS MUTE
							//
							else if (command == "canvasmute") {
								let cli = clientRecord[target];
								if (cli) {
									canvasMutesByIP[cli.ipAddr] = [Date.now(), cli.clientId];
									canvasMuteMutated = true;
									foundCli = true;
								}
							} else if (command == "canvasmuteuser") {
								for (let cid in clientRecord) {
									let cli = clientRecord[cid];
									if (cli && cli.authUser.toLowerCase() == target.toLowerCase()) {
										canvasMutesByUserIDs[cli.authUserId] = [Date.now(), cli.authUser];
										canvasMuteMutated = true;
										foundCli = true;
									}
								}
							} else if (command == "canvasunmute") {
								for (let m in canvasMutesByIP) {
									if (canvasMutesByIP[m][1] == target) {
										delete canvasMutesByIP[m];
										canvasMuteMutated = true;
										foundCli = true;
									}
								}
							} else if (command == "canvasunmuteuser") {
								for (let m in canvasMutesByUserIDs) {
									if (canvasMutesByUserIDs[m][1].toLowerCase() == target.toLowerCase()) {
										delete canvasMutesByUserIDs[m];
										canvasMuteMutated = true;
										foundCli = true;
									}
								}
							}

							//
							// 🔹 FULL MUTE (chat + canvas)
							//
							else if (command == "fullmute" || command == "fullmuteuser") {
								// just call both
								if (command == "fullmute") {
									let cli = clientRecord[target];
									if (cli) {
										chatMutesByIP[cli.ipAddr] = [Date.now(), cli.clientId];
										canvasMutesByIP[cli.ipAddr] = [Date.now(), cli.clientId];
										muteMutated = true;
										canvasMuteMutated = true;
										foundCli = true;
									}
								} else if (command == "fullmuteuser") {
									for (let cid in clientRecord) {
										let cli = clientRecord[cid];
										if (cli && cli.authUser.toLowerCase() == target.toLowerCase()) {
											chatMutesByUserIDs[cli.authUserId] = [Date.now(), cli.authUser];
											canvasMutesByUserIDs[cli.authUserId] = [Date.now(), cli.authUser];
											muteMutated = true;
											canvasMuteMutated = true;
											foundCli = true;
										}
									}
								}
							} else if (command == "fullunmute" || command == "fullunmuteuser") {
								if (command == "fullunmute") {
									for (let m in chatMutesByIP) {
										if (chatMutesByIP[m][1] == target) {
											delete chatMutesByIP[m];
											muteMutated = true;
											foundCli = true;
										}
									}
									for (let m in canvasMutesByIP) {
										if (canvasMutesByIP[m][1] == target) {
											delete canvasMutesByIP[m];
											canvasMuteMutated = true;
											foundCli = true;
										}
									}
								} else if (command == "fullunmuteuser") {
									for (let m in chatMutesByUserIDs) {
										if (chatMutesByUserIDs[m][1].toLowerCase() == target.toLowerCase()) {
											delete chatMutesByUserIDs[m];
											muteMutated = true;
											foundCli = true;
										}
									}
									for (let m in canvasMutesByUserIDs) {
										if (canvasMutesByUserIDs[m][1].toLowerCase() == target.toLowerCase()) {
											delete canvasMutesByUserIDs[m];
											canvasMuteMutated = true;
											foundCli = true;
										}
									}
								}
							}
							if (foundCli) {
								commandResponse =
									command.includes("unmute") ?
										`${command.includes("canvas") ? "Canvas" : command.includes("full") ? "Fully" : "Un"}-unmuted - ${target}` :
										`${command.includes("canvas") ? "Canvas" : command.includes("full") ? "Fully" : "Chat"}-muted - ${target}`;
							} else {
								commandResponse = `Client not found - ${target}`;
							}

							if (target == sdata.authUser.toLowerCase()) {
								commandResponse = "MUTE YOURSELF? OKAY, SUIT YOURSELF!";
							} else if (target == "") {
								commandResponse = "MUTE NOBODY? OKAY, MUTING NOBODY!";
							} else if (target == "textwall") {
								commandResponse = "MUTE TEXTWALL? OKAY, SUIT YOURSELF!"
							} else if (settings.adminList.includes(target)) {
								commandResponse = "MUTE AN ADMIN? OKAY, SUIT YOURSELF!"
							}


							else if (command === "online") {
								isCommand = true;
								// show all online users
								let onlineUsers = [];
								for (let cid in clients) {
									let cli = clients[cid].sdata;
									if (cli && cli.isConnected) {
										let onick = cli.isAuthenticated ? cli.authUser : cli.clientId;
										let world = cli.connectedWorldNamespace
										let worldName = cli.connectedWorldName
										// push
										onlineUsers.push({ n: onick, w: world, wn: worldName });
									}
								}
								if (onlineUsers.length === 1) {
									send(ws, encodeMsgpack({ msg: ["[O]", 10, "Online client:", true] }))
									send(ws, encodeMsgpack({ msg: ["[O]", 10, (!settings.adminList.includes(sdata.authUser) ? onlineUsers[0].n : (onlineUsers[0].n + " ~" + onlineUsers[0].w + " (" + onlineUsers[0].wn + ")")), true] }));
									commandResponse = "***";
								} else {
									send(ws, encodeMsgpack({ msg: ["[O]", 10, "Online clients:", true] }));
									onlineUsers.forEach(onlineUser => {
										send(ws, encodeMsgpack({ msg: ["[O]", 10, (!settings.adminList.includes(sdata.authUser) ? onlineUser.n : (onlineUser.n + " ~" + onlineUser.w + " (" + onlineUser.wn + ")")), true] }));
									});
									commandResponse = "***";
								}
							}
						}
						else if (command === "listmutes") {
							isCommand = true;

							let chatMuteList = [];
							for (let ip in chatMutesByIP) {
								let masked = mask_ip(ip)
								let entry = chatMutesByIP[ip];
								chatMuteList.push(`IP: ${masked} (ID: ${entry[1]})`);
							}
							for (let uid in chatMutesByUserIDs) {
								let entry = chatMutesByUserIDs[uid];
								chatMuteList.push(`UserID: ${uid} (Name: ${entry[1]})`);
							}
							// List canvas mutes
							let canvasMuteList = [];
							for (let ip in canvasMutesByIP) {
								let masked = mask_ip(ip)
								let entry = canvasMutesByIP[ip];
								canvasMuteList.push(`IP: ${masked} (ID: ${entry[1]})`);
							}
							for (let uid in canvasMutesByUserIDs) {
								let entry = canvasMutesByUserIDs[uid];
								canvasMuteList.push(`UserID: ${uid} (Name: ${entry[1]})`);
							}
							// compose
							send(ws, encodeMsgpack({ msg: ["[M]", 10, "Chat mutes:", true] }));
							if (chatMuteList.length === 0) {
								send(ws, encodeMsgpack({ msg: ["[M]", 10, "(none)", true] }));
							} else {
								chatMuteList.forEach(m => send(ws, encodeMsgpack({ msg: ["[M]", 10, m, true] })));
							}
							send(ws, encodeMsgpack({ msg: ["[M]", 10, "Canvas mutes:", true] }));
							if (canvasMuteList.length === 0) {
								send(ws, encodeMsgpack({ msg: ["[M]", 10, "(none)", true] }));
							} else {
								canvasMuteList.forEach(m => send(ws, encodeMsgpack({ msg: ["[M]", 10, m, true] })));
							}
							commandResponse = "***";
						}

					}
				}
				if (!isCommand) {
					var isAdmin = settings.adminList.map(a => a.toLowerCase()).includes(sdata.authUser.toLowerCase());
					if (!anonymous.includes(sdata.clientId.toLowerCase())) {
						worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
							msg: [nick, sdata.cursorColor, message, sdata.isAuthenticated, isAdmin]
						}));
					} else {
						worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
							msg: ["???", 0, message, false]
						}));
					}
				} else if (commandResponse) {
					send(ws, encodeMsgpack({
						msg: ["[SERVER]", 4, commandResponse, true]
					}));
				}
			} else if ("register" == packetType) {
				if (sdata.isAuthenticated) return;
				/*if (!sdata.isAuthenticated) {
					send(ws, encodeMsgpack({
						alert: "Registration is closed."
					}));
					return
				}*/
				var cred = data.register;

				if (!Array.isArray(cred)) return;

				var user = cred[0];
				var pass = cred[1];

				if (typeof user != "string") return;
				if (typeof pass != "string") return;
				if (user.length > 64) return;
				if (pass.length > 64) return;


				var isValid = validateUsername(user);
				if (!isValid) {
					send(ws, encodeMsgpack({
						alert: "Bad username - it must be 1-64 chars and have the following chars: A-Z a-z 0-9 - _ ."
					}));
					return;
				}

				var userObj = db.prepare("SELECT * FROM 'users' WHERE username=? COLLATE NOCASE").get(user);
				if (userObj) {
					send(ws, encodeMsgpack({
						nametaken: true
					}));
				} else {
					var rowid = db.prepare("INSERT INTO 'users' VALUES(null, ?, ?, ?)").run(user, encryptHash(pass), Date.now()).lastInsertRowid;
					sdata.isAuthenticated = true;
					sdata.authUser = user;
					sdata.authUserId = db.prepare("SELECT id FROM 'users' WHERE rowid=?").get(rowid).id;
					var newToken = generateToken();
					db.prepare("INSERT INTO 'tokens' VALUES(?, ?, ?)").run(newToken, sdata.authUser, sdata.authUserId);
					send(ws, encodeMsgpack({
						token: [user, newToken]
					}));
					sdata.authToken = newToken;

					db.prepare("INSERT INTO 'worlds' VALUES(null, ?, ?, ?)").run(sdata.authUser, "main", JSON.stringify({
						readonly: false,
						private: false,
						hideCursors: false,
						disableChat: false,
						disableColor: false,
						disableBraille: false
					}));
				}



			} else if ("login" == packetType) {
				var cred = data.login;

				if (!Array.isArray(cred)) return;

				var user = cred[0];
				var pass = cred[1];

				if (typeof user != "string") return;
				if (typeof pass != "string") return;
				if (user.length > 64) return;
				if (pass.length > 64) return;

				var userObj = db.prepare("SELECT * FROM 'users' WHERE username=? COLLATE NOCASE").get(user);
				if (userObj) {
					var db_user = userObj.username;
					var db_id = userObj.id;
					var db_pass = userObj.password;
					var isValid = checkHash(db_pass, pass);
					if (isValid) {
						sdata.isAuthenticated = true;
						sdata.authUser = db_user;
						sdata.authUserId = db_id;
						var newToken = generateToken();
						db.prepare("INSERT INTO 'tokens' VALUES(?, ?, ?)").run(newToken, sdata.authUser, sdata.authUserId);
						send(ws, encodeMsgpack({
							token: [sdata.authUser, newToken]
						}));
						sdata.authToken = newToken;
						sdata.isAdmin = settings.adminList.includes(sdata.authUser)
						send(ws, encodeMsgpack({ admin: sdata.isAdmin }));
						if (sdata.connectedWorldId) {
							var isOwner = sdata.isAuthenticated && (
								(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
								(settings.adminList && settings.adminList.includes(sdata.authUser))
							);
							if (isOwner) {
								send(ws, encodeMsgpack({
									perms: 2
								}));
								sdata.isMember = true;
								sendOwnerStuff(ws, sdata.connectedWorldId, sdata.connectedWorldNamespace);
							} else {
								/*var world = db.prepare("SELECT * FROM worlds WHERE id=?").get(sdata.connectedWorldId);
								var attr = JSON.parse(world.attributes);*/
								if (sdata.worldAttr.private) {
									evictClient(ws);
									return;
								}
								var memberCheck = db.prepare("SELECT * FROM members WHERE username=? COLLATE NOCASE AND world_id=?").get(sdata.authUser, sdata.connectedWorldId);
								if (memberCheck) {
									send(ws, encodeMsgpack({
										perms: 1
									}));
									sdata.isMember = true;
								}
							}
						}

					} else {
						send(ws, encodeMsgpack({
							loginfail: true
						}));
					}
				} else {
					send(ws, encodeMsgpack({
						loginfail: true
					}));
				}
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					cu: {
						id: sdata.clientId,
						l: [sdata.cursorX, sdata.cursorY],
						c: sdata.cursorColor,
						n: sdata.cursorAnon ? "" : (sdata.isAuthenticated ? sdata.authUser : "")
					}
				}), ws);
			} else if ("token" == packetType) {
				var token = data.token;

				if (!Array.isArray(token)) return;

				var tokenUser = token[0];
				var tokenToken = token[1];

				if (typeof tokenUser != "string") return;
				if (typeof tokenToken != "string") return;
				if (tokenUser.length > 64) return;
				if (tokenToken.length > 128) return;


				var tokenData = db.prepare("SELECT * FROM tokens WHERE token=?").get(tokenToken);
				if (tokenData) {
					var userId = tokenData.user_id;
					send(ws, encodeMsgpack({
						token: [tokenData.username, tokenData.token]
					}));
					sdata.isAuthenticated = true;
					sdata.authUser = tokenData.username;
					sdata.authUserId = userId;
					sdata.authToken = tokenData.token;
				} else {
					send(ws, encodeMsgpack({
						tokenfail: true
					}));
				}
			} else if ("logout" == packetType) {
				if (sdata.authToken) {
					db.prepare("DELETE FROM tokens WHERE token=?").run(sdata.authToken);
				}
				send(ws, encodeMsgpack({
					perms: 0
				}));
				sdata.isAdmin = false
				send(ws, encodeMsgpack({ admin: false }));
				sdata.isAuthenticated = false;
				sdata.authUser = "";
				sdata.authUserId = 0;
				sdata.isMember = false;
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					cu: {
						id: sdata.clientId,
						l: [sdata.cursorX, sdata.cursorY],
						c: sdata.cursorColor,
						n: sdata.cursorAnon ? "" : (sdata.isAuthenticated ? sdata.authUser : "")
					}
				}), ws);
			} else if ("addmem" == packetType) {
				var member = data.addmem;

				if (typeof member != "string") return;
				if (member.length > 64) return;

				if (sdata.isAuthenticated && sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) {
					var exists = db.prepare("SELECT * FROM members WHERE username=? AND world_id=? COLLATE NOCASE").get(member, sdata.connectedWorldId);
					if (!exists) {
						db.prepare("INSERT INTO members VALUES(?, ?)").run(sdata.connectedWorldId, member);
						send(ws, encodeMsgpack({
							addmem: member
						}));
					}
				}
			} else if ("rmmem" == packetType) {
				var member = data.rmmem;

				if (typeof member != "string") return;
				if (member.length > 64) return;

				if (sdata.isAuthenticated && sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) {
					db.prepare("DELETE FROM members WHERE world_id=? AND username=? COLLATE NOCASE").run(sdata.connectedWorldId, member);
				}
			} else if ("deleteaccount" == packetType) {
				var pass = data.deleteaccount;

				if (typeof pass != "string") return;
				if (pass.length > 64) return;

				var tokenData = db.prepare("SELECT * FROM tokens WHERE token=?").get(sdata.authToken);
				if (tokenData) {
					var user_id = tokenData.user_id;
					var account = db.prepare("SELECT * FROM users WHERE id=?").get(user_id);
					if (account) {
						var db_pass = account.password;
						var isValid = checkHash(db_pass, pass);
						if (isValid) {
							db.prepare("DELETE FROM users WHERE id=?").run(account.id);
							db.prepare("UPDATE worlds SET namespace=? WHERE namespace=?").run("del-" + Math.random() + "-" + account.username, account.username);
							db.prepare("DELETE FROM tokens WHERE token=?").run(sdata.authToken);
							send(ws, encodeMsgpack({
								accountdeleted: true
							}));
							sdata.authToken = "";
							sdata.isAuthenticated = false;
							sdata.authUser = "";
							sdata.authUserId = 0;
							sdata.isMember = false;
							sdata.connectedWorldNamespace = "textwall";
							sdata.connectedWorldName = "main";
							sdata.connectedWorldId = 1;
							send(ws, encodeMsgpack({
								perms: 0
							}));
						} else {
							send(ws, encodeMsgpack({
								wrongpass: true
							}));
						}
					}
				}
			} else if ("ro" == packetType) { // readonly
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "readonly", Boolean(data.ro));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					ro: Boolean(data.ro)
				}));
			} else if ("priv" == packetType) { // private
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "private", Boolean(data.priv));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					priv: Boolean(data.priv)
				}));
			} else if ("ch" == packetType) { // hide cursors
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "hideCursors", Boolean(data.ch));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					ch: Boolean(data.ch)
				}));
			} else if ("dc" == packetType) { // disable chat
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "disableChat", Boolean(data.dc));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					dc: Boolean(data.dc)
				}));
			} else if ("dcl" == packetType) { // disable color
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "disableColor", Boolean(data.dcl));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					dcl: Boolean(data.dcl)
				}));
			} else if ("db" == packetType) { // disable braille
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				editWorldAttr(sdata.connectedWorldId, "disableBraille", Boolean(data.db));
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					db: Boolean(data.db)
				}));
			} else if ("p" == packetType) { // protect
				var pos = data.p;
				if (typeof pos != "string") return;
				pos = pos.split(",");
				if (pos.length != 2) return;
				x = san_nbr(pos[0]);
				y = san_nbr(pos[1]);
				if (x % 20 != 0) return;
				if (y % 10 != 0) return;
				x /= 20;
				y /= 10;
				if (!sdata.isMember) {
					return;
				}
				var prot = toggleProtection(sdata.connectedWorldId, x, y);
				if (settings.log.enabled) {
					fs.appendFile(settings.log.path, `protect;time=${new Date().toLocaleString()};newstate=${prot};worldid=${sdata.connectedWorldId};x=${x};y=${y};ip=${ipAddr};user=${sdata.authUser};worldnamespace=${sdata.connectedWorldNamespace};worldname=${sdata.connectedWorldName}\n`, function () { });
				}
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					p: [(x * 20) + "," + (y * 10), Boolean(prot)]
				}));
			} else if ("dw" == packetType) {
				var isOwner = sdata.isAuthenticated && (
					(sdata.connectedWorldNamespace && sdata.connectedWorldNamespace.toLowerCase() == sdata.authUser.toLowerCase()) ||
					(settings.adminList && settings.adminList.includes(sdata.authUser))
				);
				if (!isOwner) return;
				db.prepare("UPDATE worlds SET namespace=? WHERE id=?").run("del-" + Math.random(), sdata.connectedWorldId);
				var kWorld = sdata.connectedWorldId;
				wss.clients.forEach(function (sock) {
					if (!sock || !sock.sdata) return;
					if (sock.sdata.connectedWorldId == kWorld) {
						evictClient(sock);
					}
				});
			} else if ("namechange" == packetType) {
				var set = data.namechange;

				if (!Array.isArray(set)) return;

				var newUser = set[0];
				var pass = set[1];

				if (typeof newUser != "string") return;
				if (typeof pass != "string") return;
				if (newUser.length > 64) return;
				if (pass.length > 128) return;

				var isValid = validateUsername(newUser);
				if (!isValid) {
					send(ws, encodeMsgpack({
						alert: "Bad username - it must be 1-64 chars and have the following chars: A-Z a-z 0-9 - _ ."
					}));
					return;
				}


				var tokenData = db.prepare("SELECT * FROM tokens WHERE token=?").get(sdata.authToken);
				if (tokenData) {
					var user_id = tokenData.user_id;
					var account = db.prepare("SELECT * FROM users WHERE id=?").get(user_id);
					if (account) {
						var db_pass = account.password;
						var isValidHash = checkHash(db_pass, pass);
						if (isValidHash) {
							var userCheck = db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(newUser);
							if (userCheck) {
								send(ws, encodeMsgpack({
									nametaken: true
								}));
							} else {
								var oldUser = account.username;
								db.prepare("UPDATE users SET username=? WHERE id=?").run(newUser, sdata.authUserId);
								sdata.authUser = newUser;
								send(ws, encodeMsgpack({
									namechanged: newUser
								}));
								db.prepare("UPDATE worlds SET namespace=? WHERE namespace=? COLlATE NOCASE").run(newUser, oldUser);
								db.prepare("UPDATE tokens SET username=? WHERE user_id=?").run(newUser, account.id);
								var kWorld = sdata.connectedWorldId;
								wss.clients.forEach(function (sock) {
									if (!sock || !sock.sdata) return;
									if (sock.sdata.connectedWorldNamespace && sock.sdata.connectedWorldNamespace.toLowerCase() == oldUser.toLowerCase()) {
										evictClient(sock);
									}
								});
							}
						} else {
							send(ws, encodeMsgpack({
								wrongpass: true
							}));
						}
					}
				}
			} else if ("passchange" == packetType) {
				var set = data.passchange;

				if (!Array.isArray(set)) return;

				var oldPass = set[0];
				var newPass = set[1];

				if (typeof oldPass != "string") return;
				if (typeof newPass != "string") return;
				if (oldPass.length > 64) return;
				if (newPass.length > 128) return;


				var tokenData = db.prepare("SELECT * FROM tokens WHERE token=?").get(sdata.authToken);
				if (tokenData) {
					var user_id = tokenData.user_id;
					var account = db.prepare("SELECT * FROM users WHERE id=?").get(user_id);
					if (account) {
						var db_pass = account.password;
						var isValid = checkHash(db_pass, oldPass);
						if (isValid) {
							db.prepare("UPDATE users SET password=? WHERE id=?").run(encryptHash(newPass), user_id);
							send(ws, encodeMsgpack({
								passchanged: true
							}));
						}
					} else {
						send(ws, encodeMsgpack({
							wrongpass: true
						}));
					}
				}
			} else if ("c" == packetType) {
				var pos = data.c;

				if (!Array.isArray(pos)) return;

				var x = pos[0];
				var y = pos[1];

				if (!Number.isInteger(x)) return;
				if (!Number.isInteger(y)) return;

				if (x % 20 != 0) return;
				if (y % 10 != 0) return;
				x /= 20;
				y /= 10;
				x = Math.floor(x);
				y = Math.floor(y);
				if (!sdata.isMember) {
					return;
				}
				clearChunk(sdata.connectedWorldId, x, y);
				if (settings.log.enabled) {
					fs.appendFile(settings.log.path, `clearchunk;time=${new Date().toLocaleString()};worldid=${sdata.connectedWorldId};x=${x};y=${y};ip=${ipAddr};user=${sdata.authUser};worldnamespace=${sdata.connectedWorldNamespace};worldname=${sdata.connectedWorldName}\n`, function () { });
				}
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					c: [x * 20, y * 10, x * 20 + 20 - 1, y * 10 + 10 - 1]
				}));
			} else if ("ping" == packetType) {
				// Pong!
				send(ws, encodeMsgpack({
					pong: true
				}));
			}
			else {
				//console.log(data)
			}

		});

		ws.on("close", function () {
			closed = true;
			onlineCount--;
			broadcast(encodeMsgpack({
				online: onlineCount
			}), ws);
            delete clients[sdata.clientId];
			if (sdata && sdata.isConnected) {
				worldBroadcast(sdata.connectedWorldId, encodeMsgpack({
					rc: sdata.clientId
				}), ws);
				
			}
			

			connObj[0]--;
		});
		ws.on("error", function () {
			console.log("Client error");
		});
	});
}


async function initServer() {
	if (!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='server_info'").get()) {
		db.prepare("CREATE TABLE 'server_info' (name TEXT, value TEXT)").run();


		db.prepare("CREATE TABLE 'worlds' (id INTEGER NOT NULL PRIMARY KEY, namespace TEXT, name TEXT, attributes TEXT)").run();
		db.prepare("CREATE TABLE 'users' (id INTEGER NOT NULL PRIMARY KEY, username TEXT, password TEXT, date_joined INTEGER)").run();
		db.prepare("CREATE TABLE 'tokens' (token TEXT, username TEXT, user_id INTEGER NOT NULL)").run();
		db.prepare("CREATE TABLE 'members' (world_id INTEGER, username TEXT)").run();
		db.prepare("CREATE TABLE 'chunks' (world_id INTEGER NOT NULL, x INTEGER NOT NULL, y INTEGER NOT NULL, text TEXT, colorFmt TEXT, protected INTEGER)").run();

		db.prepare("CREATE INDEX 'ic' ON 'chunks' (world_id, x, y)").run();
		db.prepare("CREATE INDEX 'iu' ON 'users' (username)").run();
		db.prepare("CREATE INDEX 'it' ON 'tokens' (token)").run();
		db.prepare("CREATE INDEX 'im' ON 'members' (world_id)").run();
		db.prepare("CREATE INDEX 'im2' ON 'members' (world_id, username)").run();
		db.prepare("CREATE INDEX 'iw' ON 'worlds' (namespace)").run();
		db.prepare("CREATE INDEX 'iw2' ON 'worlds' (namespace, name)").run();

		db.prepare("INSERT INTO 'worlds' VALUES(null, ?, ?, ?)").run("textwall", "main", JSON.stringify({
			readonly: false,
			private: false,
			hideCursors: false,
			disableChat: false,
			disableColor: false,
			disableBraille: false
		}));
	}
	runserver();
}
initServer();
function writeText(text, startX, startY, color, wid, isMember = true) {
	const CHUNK_WIDTH = 20;
	const CHUNK_HEIGHT = 10;
	const resp = [];

	for (let i = 0; i < text.length; i++) {
		const x = startX + i;
		const y = startY;
		const chr = text.charCodeAt(i);
		if (chr === 0 || (chr >= 0xD800 && chr <= 0xDFFF)) continue;

		const chunkX = Math.floor(x / CHUNK_WIDTH);
		const chunkY = Math.floor(y / CHUNK_HEIGHT);

		const localX = x % CHUNK_WIDTH;
		const localY = y % CHUNK_HEIGHT;
		const idx = localY * CHUNK_WIDTH + localX;

		const stat = writeChunk(wid, chunkX, chunkY, idx, chr, color, isMember);
		if (!stat) continue;
		let chunk = resp.find(c => c[0] === chunkX && c[1] === chunkY);
		if (!chunk) {
			chunk = [chunkX, chunkY];
			resp.push(chunk);
		}
		chunk.push(chr, idx, color);
	}

	worldBroadcast(wid, encodeMsgpack({ e: { e: resp } }));

	return true;
}
function toggleProtectionV2(worldId, chunkX, chunkY) {

	chunkX = Math.floor(chunkX);
	chunkY = Math.floor(chunkY);

	const tuple = `${worldId},${chunkX},${chunkY}`;
	const chunk = getChunk(worldId, chunkX, chunkY, true);
	chunk.protected = !chunk.protected;
	modifiedChunks[tuple] = true;
	const broadcastX = chunkX * 20;
	const broadcastY = chunkY * 10;
	worldBroadcast(worldId, encodeMsgpack({
		p: [`${broadcastX},${broadcastY}`, Boolean(chunk.protected)]
	}));

	return chunk.protected;
}
function clearChunkV2(worldId, chunkX, chunkY, isMember = true) {
	chunkX = Math.floor(chunkX);
	chunkY = Math.floor(chunkY);
	const chunk = getChunk(worldId, chunkX, chunkY, true);
	if (!chunk) return false;
	if (!isMember && chunk.protected) return false;
	chunk.char = Array(20 * 10).fill(String.fromCodePoint(32)); // empty space
	chunk.color = Array(20 * 10).fill(0); // default color
	modifiedChunks[`${worldId},${chunkX},${chunkY}`] = true;
	worldBroadcast(worldId, encodeMsgpack({
		c: [
			chunkX * 20,
			chunkY * 10,
			chunkX * 20 + 19, // max x in chunk
			chunkY * 10 + 9   // max y in chunk
		]
	}));

	return true;
}

process.once("SIGINT", function () {
	console.log("Server is closing, saving...");
	clearInterval(memClrInterval);
	clearInterval(saveMuteInterval);
	commitChunks();
	process.exit();
});
