
// var ip = exports;
// var Buffer = require('buffer').Buffer;
import os = require("os");

export function toBuffer(ip: string, buff?: Buffer, offset?: number): Buffer {
	offset = ~~offset;

	let result: Buffer;

	if (isV4Format(ip)) {
		result = buff || new Buffer(offset + 4);
		ip.split(/\./g).map((byte) => {
			result[offset++] = parseInt(byte, 10) & 0xff;
		});
	} else if (isV6Format(ip)) {
		let sections = ip.split(":", 8);

		for (let i = 0; i < sections.length; i++) {
			let isv4 = isV4Format(sections[i]);
			let v4Buffer;

			if (isv4) {
				v4Buffer = toBuffer(sections[i]);
				sections[i] = v4Buffer.slice(0, 2).toString("hex");
			}

			if (v4Buffer && ++i < 8) {
				sections.splice(i, 0, v4Buffer.slice(2, 4).toString("hex"));
			}
		}

		if (sections[0] === "") {
			while (sections.length < 8) { sections.unshift("0"); }
		} else if (sections[sections.length - 1] === "") {
			while (sections.length < 8) { sections.push("0"); }
		} else if (sections.length < 8) {
			let i = 0;
			for (i = 0; i < sections.length && sections[i] !== ""; i++) {
				//
			}
			let argv = [i, 1];
			for (i = 9 - sections.length; i > 0; i--) {
				argv.push(0);
			}
			sections.splice.apply(sections, argv);
		}

		result = buff || new Buffer(offset + 16);
		for (let i = 0; i < sections.length; i++) {
			let word = parseInt(sections[i], 16);
			result[offset++] = (word >> 8) & 0xff;
			result[offset++] = word & 0xff;
		}
	}

	if (!result) {
		throw Error("Invalid ip address: " + ip);
	}

	return result;
};

export function toString(buff: Buffer, offset?: number, length?: number) {
	offset = ~~offset;
	length = length || (buff.length - offset);

	if (length === 4) {
		let result = [];
		// IPv4
		for (let i = 0; i < length; i++) {
			result.push(buff[offset + i]);
		}
		return result.join(".");
	} else if (length === 16) {
		let result = [];
		// IPv6
		for (let i = 0; i < length; i += 2) {
			result.push(buff.readUInt16BE(offset + i).toString(16));
		}
		let ipresult = result.join(":");
		ipresult = ipresult.replace(/(^|:)0(:0)*:0(:|$)/, "$1::$3");
		ipresult = ipresult.replace(/:{3,4}/, "::");
		return ipresult;
	}
};

const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
const ipv6Regex =
	/^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

export function isV4Format(ip: string): boolean {
	return ipv4Regex.test(ip);
};

export function isV6Format(ip: string): boolean {
	return ipv6Regex.test(ip);
};

function _normalizeFamily(family: string): string {
	return family ? family.toLowerCase() : "ipv4";
}

export function fromPrefixLen(prefixlen: number, family?: string) {
	if (prefixlen > 32) {
		family = "ipv6";
	} else {
		family = _normalizeFamily(family);
	}

	let len = 4;
	if (family === "ipv6") {
		len = 16;
	}
	let buff = new Buffer(len);

	for (let i = 0, n = buff.length; i < n; ++i) {
		let bits = 8;
		if (prefixlen < 8) {
			bits = prefixlen;
		}
		prefixlen -= bits;

		buff[i] = ~(0xff >> bits) & 0xff;
	}

	return toString(buff);
};

export function mask(addr_: string, mask_: string) {
	let addr = toBuffer(addr_);
	let mask = toBuffer(mask_);

	let result = new Buffer(Math.max(addr.length, mask.length));

	let i = 0;
	// Same protocol - do bitwise and
	if (addr.length === mask.length) {
		for (i = 0; i < addr.length; i++) {
			result[i] = addr[i] & mask[i];
		}
	} else if (mask.length === 4) {
		// IPv6 address and IPv4 mask
		// (Mask low bits)
		for (i = 0; i < mask.length; i++) {
			result[i] = addr[addr.length - 4 + i] & mask[i];
		}
	} else {
		// IPv6 mask and IPv4 addr
		for (i = 0; i < result.length - 6; i++) {
			result[i] = 0;
		}

		// ::ffff:ipv4
		result[10] = 0xff;
		result[11] = 0xff;
		for (i = 0; i < addr.length; i++) {
			result[i + 12] = addr[i] & mask[i + 12];
		}
		i = i + 12;
	}
	for (; i < result.length; i++) {
		result[i] = 0;
	}

	return toString(result);
};

export function cidr(cidrString: string) {
	let cidrParts = cidrString.split("/");

	let addr = cidrParts[0];
	if (cidrParts.length !== 2) {
		throw new Error("invalid CIDR subnet: " + addr);
	}

	let mask_ = fromPrefixLen(parseInt(cidrParts[1], 10));

	return mask(addr, mask_);
};

export function subnet(addr: string, mask_: string) {
	let networkAddress = toLong(mask(addr, mask_));

	// Calculate the mask's length.
	let maskBuffer = toBuffer(mask_);
	let maskLength = 0;

	for (let i = 0; i < maskBuffer.length; i++) {
		if (maskBuffer[i] === 0xff) {
			maskLength += 8;
		} else {
			let octet = maskBuffer[i] & 0xff;
			while (octet) {
				octet = (octet << 1) & 0xff;
				maskLength++;
			}
		}
	}

	let numberOfAddresses = Math.pow(2, 32 - maskLength);

	return {
		networkAddress: fromLong(networkAddress),
		firstAddress: numberOfAddresses <= 2 ?
			fromLong(networkAddress) :
			fromLong(networkAddress + 1),
		lastAddress: numberOfAddresses <= 2 ?
			fromLong(networkAddress + numberOfAddresses - 1) :
			fromLong(networkAddress + numberOfAddresses - 2),
		broadcastAddress: fromLong(networkAddress + numberOfAddresses - 1),
		subnetMask: mask_,
		subnetMaskLength: maskLength,
		numHosts: numberOfAddresses <= 2 ?
			numberOfAddresses : numberOfAddresses - 2,
		length: numberOfAddresses,
		contains: (other: string) => {
			return networkAddress === toLong(mask(other, mask_));
		}
	};
};

export function cidrSubnet(cidrString: string) {
	let cidrParts = cidrString.split("/");

	let addr = cidrParts[0];
	if (cidrParts.length !== 2) {
		throw new Error("invalid CIDR subnet: " + addr);
	}

	let mask = fromPrefixLen(parseInt(cidrParts[1], 10));

	return subnet(addr, mask);
};

export function not(addr: string): string {
	let buff = toBuffer(addr);
	for (let i = 0; i < buff.length; i++) {
		buff[i] = 0xff ^ buff[i];
	}
	return toString(buff);
};

export function or(a_: string, b_: string) {
	let a = toBuffer(a_);
	let b = toBuffer(b_);

	// same protocol
	if (a.length === b.length) {
		for (let i = 0; i < a.length; ++i) {
			a[i] |= b[i];
		}
		return toString(a);

		// mixed protocols
	} else {
		let buff = a;
		let other = b;
		if (b.length > a.length) {
			buff = b;
			other = a;
		}

		let offset = buff.length - other.length;
		for (let i = offset; i < buff.length; ++i) {
			buff[i] |= other[i - offset];
		}

		return toString(buff);
	}
};

export function isEqual(a_: string, b_: string) {
	let a = toBuffer(a_);
	let b = toBuffer(b_);

	// Same protocol
	if (a.length === b.length) {
		for (let i = 0; i < a.length; i++) {
			if (a[i] !== b[i]) { return false; };
		}
		return true;
	}

	// Swap
	if (b.length === 4) {
		let t = b;
		b = a;
		a = t;
	}

	// a - IPv4, b - IPv6
	for (let i = 0; i < 10; i++) {
		if (b[i] !== 0) { return false; }
	}

	let word = b.readUInt16BE(10);
	if (word !== 0 && word !== 0xffff) { return false; }

	for (let i = 0; i < 4; i++) {
		if (a[i] !== b[i + 12]) { return false; }
	}

	return true;
};

export function isPrivate(addr: string): boolean {
	return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i
		.test(addr) ||
		/^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
		/^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i
			.test(addr) ||
		/^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
		/^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
		/^f[cd][0-9a-f]{2}:/i.test(addr) ||
		/^fe80:/i.test(addr) ||
		/^::1$/.test(addr) ||
		/^::$/.test(addr);
};

export function isPublic(addr: string): boolean {
	return !isPrivate(addr);
};

export function isLoopback(addr: string): boolean {
	return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/
		.test(addr) ||
		/^fe80::1$/.test(addr) ||
		/^::1$/.test(addr) ||
		/^::$/.test(addr);
};

export function loopback(family?: string): string {
	//
	// Default to `ipv4`
	//
	family = _normalizeFamily(family);

	if (family !== "ipv4" && family !== "ipv6") {
		throw new Error("family must be ipv4 or ipv6");
	}

	return family === "ipv4" ? "127.0.0.1" : "fe80::1";
};

//
// ### function address (name, family)
// #### @name {string|'public'|'private'} **Optional** Name or security
//      of the network interface.
// #### @family {ipv4|ipv6} **Optional** IP family of the address (defaults
//      to ipv4).
//
// Returns the address for the network interface on the current system with
// the specified `name`:
//   * String: First `family` address of the interface.
//             If not found see `undefined`.
//   * 'public': the first public ip address of family.
//   * 'private': the first private ip address of family.
//   * undefined: First address with `ipv4` or loopback address `127.0.0.1`.
//
export function address(name?: string, family?: string) {
	let interfaces = os.networkInterfaces();

	//
	// Default to `ipv4`
	//
	family = _normalizeFamily(family);

	//
	// If a specific network interface has been named,
	// return the address.
	//
	if (name && name !== "private" && name !== "public") {
		let res = interfaces[name].filter((details) => {
			let itemFamily = details.family.toLowerCase();
			return itemFamily === family;
		});
		if (res.length === 0) {
			return undefined;
		}
		return res[0].address;
	}

	let all = Object.keys(interfaces).map((nic) => {
		//
		// Note: name will only be `public` or `private`
		// when this is called.
		//
		let addresses = interfaces[nic].filter((details) => {
			details.family = details.family.toLowerCase();
			if (details.family !== family || isLoopback(details.address)) {
				return false;
			} else if (!name) {
				return true;
			}

			return name === "public" ? isPublic(details.address) : isPrivate(details.address);
		});

		return addresses.length ? addresses[0].address : undefined;
	}).filter(Boolean);

	return !all.length ? loopback(family) : all[0];
};

export function toLong(ip: string): number {
	let ipl: number = 0;
	ip.split(".").forEach((octet) => {
		ipl <<= 8;
		ipl += parseInt(octet);
	});
	return (ipl >>> 0);
};

export function fromLong(ipl: number): string {
	return ((ipl >>> 24) + "." +
		(ipl >> 16 & 255) + "." +
		(ipl >> 8 & 255) + "." +
		(ipl & 255));
};
