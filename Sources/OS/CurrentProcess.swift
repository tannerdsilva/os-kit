import cos

/// functions and properties related to the current process.
public struct CurrentProcess {
	// effective user
	// get: name
	/// returns the effective username that the calling process is running as.
	/// - WARNING: this is a low level function that should be used with caution.
	public static func effectiveUsername() -> String {
		return String(validatingUTF8:getpwuid(geteuid()).pointee.pw_name)!
	}
	// get: uid
	/// returns the effective UID that the calling process is running as.
	public static func effectiveUID() -> uid_t {
		return geteuid()
	}
	// set: name
	/// sets the effective user that the calling process will run as.
	/// - WARNING: this is a low level function that should be used with caution.
	public static func set(effectiveUsername:String) throws {
		let uid = getpwnam(effectiveUsername)
		guard uid != nil else {
			throw Errors.NotFound(expectedValue:effectiveUsername)
		}
		let resultCode = seteuid(uid!.pointee.pw_uid)
		guard resultCode == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}
	// set: uid
	/// sets the effective user that the calling process will run as.
	/// - WARNING: this is a low level function that should be used with caution.
	public static func set(effectiveUID:uid_t) throws {
		let resultCode = seteuid(effectiveUID)
		guard resultCode == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}

	// effective group
	/// get: name
	/// returns the effective groupname that the calling process is running as.
	public static func effectiveGroupname() -> String {
		return String(validatingUTF8:getgrgid(getegid()).pointee.gr_name)!
	}
	// get: gid
	/// returns the effective GID that the calling process is running as.
	public static func effectiveGID() -> gid_t {
		return getegid()
	}
	// set: name
	/// sets the effective group that the calling process will run as.
	/// - WARNING: this is a low level function that should be used with caution.
	public static func set(effectiveGroupname:String) throws {
		let gid = getgrnam(effectiveGroupname)
		guard gid != nil else {
			throw Errors.NotFound(expectedValue:effectiveGroupname)
		}
		let resultCode = setegid(gid!.pointee.gr_gid)
		guard resultCode == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}
	// set: gid
	/// sets the effective group that the calling process will run as.
	/// - WARNING: this is a low level function that should be used with caution.
	public static func set(effectiveGID:gid_t) throws {
		let resultCode = setegid(effectiveGID)
		guard resultCode == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}
}

