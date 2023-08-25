import cos

public struct User {
	/// creates a new user on the system.
	/// - no system libraries are used for locking because there are no functions defined for this purpose with the passwd entries.
	/// - atomically swaps the password file to ensure no corruption.
	/// - preserves the permissions of the original password file.
	/// - parameters:
	/// 	- name: the name of the user.
	/// 	- uid: the UID of the user.
	/// 	- gid: the GID of the user.
	/// 	- shell: the shell path that the user will use.
	/// 	- homeDirectory: the home directory of the user.
	/// 	- fullName: the full name of the user. `nil` specifies no value for this field.
	/// 	- shadow: the shadow entry for the user. `nil` a default shadow entry, which is an indefinite password disable.
	/// - throws:
	///		- `InsufficientPermissions` if the calling process does not have sufficient permissions to modify the password file.
	///		- `ValueExists` if the user already exists.
	public static func create(name:String, uid:UInt32, gid:UInt32, shell:String, homeDirectory:String, fullName:String?, shadow:Shadow.Configuration?) throws {
		// create the shadow entry first.
		try Shadow.create(name:name, configuration:shadow ?? Shadow.Configuration.defaultConfiguration())
		
		// read from the password file.
		guard let modPwd = fopen("/etc/passwd", "r") else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
		defer {
			fclose(modPwd)
		}

		// create the new user entry in memory.
		var newUser = passwd()
		newUser.pw_name = strdup(name)
		defer {
			free(newUser.pw_name)
		}
		newUser.pw_passwd = strdup("x")
		defer {
			free(newUser.pw_passwd)
		}
		newUser.pw_uid = uid
		newUser.pw_gid = gid
		newUser.pw_gecos = strdup(fullName ?? "")
		defer {
			free(newUser.pw_gecos)
		}
		newUser.pw_dir = strdup(homeDirectory)
		defer {
			free(newUser.pw_dir)
		}
		newUser.pw_shell = strdup(shell)
		defer {
			free(newUser.pw_shell)
		}

		// stat the password file to get the permissions.
		var passwdStats = stat()
		guard stat("/etc/passwd", &passwdStats) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}

		// open the copy on write file.
		// - set the permissions to match the original.
		cos.remove("/etc/passwd.cow")
		let cowFile = fopen("/etc/passwd.cow", "w")
		defer {
			fclose(cowFile)
			cos.remove("/etc/passwd.cow")
		}
		guard chown("/etc/passwd.cow", passwdStats.st_uid, passwdStats.st_gid) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
		guard chmod("/etc/passwd.cow", passwdStats.st_mode) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}

		// iterate through the password file. 
		// - validate that there aren't going to be any conflicts.
		// - copy each valid entry to the copy on write file.
		setpwent()
		while let nextUser = getpwent() {
			if String(cString:nextUser.pointee.pw_name) == name {
				throw Errors.ValueExists(value:"name:\(name)")
			} else if nextUser.pointee.pw_uid == uid {
				throw Errors.ValueExists(value:"uid:\(uid)")
			} else if nextUser.pointee.pw_gid == gid {
				throw Errors.ValueExists(value:"gid:\(gid)")
			} else {
				guard putpwent(nextUser, cowFile) == 0 else {
					throw Errors.Internal.placementError
				}
			}
		}
		endpwent()
		
		// place the new entry in the cow file
		guard putpwent(&newUser, cowFile) == 0 else {
			throw Errors.Internal.placementError
		}

		// swap the cow file with the original.
		guard rename("/etc/passwd.cow", "/etc/passwd") == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
	}

	/// removes a user from the system.
	/// - no system libraries are used for locking because there are no functions defined for this purpose with the passwd entries.
	/// - atomically swaps the password file to ensure no corruption.
	/// - preserves the permissions of the original password file.
	/// - throws:
	/// 	- `InsufficientPermissions` if the calling process does not have sufficient permissions to modify the password file.
	///		- `NotFound` if the user does not exist.
	public static func remove(name username:String) throws {
		// remove the shadow entry first.
		try Shadow.remove(name:username)
		
		// read from the password file.
		guard let modPwd = fopen("/etc/passwd", "r") else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
		defer {
			fclose(modPwd)
		}

		// open the copy on write file using identical permissions to the original.
		var passwdStats = stat()
		guard stat("/etc/passwd", &passwdStats) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
		cos.remove("/etc/passwd.cow")
		let cowFile = fopen("/etc/passwd.cow", "w")
		defer {
			fclose(cowFile)
			cos.remove("/etc/passwd.cow")
		}
		guard chown("/etc/passwd.cow", passwdStats.st_uid, passwdStats.st_gid) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
		guard chmod("/etc/passwd.cow", passwdStats.st_mode) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}

		var didFind = false

		// iterate through the password file.
		// - validate that the name acutally exists.
		// - copy each valid (nonmatching) entry to the copy on write file.
		setpwent()
		while let nextUser = getpwent() {
			if String(cString:nextUser.pointee.pw_name) == username {
				// skip this entry.
				didFind = true
			} else {
				// the entry shall be copied to the cow file.
				guard putpwent(nextUser, cowFile) == 0 else {
					throw Errors.Internal.placementError
				}
			}
		}
		endpwent()

		// ensure that the user actually exists.
		guard didFind else {
			throw Errors.NotFound(expectedValue:username)
		}

		// swap the cow file with the original.
		guard rename("/etc/passwd.cow", "/etc/passwd") == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}
	}
}

extension User {
	/// functions and properties related the shadow database for system users.
	public struct Shadow {
		/// the metadata (excluding name) that is associated with a user shadow entry.
		public struct Configuration {
			/// the password hash for the user.
			/// - no password login will be allowed if this is set to `nil`.
			public var password:String?
			/// the number of days since the epoch that the password was last changed.
			public var minDays:Int?
			/// the number of days since the epoch that the password must be changed.
			public var maxDays:Int?
			/// the number of days before the password expires that the user will be warned.
			public var warningDays:Int?
			/// the number of days since the epoch that the account will be disabled.
			public var inactiveDays:Int?
			/// creates a new shadow entry configuration with safe defaults (no password login allowed, immediately and indefinitely)
			public static func defaultConfiguration() -> Configuration {
				return Configuration(password:nil, minDays:-1, maxDays:-1, warningDays:-1, inactiveDays:-1)
			}
		}

		/// creates a user shadow entry on the system.
		/// - uses system-defined locking functions to ensure maximum safety with other compliant softwares.
		/// - atomically swaps the shadow file to ensure no corruption.
		/// - preserves the permissions of the original shadow file.
		public static func create(name:String, configuration:Configuration) throws {
			// read from the shadow file.
			while lckpwdf() != 0 {
				usleep(1000)
			}
			defer {
				ulckpwdf()
			}
			guard let modShad = fopen("/etc/shadow", "r") else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			defer {
				fclose(modShad)
			}

			// create the shadow entry in memory
			var newUser = spwd()
			newUser.sp_namp = strdup(name)
			defer {
				free(newUser.sp_namp)
			}
			newUser.sp_pwdp = strdup(configuration.password ?? "!")
			defer {
				free(newUser.sp_pwdp)
			}
			newUser.sp_lstchg = (time(nil) / 24 * 60 * 60)
			newUser.sp_min = configuration.minDays ?? -1
			newUser.sp_max = configuration.maxDays ?? -1
			newUser.sp_warn = configuration.warningDays ?? -1
			newUser.sp_inact = configuration.inactiveDays ?? -1
			newUser.sp_expire = -1
			newUser.sp_flag = 0

			// open the copy on write file using identical permissions to the original.
			cos.remove("/etc/shadow.cow")
			let cowFile = fopen("/etc/shadow.cow", "w")
			defer {
				fclose(cowFile)
				cos.remove("/etc/shadow.cow")
			}
			var shadowStats = stat()
			guard stat("/etc/shadow", &shadowStats) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			guard chown("/etc/shadow.cow", shadowStats.st_uid, shadowStats.st_gid) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			guard chmod("/etc/shadow.cow", shadowStats.st_mode) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}

			// iterate through the shadow file.
			// - validate that there aren't going to be any conflicts.
			// - copy each valid entry to the copy on write file.
			setspent()
			while let nextUser = getspent() {
				if String(cString:nextUser.pointee.sp_namp) == name {
					throw Errors.ValueExists(value:"name:\(name)")
				} else {
					guard putspent(nextUser, cowFile) == 0 else {
						throw Errors.Internal.placementError
					}
				}
			}
			endspent()

			// place the new entry in the cow file
			guard putspent(&newUser, cowFile) == 0 else {
				throw Errors.Internal.placementError
			}

			// swap the cow file with the original.
			guard rename("/etc/shadow.cow", "/etc/shadow") == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
		}

		/// removes a user shadow entry from the system.
		/// - uses system-defined locking functions to ensure maximum safety with other compliant softwares.
		/// - atomically swaps the shadow file to ensure no corruption.
		/// - preserves the permissions of the original shadow file.
		public static func remove(name:String) throws {
			// read from the shadow file.
			while lckpwdf() != 0 {
				usleep(1000)
			}
			defer {
				ulckpwdf()
			}
			guard let modShad = fopen("/etc/shadow", "r") else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			defer {
				fclose(modShad)
			}

			// open the copy on write file using identical permissions to the original.
			var shadowStats = stat()
			guard stat("/etc/shadow", &shadowStats) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			cos.remove("/etc/shadow.cow")
			let cowFile = fopen("/etc/shadow.cow", "w")
			defer {
				fclose(cowFile)
				cos.remove("/etc/shadow.cow")
			}
			guard chown("/etc/shadow.cow", shadowStats.st_uid, shadowStats.st_gid) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
			guard chmod("/etc/shadow.cow", shadowStats.st_mode) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}

			var didFind = false

			// iterate through the shadow file.
			// - validate that the name acutally exists.
			// - copy each valid (nonmatching) entry to the copy on write file.
			setspent()
			while let nextUser = getspent() {
				if String(cString:nextUser.pointee.sp_namp) == name {
					// skip this entry.
					didFind = true
				} else {
					// the entry shall be copied to the cow file.
					guard putspent(nextUser, cowFile) == 0 else {
						throw Errors.Internal.placementError
					}
				}
			}
			endspent()

			// ensure that the user actually exists.
			guard didFind else {
				throw Errors.NotFound(expectedValue:name)
			}

			// swap the cow file with the original.
			guard rename("/etc/shadow.cow", "/etc/shadow") == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
		}
	}
}
