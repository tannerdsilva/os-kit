import cos

public struct User {

	/// creates a new user on the system with locked access.
	/// - NOTE: this function's name does NOT begin with an underscore to signify that it does NOT require external locking (the locking is handled internally).
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
	public static func create(name:String, uid:UInt32, gid:UInt32, shell:String, homeDirectory:String, fullName:String?, shadow:Shadow.Configuration?) async throws {
		try await withUserEntryLock {
			try _create(name:name, uid:uid, gid:gid, shell:shell, homeDirectory:homeDirectory, fullName:fullName, shadow:shadow)
		}
	}

	/// creates a new user on the system without locking.
	/// - NOTE: this function's name begins with an underscore to signify that it requires external locking.
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
	public static func _create(name:String, uid:uid_t, gid:gid_t, shell:String, homeDirectory:String, fullName:String?, shadow:Shadow.Configuration?) throws {
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
		var foundEntries:UInt = 0
		var writtenEntries:UInt = 0
		setpwent()
		defer {
			endpwent()
		}
		while let nextUser = getpwent() {
			foundEntries += 1
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
				writtenEntries += 1
			}
		}
		
		// place the new entry in the cow file
		guard putpwent(&newUser, cowFile) == 0 else {
			throw Errors.Internal.placementError
		}
		writtenEntries += 1

		// safety check. verifiy that...
		// - we started with nonzero entries.
		// - a new entry was added to the set of existing entries.
		guard foundEntries > 0 && foundEntries + 1 == writtenEntries else {
			throw Errors.Internal.placementError
		}

		// swap the cow file with the original.
		guard rename("/etc/passwd.cow", "/etc/passwd") == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}

		// make the shadow entry
		do {
			try Shadow._create(name:name, configuration:shadow ?? Shadow.Configuration.defaultConfiguration())
		} catch let error {
			// remove the user entry.
			try? _remove(name:name)
			throw error
		}
	}

	/// removes a user from the system with locked access.
	/// - NOTE: this function does NOT begin with an underscore to signify that it does NOT require external locking (the locking is handled internally).
	/// - atomically swaps the password file to ensure no corruption.
	/// - preserves the permissions of the original password file.
	/// - throws:
	/// 	- `InsufficientPermissions` if the calling process does not have sufficient permissions to modify the password file.
	///		- `NotFound` if the user does not exist.
	public static func remove(name username:String) async throws {
		try await withUserEntryLock {
			try _remove(name:username)
		}
	}

	/// removes a user from the system without a lock.
	/// - NOTE: this function's name begins with an underscore to signify that it requires external locking.
	/// - atomically swaps the password file to ensure no corruption.
	/// - preserves the permissions of the original password file.
	/// - throws:
	/// 	- `InsufficientPermissions` if the calling process does not have sufficient permissions to modify the password file.
	///		- `NotFound` if the user does not exist.
	public static func _remove(name username:String) throws {
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
		var foundEntries:UInt = 0
		var writtenEntries:UInt = 0
		setpwent()
		defer {
			endpwent()
		}
		while let nextUser = getpwent() {
			foundEntries += 1
			if String(cString:nextUser.pointee.pw_name) == username {
				// skip this entry.
				didFind = true
			} else {
				// the entry shall be copied to the cow file.
				guard putpwent(nextUser, cowFile) == 0 else {
					throw Errors.Internal.placementError
				}
				writtenEntries += 1
			}
		}

		// ensure that the user actually exists.
		guard didFind else {
			throw Errors.NotFound(expectedValue:username)
		}

		// safety check.
		guard foundEntries > 0 && foundEntries - 1 == writtenEntries else {
			throw Errors.Internal.placementError
		}

		// swap the cow file with the original.
		guard rename("/etc/passwd.cow", "/etc/passwd") == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
		}

		// remove the shadow entry.
		do {
			try Shadow._remove(name:username)
		} catch let error {
			// remove the user entry.
			try? _remove(name:username)
			throw error
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

		/// creates a user shadow entry on the system with locked access.
		/// - NOTE: this function does NOT begin with an underscore to signify that it does NOT require external locking (the locking is handled internally).
		public static func create(name:String, configuration:Configuration) async throws {
			try await withUserEntryLock {
				try _create(name:name, configuration:configuration)
			}
		}

		/// creates a user shadow entry on the system without locked access.
		/// - NOTE: this function's name begins with an underscore to signify that it requires external locking.
		/// - uses system-defined locking functions to ensure maximum safety with other compliant softwares.
		/// - atomically swaps the shadow file to ensure no corruption.
		/// - preserves the permissions of the original shadow file.
		public static func _create(name:String, configuration:Configuration) throws {
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
			var foundEntries:UInt = 0
			var writtenEntries:UInt = 0
			setspent()
			defer {
				endspent()
			}
			while let nextUser = getspent() {
				foundEntries += 1
				if String(cString:nextUser.pointee.sp_namp) == name {
					throw Errors.ValueExists(value:"name:\(name)")
				} else {
					guard putspent(nextUser, cowFile) == 0 else {
						throw Errors.Internal.placementError
					}
					writtenEntries += 1
				}
			}

			// place the new entry in the cow file
			guard putspent(&newUser, cowFile) == 0 else {
				throw Errors.Internal.placementError
			}
			writtenEntries += 1

			// safety check. verifiy that...
			// - we started with nonzero entries.
			// - a new entry was added to the set of existing entries.
			guard foundEntries > 0 && foundEntries + 1 == writtenEntries else {
				throw Errors.Internal.placementError
			}

			// swap the cow file with the original.
			guard rename("/etc/shadow.cow", "/etc/shadow") == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
		}

		/// removes a user shadow entry from the system with locked access.
		///	- NOTE: this function does NOT begin with an underscore to signify that it does NOT require external locking (the locking is handled internally). 
		/// - atomically swaps the shadow file to ensure no corruption.
		/// - preserves the permissions of the original shadow file.
		public static func remove(name:String) async throws {
			try await withUserEntryLock {
				try _remove(name:name)
			}
		}

		/// removes a user shadow entry from the system without locked access.
		/// - NOTE: this function's name begins with an underscore to signify that it requires external locking.
		/// - atomically swaps the shadow file to ensure no corruption.
		/// - preserves the permissions of the original shadow file.
		public static func _remove(name:String) throws {
			// verify access to the shadow file.
			guard access("/etc/shadow", R_OK | W_OK) == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
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
			var foundEntries:UInt = 0
			var writtenEntries:UInt = 0
			setspent()
			defer {
				endspent()
			}
			while let nextUser = getspent() {
				foundEntries += 1
				if String(cString:nextUser.pointee.sp_namp) == name {
					// skip this entry.
					didFind = true
				} else {
					// the entry shall be copied to the cow file.
					guard putspent(nextUser, cowFile) == 0 else {
						throw Errors.Internal.placementError
					}
					writtenEntries += 1
				}
			}

			// ensure that the user actually exists.
			guard didFind else {
				throw Errors.NotFound(expectedValue:name)
			}

			// safety check. verify that...
			// - we started with nonzero entries.
			// - a entry was removed from the set of existing entries.
			guard foundEntries > 0 && foundEntries - 1 == writtenEntries else {
				throw Errors.Internal.placementError
			}

			// swap the cow file with the original.
			guard rename("/etc/shadow.cow", "/etc/shadow") == 0 else {
				throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/shadow")
			}
		}
	}
}
