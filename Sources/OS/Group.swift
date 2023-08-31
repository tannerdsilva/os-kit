import cos

/// OS provides an interface to the operating system.
public struct Group {

	/// create a new group on the system.
	/// - parameters:
	///		- name: the name of the group to create.
	///		- gid: the GID to assign to the group.
	///		- members: the members to assign to the group.
	internal static func _create(name:String, gid:gid_t, members:[String]) throws {
		// verify access to the file.
		guard access("/etc/group", R_OK | W_OK) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
		}

		// read from the password file.
		guard let modGrp = fopen("/etc/group", "r") else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
		}
		defer {
			fclose(modGrp)
		}

		// create the new group entry in memory.
		var newGroup = group()
		newGroup.gr_name = strdup(name)
		defer {
			free(newGroup.gr_name)
		}
		newGroup.gr_passwd = strdup("x")
		defer {
			free(newGroup.gr_passwd)
		}
		newGroup.gr_gid = gid
		let membersArr = members.map({ strdup($0) })
		defer {
			for member in membersArr {
				free(member)
			}
		}
		let cMembers = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: membersArr.count + 1)
		defer {
			cMembers.deallocate()
		}
		cMembers.initialize(from:membersArr, count:membersArr.count)
		cMembers.advanced(by:membersArr.count).pointee = nil
		newGroup.gr_mem = cMembers

		// open the copy on write file using identical permissions to the original.
		cos.remove("/etc/group.cow")
		let cowFile = fopen("/etc/group.cow", "w")
		defer {
			fclose(cowFile)
			cos.remove("/etc/group.cow")
		}
		var statObj = stat()
		guard stat("/etc/group", &statObj) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
		}
		guard chmod("/etc/group.cow", statObj.st_mode) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group.cow")
		}
		guard chown("/etc/group.cow", statObj.st_uid, statObj.st_gid) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group.cow")
		}

		// iterate through the group file.
		// - validate that there aren't going to be any conflicts.
		// - copy each valid entry to the copy on write file.
		var foundEntries:UInt = 0
		var writtenEntries:UInt = 0
		setgrent()
		defer {
			endgrent()
		}
		while let nextGroup = getgrent() {
			foundEntries += 1
			if String(cString:nextGroup.pointee.gr_name) == name {
				throw Errors.ValueExists(value:"name:\(name)")
			} else if nextGroup.pointee.gr_gid == gid {
				throw Errors.ValueExists(value:"gid:\(name)")
			} else {
				guard _putgrent(nextGroup, cowFile) == 0 else {
					throw Errors.SystemErrnoCode(code:getErrno())
				}
				writtenEntries += 1
			}
		}

		// write the new group entry to the copy on write file.
		guard _putgrent(&newGroup, cowFile) == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
		writtenEntries += 1

		// verify that the expected number of entries were found and written.
		guard foundEntries > 0 && foundEntries + 1 == writtenEntries else {
			throw Errors.Internal.placementError
		}
		
		// move the copy on write file to the original.
		guard rename("/etc/group.cow", "/etc/group") == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}

	/// remove a group from the system.
	public static func remove(name:String) throws {
		// read from the password file.
		guard let modGrp = fopen("/etc/group", "r") else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
		}
		defer {
			fclose(modGrp)
		}

		// open the copy on write file using identical permissions to the original.
		cos.remove("/etc/group.cow")
		let cowFile = fopen("/etc/group.cow", "w")
		defer {
			fclose(cowFile)
			cos.remove("/etc/group.cow")
		}
		var statObj = stat()
		guard stat("/etc/group", &statObj) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
		}
		guard chmod("/etc/group.cow", statObj.st_mode) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group.cow")
		}
		guard chown("/etc/group.cow", statObj.st_uid, statObj.st_gid) == 0 else {
			throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group.cow")
		}

		// iterate through the group file.
		// - validate that there aren't going to be any conflicts.
		// - copy each valid entry to the copy on write file.
		var foundEntries:UInt = 0
		var writtenEntries:UInt = 0
		setgrent()
		defer {
			endgrent()
		}
		while let nextGroup = getgrent() {
			foundEntries += 1
			if String(cString:nextGroup.pointee.gr_name) == name {
				// skip this entry.
			} else {
				guard _putgrent(nextGroup, cowFile) == 0 else {
					throw Errors.SystemErrnoCode(code:getErrno())
				}
				writtenEntries += 1
			}
		}

		// verify that the expected number of entries were found and written.
		guard foundEntries > 0 && foundEntries - 1 == writtenEntries else {
			throw Errors.NotFound(expectedValue:"name:\(name)")
		}

		// move the copy on write file to the original.
		guard rename("/etc/group.cow", "/etc/group") == 0 else {
			throw Errors.SystemErrnoCode(code:getErrno())
		}
	}
}