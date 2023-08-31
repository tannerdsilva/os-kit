import cos

/// obtains a lock from the system to safely access the user entry database and modifify its contents.
/// - enables safe access to /etc/passwd, /etc/group/ and their shadow counterparts.
/// - this function is asynchronous as obtaining the lock may take some time.
/// - throws: 
/// 	- Errors.InsufficientPermissions if the calling process does not have sufficient permissions to access the user entry database.
/// 	- CancellationError if the task is cancelled while waiting for the lock.
public func withUserEntryLock<R>(_ lockHandler:() throws -> R) async throws -> R {
	// verify access to the system files.
	guard access("/etc/passwd", R_OK & W_OK) == 0 else {
		throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/passwd")
	}
	guard access("/etc/group", R_OK & W_OK) == 0 else {
		throw Errors.InsufficientPermissions(whoami:CurrentProcess.effectiveUsername(), accessPath:"/etc/group")
	}

	// obtain the lock. this will block forever if access is not verified up front.
	try await withUnsafeThrowingContinuation { (continuation:UnsafeContinuation<Void, Swift.Error>) in
		while lckpwdf() != 0 && Task.isCancelled == false {
			usleep(1000)
		}
		guard Task.isCancelled == false else {
			continuation.resume(throwing:CancellationError())
			return
		}
		continuation.resume()
	}
	defer {
		ulckpwdf()
	}

	return try lockHandler()
}