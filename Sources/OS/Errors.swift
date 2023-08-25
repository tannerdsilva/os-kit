/// errors that this library may throw
public struct Errors {
	/// Error: Internal
	/// errors that are mostly useful to developers of this framework.
	public enum Internal:Swift.Error {
		/// thrown when an entry could not be placed into a file. 
		case placementError
	}

	/// Error: Not Found
	/// thrown when an expected value or entry could not be found to complete the operation.
	public struct NotFound:Swift.Error {
		/// the expected value that was not found during the operation.
		public let expectedValue:CustomStringConvertible
	}

	/// Error: Value Exists
	/// thrown when a value already exists and cannot be created.
	public struct ValueExists:Swift.Error {
		/// the value that was found to already exist.
		public let value:CustomStringConvertible
	}

	/// Error: Insufficient Permissions
	/// thrown when the calling process does not have sufficient permissions to complete the operation.
	public struct InsufficientPermissions:Swift.Error {
		/// the user of the process that was attempting to access the file at the time of the error.
		public let whoami:String
		/// the path to the file that was being accessed.
		public let accessPath:String
	}

	/// Error: System Errno Code
	/// thrown when a system call returns an errno code.
	public struct SystemErrnoCode:Swift.Error {
		/// the errno code that was returned by the system call.
		public let code:Int32
	}
}
