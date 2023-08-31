// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.
import PackageDescription
let package = Package(
	name: "os-kit",
	products: [
		.library(
			name: "OS",
			targets: ["OS"]),
	],
	dependencies:[
		.package(url:"https://github.com/apple/swift-log.git", from:"1.0.0"),
	],
	targets: [
		.target(
			name: "cos",
			cSettings: [
				.define("_GNU_SOURCE")
			]),
		.target(
			name:"OS",
			dependencies: [
				"cos",
				.product(name:"Logging", package:"swift-log"),
			]),
	]
)
