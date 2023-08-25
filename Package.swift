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
	targets: [
		.target(
			name: "cos",
			cSettings: [
				.define("_GNU_SOURCE")
			]),
		.target(
			name:"OS",
			dependencies: ["cos"],
			cSettings: [
				.define("_GNU_SOURCE")
			]),
	]
)
