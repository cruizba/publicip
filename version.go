package publicip

// version is the current version of the library. The release workflow rewrites this
// line, so keep the declaration on a single line and in this exact shape.
const version = "v2.0.1"

// Version returns the release the package was built from, as a vMAJOR.MINOR.PATCH tag.
func Version() string { return version }
