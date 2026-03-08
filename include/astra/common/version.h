// ============================================================================
// Astra Runtime - Version Information
// include/astra/common/version.h
//
// Compile-time version constants. The build system populates these.
// ============================================================================
#ifndef ASTRA_COMMON_VERSION_H
#define ASTRA_COMMON_VERSION_H

namespace astra
{

constexpr int    VERSION_MAJOR = 0;
constexpr int    VERSION_MINOR = 1;
constexpr int    VERSION_PATCH = 0;
constexpr char   VERSION_STRING[] = "0.1.0-dev";
constexpr char   VERSION_CODENAME[] = "foundation";

// Build metadata - set by CI, fallback to dev values
#ifndef ASTRA_BUILD_HASH
#define ASTRA_BUILD_HASH "dev"
#endif

#ifndef ASTRA_BUILD_DATE
#define ASTRA_BUILD_DATE __DATE__
#endif

#ifndef ASTRA_BUILD_TIME
#define ASTRA_BUILD_TIME __TIME__
#endif

constexpr char BUILD_HASH[] = ASTRA_BUILD_HASH;
constexpr char BUILD_DATE[] = ASTRA_BUILD_DATE;
constexpr char BUILD_TIME[] = ASTRA_BUILD_TIME;

} // namespace astra

#endif // ASTRA_COMMON_VERSION_H
