# CPMAddPackage(
#   NAME cxxopts
#   GITHUB_REPOSITORY jarro2783/cxxopts
#   VERSION 2.2.1
#   OPTIONS
#     "CXXOPTS_BUILD_EXAMPLES Off"
#     "CXXOPTS_BUILD_TESTS Off"
# )

CPMAddPackage(
  NAME CLI11
  GITHUB_REPOSITORY CLIUtils/CLI11
  VERSION 1.9.1
  DOWNLOAD_ONLY True
)

CPMAddPackage(
  NAME Catch2
  GITHUB_REPOSITORY catchorg/Catch2
  VERSION 2.13.2
 )

 CPMAddPackage(
  NAME strutils
  GITHUB_REPOSITORY msaf1980/cppstrutils
  VERSION 0.1.1
 )
