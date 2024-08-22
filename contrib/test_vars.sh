# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="rand-std serde base64 miniscript-std"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="rand serde base64 miniscript-no-std"

# Run these examples.
EXAMPLES="v0:std v2:std v2-separate-creator-constructor:std"
