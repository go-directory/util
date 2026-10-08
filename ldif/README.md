# ldif

Package ldif implements portions of [RFC2849](https://datatracker.ietf.org/doc/html/rfc2849) using a heavily modified rendition of [go-ldap/ldif](https://github.com/go-ldap/ldif).

This package is modified specifically for use by the [Go Directory Project](https://github.com/go-directory).

# Status

This package is prone to breaking changes and is still undergoing heavy development periodically. It is not suitable for use in any production environment at this time.

# Warning

This package is NOT meant for use as a general-use LDIF utility, and its scope is largely internal within the [Go Directory Project](https://github.com/go-directory) space. End users are advised to continue using [go-ldap/ldif](https://github.com/go-ldap/ldif).

# License

This package is released under the terms of the MIT license. See the LICENSE file in the package directory for details.

# Change log

The differences between the original [go-ldap/ldif](https://github.com/go-ldap/ldif) and this rendition are vast.

  - Various coverage gaps filled
  - General code clean-up
  - Built-in DUA (client) functionality removed
  - Import of [go-directory/protocol](https://github.com/go-directory/protocol) and [go-directory/syntax](https://github.com/go-directory/syntax) to supplement the removal of built-in DUA functionality
  - Needless cyclomatic penalties reduced
  - Large functions (including tests) broken up into more manageable portions
  - Various spelling and grammatical errors corrected
  - "ineffassign" fixes
  - Windows path-related functionality removed
  - Initial prep-work for ModifyDN support in-place (not yet available)
