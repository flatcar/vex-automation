# portage

Compares Gentoo package versions (`Compare`) and evaluates GLSA version ranges
(`Satisfies`). Every GLSA verdict comes down to these two functions.

Semantic versioning can't be used: Gentoo versions look like `1.2.3_p4-r1` (patch level 4,
ebuild revision 1), with `_p`/`_rc` suffixes and letters (`1.0a`) that semver orders
differently or rejects. This is a direct port of Portage's own `vercmp`
(`lib/portage/versions.py`), including leading zeros (`1.02` < `1.1`), missing components
(`1.0` < `1.0.0`) and chained suffixes.

Range operators follow `lib/portage/glsa.py`: `lt`, `le`, `eq`, `ge`, `gt`; `eq` with a
trailing `*` is Portage's `=*` glob; and `rlt`, `rle`, `rge`, `rgt` compare only the `-rN`
revision within the same base version.

A version that can't be parsed is an error, never a guess, so callers report it as under
investigation instead of emitting a wrong VEX statement. `testdata` holds cases checked
against Portage itself.
