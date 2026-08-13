#!/bin/bash
# Refresh html/eid/ from the pages the association's site serves.
#
# The eid generators are written once, in foopgp-hugowebsite/static/eid/, and
# served from two places: foopgp.org/eid/ and this key server. They were built
# to be copied — "Absolute links: this page is meant to be copied and served
# elsewhere", says their own source — so the copy here is verbatim and never
# patched. Anything to change is changed there and synced back.
#
# coreutils only, no rsync: five files, and a script that needs a package the
# machine may not have is a script that fails the day it is needed.
#
# Usage: tools/sync-eid.sh [SOURCE] [--check]
#   SOURCE   defaults to ~/git/foopgp/foopgp-hugowebsite/static/eid
#   --check  say what differs, write nothing (exit 1 if the copy is behind)

set -o pipefail

readonly ROOT="$(dirname "$(dirname "$(readlink --canonicalize "$0")")")"
readonly DEST="$ROOT/html/eid"

src="${HOME}/git/foopgp/foopgp-hugowebsite/static/eid"
check=0
for ((;$#;)) ; do
    case "$1" in
        --check) check=1 ;;
        -h|--help) printf 'Usage: %s [SOURCE] [--check]\n' "${0##*/}" ; exit 0 ;;
        -*) printf '%s: Error: Unrecognized option '\''%s'\''\n' "${0##*/}" "$1" >&2 ; exit 2 ;;
        *) src="$1" ;;
    esac
    shift
done

if [[ ! -d "$src" ]] ; then
    printf '%s: Error: no such source directory: %s\n' "${0##*/}" "$src" >&2
    exit 2
fi

# Both what changed and what disappeared upstream: "Only in $DEST" is a file
# to drop, which a plain copy would leave behind for ever.
diff_out=$(diff --recursive --brief "$src" "$DEST" 2>&1)
if [[ -z "$diff_out" ]] ; then
    printf '%s: Info: html/eid/ already matches %s\n' "${0##*/}" "$src" >&2
    exit 0
fi
printf '%s\n' "$diff_out"

if ((check)) ; then
    printf '%s: Notice: html/eid/ differs from %s\n' "${0##*/}" "$src" >&2
    exit 1
fi

# Replace rather than overlay, so a page deleted upstream stops being served.
# Guarded: this deletes a directory, and the only one it may ever delete is
# the copy this script owns.
if [[ "$DEST" != */html/eid ]] ; then
    printf '%s: Error: refusing to erase %s\n' "${0##*/}" "$DEST" >&2
    exit 1
fi
rm --recursive --force -- "$DEST"
mkdir --parents -- "$DEST"
cp --recursive --preserve=timestamps -- "$src/." "$DEST/"
printf '%s: Info: html/eid/ refreshed from %s\n' "${0##*/}" "$src" >&2
