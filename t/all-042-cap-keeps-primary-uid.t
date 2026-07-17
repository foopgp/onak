#!/bin/sh
# The UID cap is FIFO (drops the oldest excess). The primary UID — for
# foopgp the identity anchor UID:urn:eid: — is minted once and is thus
# the oldest, so a naive FIFO would evict it. Check it is protected: the
# key carries 41 UIDs, its primary is the OLDEST one, and after the
# default cap of 32 the primary must still be present.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/primaryuid.key
INDEX=$(${BUILDDIR}/onak -c $1 index 0x593B12BC426D1EAD 2>/dev/null)
COUNT=$(echo "$INDEX" | grep -c '@example.org' || true)
if [ "$COUNT" != "32" ]; then
	echo "* cap did not trim to 32 UIDs (got $COUNT)"
	exit 1
fi
if ! echo "$INDEX" | grep -q 'primary-survives@example.org'; then
	echo "* the primary UID was evicted by the FIFO cap"
	exit 1
fi

exit 0
