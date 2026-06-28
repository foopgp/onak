#!/bin/sh
# Check that max_sigs_per_uid trims the sig list when a key is added.
# noodles.key carries 134 signature packets distributed over a single
# UID and a couple of subkeys; capping at 4 must leave significantly
# fewer than 134 in the stored record.

set -e

cd ${WORKDIR}
cp $1 cap-sigs.ini
echo max_sigs_per_uid=4 >> cap-sigs.ini
${BUILDDIR}/onak -b -c cap-sigs.ini add < ${TESTSDIR}/../keys/noodles.key
COUNT=$(${BUILDDIR}/onak -c cap-sigs.ini vindex 0x94FA372B2DA8B985 2>/dev/null | \
	grep -c '^sig' || true)
rm cap-sigs.ini
# vindex prints one line per sig; with 4 kept on the UID plus 2 subkey
# binding sigs we expect well under 134 and at least 4.
if [ "$COUNT" -ge 134 ] || [ "$COUNT" -lt 4 ]; then
	echo "* max_sigs_per_uid did not trim the sig list (got $COUNT)"
	exit 1
fi

exit 0
