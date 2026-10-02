#!/bin/sh
# A short key ID of 8 hex digits is not answered: 32 bits collide by design,
# and the HKP draft forbids it. A 0x search that is neither a long key ID nor
# a fingerprint gets a 400 rather than being read as text.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
ln -s $1 ${WORKDIR}/onak.ini
trap 'rm -f ${WORKDIR}/onak.ini' exit

lookup () {
	XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup "$1" 2>/dev/null
}
head_of () {
	sed '/^$/q' "$1"
}

for q in "op=get&search=0x2DA8B985" \
		"op=get&options=mr&search=0x2DA8B985" \
		"op=index&search=0x2DA8B985" \
		"op=get&search=0x94FA372B2DA8B985&search=0x2DA8B985" \
		"op=get&search=0xZZZZ372B2DA8B985ZZZZ372B2DA8B985ZZZZ372B"; do
	lookup "${q}" > short.out
	if ! head_of short.out | grep -q '^Status: 400'; then
		echo "* ${q} was not refused with 400"
		exit 1
	fi
done

# The long key ID still answers.
lookup "op=get&search=0x94FA372B2DA8B985" > long.out
if head_of long.out | grep -q '^Status:' || \
		! grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' long.out; then
	echo "* a long key ID did not answer its key"
	exit 1
fi

exit 0
