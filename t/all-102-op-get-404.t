#!/bin/sh
# op=get: a key that is there comes with its download headers, as headers; a
# key that is not answers 404, as the HKP draft asks, and not a 200 with a
# sentence that clients took for a certificate. Both with and without
# options=mr, which used to close the header block before either was written.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
ln -s $1 ${WORKDIR}/onak.ini
trap 'rm -f ${WORKDIR}/onak.ini' exit

for mr in "" "&options=mr"; do
	# Found: the first header is the key's own type, and the body starts
	# with the armor -- nothing of the headers spilled into it.
	XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
		"op=get&search=0x94FA372B2DA8B985${mr}" 2>/dev/null > get.out
	if ! sed '/^$/q' get.out | grep -q '^Content-Type: application/pgp-keys'; then
		echo "* op=get${mr}: no application/pgp-keys header"
		exit 1
	fi
	if [ "$(sed '1,/^$/d' get.out | head -n 1)" != \
			"-----BEGIN PGP PUBLIC KEY BLOCK-----" ]; then
		echo "* op=get${mr}: the body does not start with the armor"
		exit 1
	fi

	# Missing: 404, in the headers.
	XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
		"op=get&search=0x0000000000000000${mr}" 2>/dev/null > miss.out
	if ! sed '/^$/q' miss.out | grep -q '^Status: 404'; then
		echo "* op=get${mr}: a missing key did not answer 404"
		exit 1
	fi
done

exit 0
