#!/bin/sh
# A certification revocation (0x30) takes back the vouching of whoever issued
# it, and nothing more. Only the key's own hand can withdraw one of its UIDs,
# so a third party's revocation must never hide an identity its owner still
# asserts.
#
# The test key carries three UIDs: work@ (certified by another key, which then
# revoked its own certification), anne@ (plainly certified) and old@ (revoked
# by the key itself).

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/thirdpartysigrev.key

# The revoked-UID policy lives in the templated HTML rendering, so drive it
# through the lookup CGI with the foopgp templates.
sed -e "s;^\[main\];[main]\ntemplate_dir=${TESTSDIR}/../templates/foopgp;" \
	$1 > ${WORKDIR}/onak.ini
trap 'rm -f ${WORKDIR}/onak.ini' exit

# op=index: what the holder asserts today. work@ and anne@ stay, old@ goes.
XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
	"op=index&search=0x9BB09E2FA0253A1B" 2>/dev/null > index.out

if ! grep -q 'class="fp-uid">Anne (work)' index.out; then
	echo "* a certification revoked by its own signer hid the UID"
	exit 1
fi
if ! grep -q 'class="fp-uid">Anne &lt;anne@' index.out; then
	echo "* the plainly certified UID went missing"
	exit 1
fi
if grep -q 'class="fp-uid">Anne (old)' index.out; then
	echo "* a UID revoked by the key itself was listed"
	exit 1
fi

# op=vindex: the full history. Every UID shows, and exactly one of them --
# the self-revoked old@ -- wears the revoked badge.
XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
	"op=vindex&search=0x9BB09E2FA0253A1B" 2>/dev/null > vindex.out

for uid in 'Anne (work)' 'Anne &lt;anne@' 'Anne (old)'; do
	if ! grep -q "class=\"fp-uid\">${uid}" vindex.out; then
		echo "* op=vindex dropped ${uid}"
		exit 1
	fi
done
if [ "$(grep -o 'fp-uid-block rev' vindex.out | wc -l)" != "1" ]; then
	echo "* op=vindex did not mark exactly one UID as revoked"
	exit 1
fi
if ! grep -q 'fp-uid-block rev"><span class="fp-uid">Anne (old)' vindex.out; then
	echo "* op=vindex marked the wrong UID as revoked"
	exit 1
fi

exit 0
