#!/bin/sh
# op=photo: a valid idx returns the JPEG with no HTML footer glued on; an
# out-of-range idx returns a 404 rather than the page footer served as a
# broken image/jpeg.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/photo.key
ln -s $1 ${WORKDIR}/onak.ini
trap 'rm -f ${WORKDIR}/onak.ini' exit

# idx=0 : the photo. Body (after the CGI headers) must start with the JPEG SOI
# marker (ff d8) and the whole response must not carry the HTML footer.
XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
	"op=photo&search=0x7105142E354CA35A&idx=0" 2>/dev/null > photo0.out
if [ "$(sed '1,/^$/d' photo0.out | head -c 2 | od -An -tx1 | tr -d ' ')" != "ffd8" ]; then
	echo "* op=photo idx=0 did not return a JPEG"
	exit 1
fi
if grep -q -- '<hr>' photo0.out; then
	echo "* op=photo idx=0 leaked the HTML footer into the image"
	exit 1
fi

# idx=1 : out of range → 404 (no image body).
XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup \
	"op=photo&search=0x7105142E354CA35A&idx=1" 2>/dev/null > photo1.out
if ! grep -q '404' photo1.out; then
	echo "* op=photo out-of-range idx did not return a 404"
	exit 1
fi

exit 0
