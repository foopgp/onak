#!/bin/sh
# op=get with several searches answers them all in one bundle, says so in
# X-HKP-Multi-Search on every get, and refuses text searches and more than
# the limit. op=index answers 404 when nothing matches, mr or not.

set -e

cd ${WORKDIR}
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/noodles.key
${BUILDDIR}/onak -b -c $1 add < ${TESTSDIR}/../keys/photo.key
ln -s $1 ${WORKDIR}/onak.ini
trap 'rm -f ${WORKDIR}/onak.ini' exit

NOODLES=0x94FA372B2DA8B985
PHOTO=0x7105142E354CA35A

lookup () {
	XDG_CONFIG_HOME=${WORKDIR} ${BUILDDIR}/cgi/lookup "$1" 2>/dev/null
}
head_of () {
	sed '/^$/q' "$1"
}

# A single get already announces the limit.
lookup "op=get&search=${NOODLES}" > one.out
if ! head_of one.out | grep -q '^X-HKP-Multi-Search: 100$'; then
	echo "* a single op=get did not announce X-HKP-Multi-Search"
	exit 1
fi

# Both keys, one of them twice, and one that is not there: a 200 bundle.
lookup "op=get&search=${NOODLES}&search=${PHOTO}&search=${NOODLES}&search=0x0000000000000001&options=mr" > many.out
if head_of many.out | grep -q '^Status:'; then
	echo "* a multi-search that found keys did not answer 200"
	exit 1
fi
if [ "$(sed '1,/^$/d' many.out | grep -c -- '-----BEGIN PGP PUBLIC KEY BLOCK-----')" != 1 ]; then
	echo "* a multi-search did not answer one armored bundle"
	exit 1
fi
# The bundle carries both keys: take them out, put the bundle back in, and
# both are there again.
${BUILDDIR}/onak -c $1 delete ${NOODLES} 2>/dev/null
${BUILDDIR}/onak -c $1 delete ${PHOTO} 2>/dev/null
sed '1,/^$/d' many.out | ${BUILDDIR}/onak -c $1 add 2>/dev/null
for key in ${NOODLES} ${PHOTO}; do
	if ! ${BUILDDIR}/onak -c $1 get ${key} 2>/dev/null | \
			grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
		echo "* the multi-search bundle did not carry ${key}"
		exit 1
	fi
done

# None found: 404.
lookup "op=get&search=0x0000000000000001&search=0x0000000000000002" > none.out
if ! head_of none.out | grep -q '^Status: 404'; then
	echo "* a multi-search that found nothing did not answer 404"
	exit 1
fi

# A text search among several: 400.
lookup "op=get&search=${NOODLES}&search=noodles" > text.out
if ! head_of text.out | grep -q '^Status: 400'; then
	echo "* a text search in a multi-search was not refused"
	exit 1
fi

# One more than the limit: 413.
query="op=get"
n=0
while [ $n -lt 101 ]; do
	query="${query}&search=${NOODLES}"
	n=$((n + 1))
done
lookup "${query}" > over.out
if ! head_of over.out | grep -q '^Status: 413'; then
	echo "* 101 searches were not refused"
	exit 1
fi

# op=index and op=vindex that match nothing: 404, mr or not.
for q in "op=index&search=nobody-here@example.invalid" \
		"op=index&options=mr&search=nobody-here@example.invalid" \
		"op=vindex&search=nobody-here@example.invalid"; do
	lookup "${q}" > idx.out
	if ! head_of idx.out | grep -q '^Status: 404'; then
		echo "* ${q} did not answer 404"
		exit 1
	fi
done
# And one that matches: no status, and the mr count.
lookup "op=index&options=mr&search=${NOODLES}" > idx.out
if head_of idx.out | grep -q '^Status:' || ! grep -q '^info:1:1$' idx.out; then
	echo "* op=index for a key that is there did not answer 200 info:1:1"
	exit 1
fi

exit 0
