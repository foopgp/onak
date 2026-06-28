#!/bin/sh
# Smoke-test the Mustache-style template engine via the standalone
# exerciser tmpl-render. The engine's job here is to take the
# bundled sample template (which mimics a single-key HTML
# op=index response) and produce the expected HTML.

set -e

cd ${WORKDIR}
OUT=$(${BUILDDIR}/tmpl-render ${TESTSDIR}/../templates/vanilla/sample.html)
case "$OUT" in
    *"<pre>"*) ;;
    *) echo "* tmpl-render: missing <pre> wrapper"; exit 1 ;;
esac
case "$OUT" in
    *'<a href="lookup?op=get&search=0x0E3A94C3E83002DA">0x0E3A94C3E83002DA</a>'*) ;;
    *) echo "* tmpl-render: missing key-id anchor"; exit 1 ;;
esac
case "$OUT" in
    *"Other UID with &lt;markup&gt;"*) ;;
    *) echo "* tmpl-render: HTML escaping broken in section"; exit 1 ;;
esac

exit 0
