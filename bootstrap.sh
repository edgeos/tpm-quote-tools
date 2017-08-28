set -x
echo "***ACLOCAL***"
aclocal || exit 1
echo "***AUTOHEADER***"
autoheader || exit 1
echo "***AUTOCONF***"
autoconf || exit 1
echo "***AUTOMAKE***"
automake --add-missing -c --foreign || exit 1

