def_dir=/usr/local
build_part="all"

if [ ! -z $1 ]; then
    build_part=$1
fi

if [ ! -z $2 ]; then
    def_dir=$2
fi

echo "install directory:"$def_dir

if [ "$build_part" = "all" ] || [ "$build_part" = "reconf" ]; then
aclocal
libtoolize
autoconf
autoheader
automake --add-missing
./configure --prefix=$def_dir
fi

if [ "$build_part" = "all" ] || [ "$build_part" = "reconf" ] || [ "$build_part" = "src" ]; then
make -C src
fi

