#!/bin/sh
set -e

if [ "$1" == "" ]; then
    echo "Missing rootfs argument"
    exit 1
fi

prepare() {
    rootfs="$1"
    device=$(findmnt -n -o SOURCE --target "${rootfs}")

    echo "[+] running test on: ${rootfs}"
    echo "[+] rootfs device: ${device}"
}

tests() {
    set -x

    echo "Hello World" > ${rootfs}/hello
    sum=$(md5sum ${rootfs}/hello | awk '{ print $1 }')

    [[ "$sum" == "e59ff97941044f85df5297e1c302d260" ]] || echo "Test failed"


    stat ${rootfs}/hello
    rm -f ${rootfs}/hello
    rm ${rootfs}/hello || true

    touch ${rootfs}/newfile
    chmod 555 ${rootfs}/newfile
    chown nobody ${rootfs}/newfile
    chmod 664 ${rootfs}/newfile
    echo > ${rootfs}/newfile
    echo Yeah >> ${rootfs}/newfile
    ln -s ${rootfs}/newfile ${rootfs}/newsymlink
    ln ${rootfs}/newfile ${rootfs}/newlink

    readlink ${rootfs}/newsymlink
    mv ${rootfs}/newfile ${rootfs}/renamedfile

    mkdir ${rootfs}/newdir
    rm -rf ${rootfs}/newdir

    mkdir -p ${rootfs}/newdir/subdir/hello
    mv ${rootfs}/newlink ${rootfs}/newdir/subdir/hello/newname

    sum1=$(md5sum ${rootfs}/newdir/subdir/hello/newname | awk '{ print $1 }')
    sum2=$(md5sum ${rootfs}/renamedfile | awk '{ print $1 }')

    [[ "$sum1" == "$sum2" ]] || echo "Test failed"

    rm -f ${rootfs}/renamedfile
    rm -f ${rootfs}/newsymlink

    cat ${rootfs}/newdir/subdir/hello/newname

    rm -rf ${rootfs}/newdir
}

main() {
    echo "[+] initializing 0-db-fs tests suite"

    prepare $@
    tests
}

main $@
