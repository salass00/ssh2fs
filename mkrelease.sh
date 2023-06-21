#!/bin/sh
#
# Script for generating a release archive (OS3/AROS only).
#

HOST="${1:-m68k-amigaos}"
FORMAT="${2:-lha}"

if [ "$HOST" = "m68k-amigaos" ]; then
  make -f makefile.os3 all
else
  CPU=`echo "${HOST}" | cut -d'-' -f1`
  make -f makefile.aros CPU=${CPU} all
fi;

LIBSSH2='libssh2-1.10.0'
DESTDIR='tmp'

rm -rf ${DESTDIR}
mkdir -p ${DESTDIR}/ssh2fs/L

if [ "$HOST" = "m68k-amigaos" ]; then
  cp -p Install-OS3 ${DESTDIR}/ssh2fs/Install
#  cp -p README-OS3 ${DESTDIR}/ssh2fs/README
  cp -p bin/ssh2-handler.000 ${DESTDIR}/ssh2fs/L
  cp -p bin/ssh2-handler.020 ${DESTDIR}/ssh2fs/L
else
  cp -p Install-AROS ${DESTDIR}/ssh2fs/Install
#  cp -p README-AROS ${DESTDIR}/ssh2fs/README
  cp -p bin/ssh2-handler.${CPU} ${DESTDIR}/ssh2fs/L/ssh2-handler
fi;
cp -p LICENSE ${DESTDIR}/ssh2fs
cp -p ${LIBSSH2}/COPYING ${DESTDIR}/ssh2fs/COPYING-libssh2
#cp -p releasenotes ${DESTDIR}/ssh2fs

cp -p icons-os3/def_drawer.info ${DESTDIR}/ssh2fs.info
cp -p icons-os3/def_install.info ${DESTDIR}/ssh2fs/Install.info
#cp -p icons-os3/def_doc.info ${DESTDIR}/ssh2fs/README.info
cp -p icons-os3/def_doc.info ${DESTDIR}/ssh2fs/LICENSE.info
cp -p icons-os3/def_doc.info ${DESTDIR}/ssh2fs/COPYING-libssh2.info
#cp -p icons-os3/def_doc.info ${DESTDIR}/ssh2fs/releasenotes.info

case "${FORMAT}" in
  "7z")
    rm -f ssh2fs.${HOST}.7z
    7za u ssh2fs.${HOST}.7z ./${DESTDIR}/*
    echo "ssh2fs.${HOST}.7z created"
    ;;
  "iso")
    rm -f ssh2fs.${HOST}.iso
    PREVDIR=`pwd`
    cd ${DESTDIR} && mkisofs -R -o ../ssh2fs.${HOST}.iso -V SSH2FS .
    cd ${PREVDIR}
    echo "ssh2fs.${HOST}.iso created"
    ;;
  "lha")
    rm -f ssh2fs.${HOST}.lha
    PREVDIR=`pwd`
    cd ${DESTDIR} && lha ao5 ../ssh2fs.${HOST}.lha *
    cd ${PREVDIR}
    echo "ssh2fs.${HOST}.lha created"
    ;;
esac

rm -rf ${DESTDIR}

