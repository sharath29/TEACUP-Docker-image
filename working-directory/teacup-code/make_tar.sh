#!/bin/sh
# Copyright (c) 2013-2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (sebastian.zander@gmx.de)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# generate a tar file for the source code
# usage: make_tar.sh
#
# $Id$

if [ ! -e VERSION ] ; then
	echo "Error: this script needs to be executed in the source directory"
	exit 1
fi

VERSION=`cat VERSION | head -1`
NAME=teacup-${VERSION}.tar.gz

echo "Generating $NAME"
mkdir -p teacup-${VERSION} 
cp -rd --preserve=all * teacup-${VERSION}/ 
# add SVN info to version file
cat teacup-${VERSION}/VERSION | head -1 > teacup-${VERSION}/VERSION.tmp && mv teacup-${VERSION}/VERSION.tmp teacup-${VERSION}/VERSION
./get_hg_info.sh >> teacup-${VERSION}/VERSION
# substitute Id tags
hg kwexpand || { echo "MUST commit changes first" ; rm -rf teacup-${VERSION}/ ; exit 1 ; }
# tar everything
tar -H gnu -cvzf $NAME --hard-dereference \
        teacup-${VERSION}/*.py teacup-${VERSION}/INSTALL teacup-${VERSION}/TODO teacup-${VERSION}/README \
        teacup-${VERSION}/AUTHORS teacup-${VERSION}/COPYING teacup-${VERSION}/VERSION teacup-${VERSION}/ChangeLog \
        teacup-${VERSION}/*.in teacup-${VERSION}/*.R teacup-${VERSION}/*.sh teacup-${VERSION}/tools \
        teacup-${VERSION}/example_configs teacup-${VERSION}/ACKNOWLEDGMENTS 
rm -rf teacup-${VERSION}/
