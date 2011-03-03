#
# Copyright 2011 Google Inc. All Rights Reserved.
#

ARCH=i386
OSX_VERSION=$(shell sw_vers -productVersion | cut -d. -f1-2)
SIMIAN_VERSION=1.0.1
SIMIAN=simian-${SIMIAN_VERSION}
SDIST_TAR=dist/simian-${SIMIAN_VERSION}.tar
SDIST=${SDIST_TAR}.gz
MUNKI_VERSION=0.7.0.1047.0
MUNKI=munkitools-${MUNKI_VERSION}
MUNKIFILE=${MUNKI}.pkg.dmg
M2CRYPTO25=M2Crypto-0.21.1-py2.5-macosx-10.5-i386.egg
M2CRYPTO26=M2Crypto-0.21.1-py2.6-macosx-10.6-universal.egg

test:
	python setup.py google_test

build:
	python setup.py build

install: build
	python setup.py install
	mkdir -p /etc/simian/ && cp -Rf etc/simian /etc && chmod 644 /etc/simian/simian.cfg

clean: clean_contents clean_sdist clean_pkgs
	rm -rf ${SIMIAN}.dmg ${SIMIAN}-${MUNKI}.dmg dist/* build/*

clean_sdist:
	rm -rf ${SDIST} ${SDIST_TAR}

clean_contents:
	rm -rf contents.tar contents.tar.gz tmpcontents

clean_pkgs:
	rm -rf tmppkgs

${SDIST}: clean_sdist config
	python setup.py sdist --formats=tar
	gzip ${SDIST_TAR}

config:
	python src/simian/util/gen_settings.py --config-dir etc/simian/ --output gae_bundle/simian/settings.py
	sed -i "" "s/^application:.*/application: `PYTHONPATH=. python src/simian/util/appid_generator.py`/" gae_bundle/app.yaml
	src/simian/util/link_module.sh tlslite
	src/simian/util/link_module.sh pyasn1

${MUNKIFILE}:
	curl -o $@ http://munki.googlecode.com/files/$@
	
add_munkicontents: ${MUNKIFILE}
	mkdir -p tmpcontents/
	mnt=`hdiutil attach ${MUNKIFILE} | tail -1 | awk '{print $$3};'` ; \
	cd tmpcontents && gzip -dc "$$mnt/${MUNKI}.pkg/Contents/Archive.pax.gz" | pax -r ; \
	hdiutil detach "$$mnt"
	
contents.tar.gz: config
	mkdir -p tmpcontents/etc/simian/ssl/certs
	mkdir -p tmpcontents/etc/simian/ssl/private_keys
	chmod 750 tmpcontents/etc/simian/ssl/private_keys
	mkdir -p tmpcontents/usr/local/munki/
	mkdir -p tmpcontents/usr/local/bin
	# add entire config
	cp -R etc/simian tmpcontents/etc
	# sideline simian.cfg to avoid overwriting it on install
	mv tmpcontents/etc/simian/simian.cfg tmpcontents/etc/simian/simian.cfg+
	# add munki integration binaries
	cp ./src/simian/munki/* tmpcontents/usr/local/munki
	# add simianfacter
	cp ./src/simian/util/simianfacter tmpcontents/usr/local/bin
	# build targz
	cd tmpcontents && tar -cf ../contents.tar .
	gzip contents.tar
	
${M2CRYPTO25}:
	curl -o $@ http://chandlerproject.org/pub/Projects/MeTooCrypto/$@

${M2CRYPTO26}:
	curl -o $@ http://chandlerproject.org/pub/Projects/MeTooCrypto/$@

${SIMIAN}.dmg: ${M2CRYPTO25} ${M2CRYPTO26} ${SDIST} clean_contents contents.tar.gz
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-r ${M2CRYPTO25} \
	-r ${M2CRYPTO26} \
	-r ${SDIST} \
	-s postflight

${SIMIAN}.pkg: ${M2CRYPTO25} ${M2CRYPTO26} ${SDIST} clean_contents contents.tar.gz
	rm -rf tmppkgs/$@
	mkdir -p tmppkgs
	./tgz2dmg.sh contents.tar.gz tmppkgs/$@ \
	-pkgonly \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-r ${M2CRYPTO25} \
	-r ${M2CRYPTO26} \
	-r ${SDIST} \
	-s postflight

${SIMIAN}-and-${MUNKI}.dmg: ${M2CRYPTO25} ${M2CRYPTO26} ${SDIST} clean_contents add_munkicontents contents.tar.gz
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-r ${M2CRYPTO25} \
	-r ${M2CRYPTO26} \
	-r ${SDIST} \
	-s postflight

pkg: ${SIMIAN}.pkg

dmg: ${SIMIAN}-and-${MUNKI}.dmg

release: config
	appcfg.py update gae_bundle/
