#
# Copyright 2011 Google Inc. All Rights Reserved.
#

ARCH=i386
OSX_VERSION=$(shell sw_vers -productVersion | cut -d. -f1-2)
SIMIAN_VERSION=0.5
SIMIAN=simian-${SIMIAN_VERSION}
SDIST_TAR=dist/simian-${SIMIAN_VERSION}.tar
SDIST=${SDIST_TAR}.gz
MUNKI_VERSION=0.7.0.1004.0
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

clean: clean_contents clean_sdist
	rm -rf ${SIMIAN}.dmg ${SIMIAN}-${MUNKI}.dmg dist/* build/*

clean_sdist:
	rm -rf ${SDIST} ${SDIST_TAR}

${SDIST}: clean_sdist config
	python setup.py sdist --formats=tar

	# add data files missed by sdist
	gnutar -rf ${SDIST_TAR} ../simian-0.5/src/simian/client/gae_client.zip

	# remove server code which is not necessary on client.
	# note although these files are gone, entries for them remain in the
	# in src/simian.egg-info/SOURCES.txt manifest
	gnutar -f dist/simian-0.5.tar --wildcards --delete \
	simian-${SIMIAN_VERSION}/src/simian/mac/admin/ \
	simian-${SIMIAN_VERSION}/src/simian/mac/appengine_config.py \
	simian-${SIMIAN_VERSION}/src/simian/mac/common/ \
	simian-${SIMIAN_VERSION}/src/simian/mac/cron/ \
	simian-${SIMIAN_VERSION}/src/simian/mac/deferred_wrapper.py \
	simian-${SIMIAN_VERSION}/src/simian/mac/main.py \
	simian-${SIMIAN_VERSION}/src/simian/mac/models.py \
	simian-${SIMIAN_VERSION}/src/simian/mac/munki/common.py \
	simian-${SIMIAN_VERSION}/src/simian/mac/munki/handlers \
	simian-${SIMIAN_VERSION}/src/simian/mac/urls.py
	gzip ${SDIST_TAR}

config:
	python src/simian/util/gen_settings.py --config-dir etc/simian/ --output gae_bundle/simian/settings.py
	sed -i "" "s/^application:.*/application: `PYTHONPATH=. python src/simian/util/appid_generator.py`/" gae_bundle/app.yaml
	src/simian/util/link_module.sh tlslite
	src/simian/util/link_module.sh pyasn1

${MUNKIFILE}:
	curl -o $@ http://munki.googlecode.com/files/$@

clean_contents:
	rm -rf contents.tar contents.tar.gz tmpcontents

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
	-r ${M2CRYPTO25} \
	-r ${M2CRYPTO26} \
	-r ${SDIST} \
	-s postflight

${SIMIAN}-${MUNKI}.dmg: ${M2CRYPTO25} ${M2CRYPTO26} ${SDIST} clean_contents add_munkicontents contents.tar.gz
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-r ${M2CRYPTO25} \
	-r ${M2CRYPTO26} \
	-r ${SDIST} \
	-s postflight

dmg: ${SIMIAN}.dmg

munkidmg: ${SIMIAN}-${MUNKI}.dmg

release: config
	server=`python -c "from gae_bundle.simian import settings ; print '%s.%s' % (settings.SUBDOMAIN, settings.DOMAIN)"` ; \
	appcfg.py update --server=$$server gae_bundle/
