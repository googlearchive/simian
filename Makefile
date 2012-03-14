#
# Copyright 2011 Google Inc. All Rights Reserved.
#

OSX_VERSION=$(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1-2)
SWIG=$(shell type -p swig 2>/dev/null)
SIMIAN_VERSION=2.0
SIMIAN=simian-${SIMIAN_VERSION}
SDIST_TAR=dist/simian-${SIMIAN_VERSION}.tar
SDIST=${SDIST_TAR}.gz
MUNKI_VERSION=0.8.2.1430.0
MUNKI=munkitools-${MUNKI_VERSION}
MUNKIFILE=${MUNKI}.mpkg.dmg
PYTHON_VERSION=2.5
PYTHON=$(shell type -p python${PYTHON_VERSION})
TS=$(shell date '+%s')
# This is the version that opensource.apple.com offers
SWIG_VERSION=1.3.40
SWIG_URL=http://downloads.sourceforge.net/project/swig/swig/swig-${SWIG_VERSION}/swig-${SWIG_VERSION}.tar.gz?r=&ts=${TS}

os_check:
	@if [ -z "${OSX_VERSION}" ]; then echo Must run on OS X ; exit 1 ; fi

python_check:
	@if [ ! -x "${PYTHON}" ]; then echo Cannot find ${PYTHON} ; exit 1 ; fi

swig_check:
	@if [ -z "${SWIG}" -o ! -x "${SWIG}" ]; then \
	echo swig must be installed. make swig to do this automatically. ; \
	exit 1 ; \
	fi

swig.tgz:
	curl -L -o swig.tgz "${SWIG_URL}"

swig: os_check swig.tgz
	rm -rf tmpswig
	mkdir -p tmpswig
	tar -zxf swig.tgz -C tmpswig
	cd tmpswig/swig-${SWIG_VERSION} ; \
	./configure --prefix=/usr/local ; \
	make ; \
	echo Type your password to exec sudo make install. ; \
	sudo make install
	rm -rf tmpswig
	@echo Success building and installing swig.

virtualenv: python_check
	${PYTHON} -c 'import virtualenv' || \
	sudo easy_install-${PYTHON_VERSION} -U virtualenv

VE: virtualenv python_check
	${PYTHON} $(shell type -p virtualenv) --no-site-packages VE

test: swig_check VE
	VE/bin/python src/simian/util/gen_settings.py -t client -o src/simian/settings.py etc/simian/{common,for_tests,client}.cfg
	env SIMIAN_CONFIG_PATH="${PWD}/etc/simian/" VE/bin/python setup.py google_test

build: swig_check VE
	VE/bin/python setup.py build

install: swig_check client_config build
	VE/bin/python setup.py install
	mkdir -p /etc/simian/ && cp -Rf etc/simian /etc && chmod 644 /etc/simian/*.cfg

clean_contents:
	rm -rf contents.tar contents.tar.gz tmpcontents

clean_pkgs:
	rm -rf tmppkgs

clean_sdist:
	rm -rf ${SDIST} ${SDIST_TAR}

clean: clean_contents clean_pkgs clean_sdist
	rm -rf ${SIMIAN}.dmg ${SIMIAN}-${MUNKI}.dmg dist/* build/* VE *.egg

${SDIST}: VE clean_sdist client_config
	VE/bin/python setup.py sdist --formats=tar
	gzip ${SDIST_TAR}

server_config: VE
	src/simian/util/create_gae_bundle.sh $(PWD)
	VE/bin/python src/simian/util/gen_settings.py -t server -o gae_bundle/simian/settings.py etc/simian/{common,server}.cfg
	sed -i "" "s/^application:.*/application: `PYTHONPATH=. python src/simian/util/appid_generator.py`/" gae_bundle/app.yaml
	src/simian/util/link_module.sh PyYAML
	src/simian/util/link_module.sh pytz
	src/simian/util/link_module.sh tlslite
	src/simian/util/link_module.sh pyasn1
	src/simian/util/link_module.sh icalendar
	VE/bin/python src/simian/util/compile_js.py src/simian/mac/admin/js/main.js gae_bundle/simian/mac/admin/js/simian.js
	
client_config: VE
	VE/bin/python src/simian/util/gen_settings.py -t client -o src/simian/settings.py etc/simian/{common,client}.cfg

${MUNKIFILE}:
	curl -o $@ http://munki.googlecode.com/files/$@
	
add_munkicontents: os_check ${MUNKIFILE}
	mkdir -p tmpcontents/
	# Munki moved to a mpkg, scrape out all the contents of each
	# mpkg in this shell multiliner.
	mnt=`hdiutil attach ${MUNKIFILE} | tail -1 | awk '{print $$3};'` ; \
	cd tmpcontents && \
	for pkg in $$mnt/${MUNKI}.mpkg/Contents/Packages/*.pkg; do \
	gzip -dc "$$pkg/Contents/Archive.pax.gz" | pax -r ; done ; \
	hdiutil detach "$$mnt"
	
contents.tar.gz: client_config
	mkdir -p tmpcontents/etc/simian/ssl/certs
	mkdir -p tmpcontents/etc/simian/ssl/private_keys
	chmod 750 tmpcontents/etc/simian/ssl/private_keys
	mkdir -p tmpcontents/usr/local/munki/
	mkdir -p tmpcontents/usr/local/bin
	# add entire config
	cp -R etc/simian tmpcontents/etc
	# sideline simian.cfg to avoid overwriting it on install
	mv tmpcontents/etc/simian/client.cfg tmpcontents/etc/simian/client.cfg+
	mv tmpcontents/etc/simian/common.cfg tmpcontents/etc/simian/common.cfg+
	# add munki integration binaries
	cp ./src/simian/munki/* tmpcontents/usr/local/munki
	# add simianfacter
	cp ./src/simian/util/simianfacter tmpcontents/usr/local/bin
	# build targz
	cd tmpcontents && tar -c --exclude .svn -f ../contents.tar .
	gzip contents.tar
	
${SIMIAN}.dmg: os_check ${SDIST} clean_contents contents.tar.gz
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-R M2Crypto-*.egg \
	-R PyYAML-*.egg \
	-R WebOb-*.egg \
	-R google_apputils-*.egg \
	-R icalendar-*.egg \
	-R pyasn1-*.egg \
	-R python_dateutil-*.egg \
	-R python_gflags-*.egg \
	-R pytz-*.egg \
	-R tlslite-*.egg \
	-r ${SDIST} \
	-s postflight

${SIMIAN}.pkg: os_check ${SDIST} clean_contents contents.tar.gz
	rm -rf tmppkgs/$@
	mkdir -p tmppkgs
	./tgz2dmg.sh contents.tar.gz tmppkgs/$@ \
	-pkgonly \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-R M2Crypto-*.egg \
	-R PyYAML-*.egg \
	-R WebOb-*.egg \
	-R google_apputils-*.egg \
	-R icalendar-*.egg \
	-R pyasn1-*.egg \
	-R python_dateutil-*.egg \
	-R python_gflags-*.egg \
	-R pytz-*.egg \
	-R tlslite-*.egg \
	-r ${SDIST} \
	-s postflight

${SIMIAN}-and-${MUNKI}.pkg: os_check ${SDIST} clean_contents add_munkicontents contents.tar.gz
	rm -rf tmppkgs/$@
	mkdir -p tmppkgs
	./tgz2dmg.sh contents.tar.gz tmppkgs/$@ \
	-pkgonly \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-R M2Crypto-*.egg \
	-R PyYAML-*.egg \
	-R WebOb-*.egg \
	-R google_apputils-*.egg \
	-R icalendar-*.egg \
	-R pyasn1-*.egg \
	-R python_dateutil-*.egg \
	-R python_gflags-*.egg \
	-R pytz-*.egg \
	-R tlslite-*.egg \
	-r ${SDIST} \
	-s postflight

${SIMIAN}-and-${MUNKI}.dmg: os_check ${SDIST} clean_contents add_munkicontents contents.tar.gz
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-R M2Crypto-*.egg \
	-R PyYAML-*.egg \
	-R WebOb-*.egg \
	-R google_apputils-*.egg \
	-R icalendar-*.egg \
	-R pyasn1-*.egg \
	-R python_dateutil-*.egg \
	-R python_gflags-*.egg \
	-R pytz-*.egg \
	-R tlslite-*.egg \
	-r ${SDIST} \
	-s postflight

simian-pkg: ${SIMIAN}.pkg

pkg: ${SIMIAN}-and-${MUNKI}.pkg

dmg: ${SIMIAN}-and-${MUNKI}.dmg

release: server_config
	appcfg.py update gae_bundle/
