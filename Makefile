#
# Copyright 2011 Google Inc. All Rights Reserved.
#

OSX_VERSION=$(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1-2)
SWIG=$(shell type -p swig 2>/dev/null)
SIMIAN_VERSION=2.2.2
SIMIAN=simian-${SIMIAN_VERSION}
SDIST_TAR=dist/simian-${SIMIAN_VERSION}.tar
SDIST=${SDIST_TAR}.gz
MUNKI_VERSION=1.0.0.1867.0
MUNKI=munkitools-${MUNKI_VERSION}
MUNKIFILE=${MUNKI}.dmg
PYTHON_VERSION=2.6
PYTHON=$(shell type -p python${PYTHON_VERSION})
TS=$(shell date '+%s')
# This is the version that opensource.apple.com offers
SWIG_VERSION=1.3.40
SWIG_URL=http://downloads.sourceforge.net/project/swig/swig/swig-${SWIG_VERSION}/swig-${SWIG_VERSION}.tar.gz?r=&ts=${TS}
SVN_VERSION=$(shell svnversion | tr '[:upper:]' '[:lower:]')
SVN_REGEX=^[0-9]+[a-z]*$
BUILD_VERSION=$(shell if [[ '${SVN_VERSION}' =~ ${SVN_REGEX} ]]; then echo ${SVN_VERSION}; else echo ${SIMIAN_VERSION} | tr '.' '-'; fi)

os_check:
	@if [ -z "${OSX_VERSION}" ]; then echo Must run on OS X ; exit 1 ; fi

python_check:
	@if [ ! -x "${PYTHON}" ]; then echo Cannot find ${PYTHON} ; exit 1 ; fi

swig_check:
	@if [ -z "${SWIG}" -o ! -x "${SWIG}" ]; then \
	echo swig must be installed. type: ; \
	echo ; \
	echo "       make swig" ; \
	echo ; \
	echo and it will be done automatically for you. ; \
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
	sudo easy_install-${PYTHON_VERSION} -U virtualenv==1.10.1

VE: virtualenv python_check
	[ -d VE ] || \
	${PYTHON} $(shell type -p virtualenv) --no-site-packages VE

test: swig_check VE
	[ -f test ] || \
	env SIMIAN_CONFIG_PATH="${PWD}/etc/simian/" \
	VE/bin/python setup.py google_test && touch test && \
	echo ALL TESTS COMPLETED SUCCESSFULLY

settings_check: test
	VE/bin/python \
	src/simian/util/validate_settings.py etc/simian/ \
	src/ ./pyasn1*.egg ./tlslite*.egg

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

clean_test:
	rm -f test

clean_ve:
	rm -rf VE

clean: clean_contents clean_pkgs clean_sdist clean_test clean_ve
	rm -rf ${SIMIAN}.dmg ${SIMIAN}-${MUNKI}.dmg dist/* build/* *.egg install_name_tool

${SDIST}: VE clean_sdist client_config
	VE/bin/python setup.py sdist --formats=tar
	gzip ${SDIST_TAR}

server_config:
	src/simian/util/create_gae_bundle.sh $(PWD)
	sed -i "" "s/^application:.*/application: `PYTHONPATH=. python src/simian/util/appid_generator.py`/" gae_bundle/app.yaml
	src/simian/util/link_module.sh PyYAML
	src/simian/util/link_module.sh pytz
	src/simian/util/link_module.sh tlslite
	src/simian/util/link_module.sh pyasn1
	src/simian/util/link_module.sh icalendar
	VE/bin/python src/simian/util/compile_js.py gae_bundle/simian/mac/admin/js/simian.js

client_config: settings_check

${MUNKIFILE}:
	curl -o $@ https://munkibuilds.org/${MUNKI_VERSION}/$@
	hdiutil verify "$@" || (rm -f "$@" ; exit 1)

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
	mv tmpcontents/etc/simian/settings.cfg tmpcontents/etc/simian/settings.cfg+
	# add munki integration binaries
	cp ./src/simian/munki/* tmpcontents/usr/local/munki
	# add simianfacter
	cp ./src/simian/util/simianfacter tmpcontents/usr/local/bin
	# build tar
	tar -v -c --exclude '*/.*' -f contents.tar -C tmpcontents .
	# build gz
	gzip -f contents.tar
	
install_name_tool:
	cp /usr/bin/install_name_tool .

m2crypto:
	for egg in \
	M2Crypto-0.22.3-py2.6-macosx-10.7-intel.egg \
	M2Crypto-0.22.3-py2.6-macosx-10.8-x86_64.egg \
	M2Crypto-0.22.3-py2.6-macosx-10.9-x86_64.egg ; do \
	[[ -f "simian_$${egg}" ]] || curl -o "simian_$${egg}" "https://storage.googleapis.com/m2crypto_eggs/$${egg}" ; \
	done		
	
vep: install_name_tool

${SIMIAN}.dmg: os_check ${SDIST} clean_contents contents.tar.gz m2crypto vep
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-vep install_name_tool \
	-R simian_M2Crypto-*.egg \
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
	-s postflight \
	-s roots.pem

${SIMIAN}.pkg: os_check ${SDIST} clean_contents contents.tar.gz m2crypto vep
	rm -rf tmppkgs/$@
	mkdir -p tmppkgs
	./tgz2dmg.sh contents.tar.gz tmppkgs/$@ \
	-pkgonly \
	-id com.google.code.simian \
	-version ${SIMIAN_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-vep install_name_tool \
	-R simian_M2Crypto-*.egg \
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
	-s postflight \
	-s roots.pem

${SIMIAN}-and-${MUNKI}.pkg: os_check ${SDIST} clean_contents m2crypto add_munkicontents contents.tar.gz vep
	rm -rf tmppkgs/$@
	mkdir -p tmppkgs
	./tgz2dmg.sh contents.tar.gz tmppkgs/$@ \
	-pkgonly \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-vep install_name_tool \
	-R simian_M2Crypto-*.egg \
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
	-s postflight \
	-s roots.pem

${SIMIAN}-and-${MUNKI}.dmg: os_check ${SDIST} clean_contents m2crypto add_munkicontents contents.tar.gz vep
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-vep install_name_tool \
	-R simian_M2Crypto-*.egg \
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
	-s postflight \
	-s roots.pem

simian-pkg: ${SIMIAN}.pkg

pkg: ${SIMIAN}-and-${MUNKI}.pkg

dmg: ${SIMIAN}-and-${MUNKI}.dmg

release: server_config
	appcfg.py --version=${BUILD_VERSION} update gae_bundle/ 
	appcfg.py --version=${BUILD_VERSION} set_default_version gae_bundle/ 
