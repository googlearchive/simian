#
# Copyright 2011 Google Inc. All Rights Reserved.
#

OSX_VERSION=$(shell sw_vers -productVersion 2>/dev/null | cut -d. -f1-2)
SIMIAN_VERSION=2.4
SIMIAN=simian-${SIMIAN_VERSION}
SDIST_TAR=dist/simian-${SIMIAN_VERSION}.tar
SDIST=${SDIST_TAR}.gz
MUNKI_VERSION=2.5.1.2630
MUNKI=munkitools-${MUNKI_VERSION}
MUNKIFILE=${MUNKI}.pkg
PYTHON_VERSION=2.7
PYTHON="/usr/bin/python${PYTHON_VERSION}"
TS=$(shell date '+%s')
BUILD_VERSION=$(shell (git rev-parse HEAD 2>/dev/null || echo ${SIMIAN_VERSION} | tr '.' '-') | cut -c1-12)

os_check:
	@if [ -z "${OSX_VERSION}" ]; then echo Must run on OS X ; exit 1 ; fi

python_check:
	@if [ ! -x "${PYTHON}" ]; then echo Cannot find ${PYTHON} ; exit 1 ; fi

virtualenv: python_check
	${PYTHON} -c 'import virtualenv; exit(virtualenv.__version__ != "13.1.2")' || \
	(sudo /usr/bin/easy_install-${PYTHON_VERSION} -U virtualenv==13.1.2 && \
	sudo /usr/bin/easy_install-${PYTHON_VERSION} -U setuptools==18.6.1)

VE: virtualenv python_check
	[ -d VE ] || \
	${PYTHON} $(shell type -p virtualenv) --no-site-packages VE

test: m2crypto VE
	[ -f test ] || \
	VE/bin/python VE/bin/easy_install-${PYTHON_VERSION} "${PWD}"/simian_M2Crypto-*-py${PYTHON_VERSION}-macosx-${OSX_VERSION}*.egg && \
	env SIMIAN_CONFIG_PATH="${PWD}/etc/simian/" \
	VE/bin/python setup.py google_test && touch test && \
	echo ALL TESTS COMPLETED SUCCESSFULLY

settings_check: test
	VE/bin/python \
	src/simian/util/validate_settings.py etc/simian/ \
	src/ ./.eggs/pyasn1*.egg ./.eggs/tlslite*.egg

build: VE
	VE/bin/python setup.py build

install: client_config build
	VE/bin/python setup.py install
	mkdir -p /etc/simian/ && cp -Rf etc/simian /etc && chmod 644 /etc/simian/*.cfg

clean_contents:
	rm -rf contents.tar contents.tar.gz tmpcontents swig.tgz

clean_pkgs:
	rm -rf tmppkgs

clean_sdist:
	rm -rf ${SDIST} ${SDIST_TAR}

clean_test:
	rm -f test

clean_ve:
	rm -rf VE

clean: clean_contents clean_pkgs clean_sdist clean_test clean_ve
	rm -rf ${SIMIAN}.dmg ${SIMIAN}-${MUNKI}.dmg dist/* build/* *.egg .eggs install_name_tool

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
	VE/bin/python src/simian/util/compile_js.py gae_bundle/simian/mac/admin/js/simian.js

client_config: settings_check

${MUNKIFILE}:
	curl -o $@ https://munkibuilds.org/${MUNKI_VERSION}/$@
	@xar -t -f "$@" > /dev/null || ( rm -f "$@" ; exit 1)

add_munkicontents: os_check ${MUNKIFILE}
	pkgutil --expand ${MUNKIFILE} tmpcontents/
	cd tmpcontents/ && \
	for pkg in *.pkg ; do \
	gzip -dc "$$pkg/Payload" | pax -r | rm -r $$pkg; done

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
	M2Crypto-0.22.3-py2.7-macosx-10.9-intel.egg \
	M2Crypto-0.22.3-py2.7-macosx-10.10-intel.egg \
	M2Crypto-0.22.3-py2.7-macosx-10.11-intel.egg \
	M2Crypto-0.22.3-py2.7-macosx-10.12-intel.egg ; do \
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
	-R simian_M2Crypto-*-10.9-*.egg \
	-R simian_M2Crypto-*-10.10-*.egg \
	-R simian_M2Crypto-*-10.11-*.egg \
	-R simian_M2Crypto-*-10.12-*.egg \
	-R .eggs/PyYAML-*.egg \
	-R .eggs/WebOb-*.egg \
	-R .eggs/google_apputils-*.egg \
	-R .eggs/pyasn1-*.egg \
	-R .eggs/python_dateutil-*.egg \
	-R .eggs/python_gflags-*.egg \
	-R .eggs/pytz-*.egg \
	-R .eggs/requests-*.egg \
	-R .eggs/tlslite-*.egg \
	-r ${SDIST} \
	-s postflight \
	-s preinstall \
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
	-R simian_M2Crypto-*-10.9-*.egg \
	-R simian_M2Crypto-*-10.10-*.egg \
	-R simian_M2Crypto-*-10.11-*.egg \
	-R simian_M2Crypto-*-10.12-*.egg \
	-R .eggs/PyYAML-*.egg \
	-R .eggs/WebOb-*.egg \
	-R .eggs/google_apputils-*.egg \
	-R .eggs/pyasn1-*.egg \
	-R .eggs/python_dateutil-*.egg \
	-R .eggs/python_gflags-*.egg \
	-R .eggs/pytz-*.egg \
	-R .eggs/requests-*.egg \
	-R .eggs/tlslite-*.egg \
	-r ${SDIST} \
	-s postflight \
	-s preinstall \
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
	-R simian_M2Crypto-*-10.9-*.egg \
	-R simian_M2Crypto-*-10.10-*.egg \
	-R simian_M2Crypto-*-10.11-*.egg \
	-R simian_M2Crypto-*-10.12-*.egg \
	-R .eggs/PyYAML-*.egg \
	-R .eggs/WebOb-*.egg \
	-R .eggs/google_apputils-*.egg \
	-R .eggs/pyasn1-*.egg \
	-R .eggs/python_dateutil-*.egg \
	-R .eggs/python_gflags-*.egg \
	-R .eggs/pytz-*.egg \
	-R .eggs/requests-*.egg \
	-R .eggs/tlslite-*.egg \
	-r ${SDIST} \
	-s postflight \
	-s preinstall \
	-s roots.pem

${SIMIAN}-and-${MUNKI}.dmg: os_check ${SDIST} clean_contents m2crypto add_munkicontents contents.tar.gz vep
	rm -f $@
	./tgz2dmg.sh contents.tar.gz $@ \
	-id com.google.code.simian.and.munkitools \
	-version ${SIMIAN_VERSION}.${MUNKI_VERSION} \
	-pyver ${PYTHON_VERSION} \
	-vep install_name_tool \
	-R simian_M2Crypto-*-10.9-*.egg \
	-R simian_M2Crypto-*-10.10-*.egg \
	-R simian_M2Crypto-*-10.11-*.egg \
	-R simian_M2Crypto-*-10.12-*.egg \
	-R .eggs/PyYAML-*.egg \
	-R .eggs/WebOb-*.egg \
	-R .eggs/google_apputils-*.egg \
	-R .eggs/pyasn1-*.egg \
	-R .eggs/python_dateutil-*.egg \
	-R .eggs/python_gflags-*.egg \
	-R .eggs/pytz-*.egg \
	-R .eggs/requests-*.egg \
	-R .eggs/tlslite-*.egg \
	-r ${SDIST} \
	-s postflight \
	-s preinstall \
	-s roots.pem

simian-pkg: ${SIMIAN}.pkg

pkg: ${SIMIAN}-and-${MUNKI}.pkg

dmg: ${SIMIAN}-and-${MUNKI}.dmg

release: server_config
	appcfg.py --version=${BUILD_VERSION} update gae_bundle/
	appcfg.py --version=${BUILD_VERSION} set_default_version gae_bundle/

release_with_oauth: server_config
	appcfg.py --version=${BUILD_VERSION} --oauth2 update gae_bundle/
	appcfg.py --version=${BUILD_VERSION} --oauth2 set_default_version gae_bundle/
