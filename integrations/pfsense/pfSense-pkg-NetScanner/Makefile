# $FreeBSD$

PORTNAME=	pfSense-pkg-NetScanner
PORTVERSION=	0.1.
PORTREVISION=	0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	NetScanner
COMMENT=	NetScanner network telemetry push agent for pfSense

LICENSE=	APACHE20

NO_BUILD=	yes
NO_MTREE=	yes
NO_ARCH=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	@${MKDIR} ${WRKSRC}

do-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	@${MKDIR} ${STAGEDIR}${PREFIX}/bin
	@${MKDIR} ${STAGEDIR}${PREFIX}/etc/netscanner
	@${MKDIR} ${STAGEDIR}${PREFIX}/www/packages/netscanner
	@${MKDIR} ${STAGEDIR}/etc/inc/priv
	@${MKDIR} ${STAGEDIR}${DATADIR}
	@${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/bin/netscanner-collect \
		${STAGEDIR}${PREFIX}/bin/netscanner-collect
	@${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/bin/netscanner-collect.php \
		${STAGEDIR}${PREFIX}/bin/netscanner-collect.php
	@${INSTALL_DATA} ${FILESDIR}${PREFIX}/etc/netscanner/agent.conf.example \
		${STAGEDIR}${PREFIX}/etc/netscanner/agent.conf.example
	@${INSTALL_DATA} -m 0644 ${FILESDIR}${PREFIX}/pkg/netscanner.xml \
		${STAGEDIR}${PREFIX}/pkg
	@${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/netscanner.inc \
		${STAGEDIR}${PREFIX}/pkg
	@${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/pkg/configure-pfsense.php \
		${STAGEDIR}${PREFIX}/pkg/configure-pfsense.php
	@${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/netscanner.priv.inc \
		${STAGEDIR}/etc/inc/priv
	@${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/packages/netscanner/index.php \
		${STAGEDIR}${PREFIX}/www/packages/netscanner
	@${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${PREFIX}/pkg/netscanner.xml \
		${STAGEDIR}${DATADIR}/info.xml

.include <bsd.port.mk>
