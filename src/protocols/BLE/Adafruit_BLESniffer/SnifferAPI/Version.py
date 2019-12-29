from __future__ import absolute_import
from . import myVersion

pdfVersion = "1.2"


def getRevision():
    return myVersion.version


def getVersionString(mRevision=getRevision()):
    # prevRev = 0

    # if mRevision == 0:
        # return "0.0.0"
    # for rev in versions:
        # if rev > int(mRevision):
            # return versions[prevRev]
        # prevRev = rev
    # return versions[prevRev]

    return myVersion.versionString + myVersion.versionNameAppendix


def getPureVersionString(mRevision=getRevision()):
    return myVersion.versionString


def getUserGuideFileName(version=pdfVersion, platformName="win", deliverableName="ble-sniffer",
                         itemName="User Guide.pdf"):
    return str(deliverableName) + "_" + str(platformName) + "_" + str(version) + "_" + str(itemName)


def getReadableVersionString(mRevision=getRevision()):
    return "SVN rev. "+str(mRevision) if mRevision else "version information unavailable"


def getFileNameVersionString(mRevision=getRevision(), itemName="", platformName="win",
                             deliverableName="ble-sniffer"):
    ver = getVersionString(mRevision)
    if itemName != "":
        return str(deliverableName)+"_"+str(platformName)+"_"+str(ver)+"_"+str(itemName)
    else:
        return str(deliverableName)+"_"+str(platformName)+"_"+str(ver)
