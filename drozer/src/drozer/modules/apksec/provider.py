from pydiesel.reflection import ReflectionException
from drozer.modules import Module, common
from drozer.modules.common.package_manager import PackageManager
from drozer import android
import os, sys

class Detect(Module, common.Filters, common.PackageManager, common.Provider, common.Strings, common.FileSystem, common.ZipFile):
    name = "Detect Provider Security Hole"
    description = "Detect the providers, find the security holes"
    examples = "run apksec.provider.detect"
    date = "2015-10-14"
    author = "Xiaofang Huang"
    license = "MWR Code License"
    path = ["apksec","provider"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", default = None, help = "specify the package to inspect")

    def execute(self, arguments):
        self.stdout.write("Successfully relize a new module named 'apksec.provider.detect'!\n")

        reload(sys)
        sys.setdefaultencoding('utf-8')

        shell = self.new("com.mwr.jdiesel.util.Shell")
        shell.write("su\n")
        cursor = None

        shell.write("logcat QUERY_SQL:E *:S INSERT_SQL:E *:S UPDATE_SQL:E *:S DELETE_SQL:E *:S")
        shell.read()

        if arguments.package != None:
            count = 1
            self.stdout.write("provider uri detecting starts...\n")

            for uri in self.findAllContentUris(arguments.package):
                self.stdout.write("  No.%d: %s\n" % (count, uri))
                count = count + 1

                try:
                    cursor = self.contentResolver().query(uri)
                except ReflectionException as e:
                    self.stdout.write("Could not query from URI %s \n" % uri)
                    continue

                if cursor != None:
                    self.stdout.write("Accessible Tables From URI: %s \n" % uri)
                    if(str(uri).startswith("content://media/internal/audio/")):
                        pass
        else:
            self.stdout.write("packagename could not be None!\n ")

        shell.close()


    def findAllContentUris(self, package):
        uris = set([])

        if package == None:
            for package in self.packageManager().getPackages(PackageManager.GET_PROVIDERS | PackageManager.GET_URI_PERMISSION_PATTERNS):
                try:
                    uris = uris.union(self.__search_package(package))
                except ReflectionException as e:
                    if "java.util.zip.ZipException: unknown format" in e.message:
                        self.stderr.write("Skipping package %s, because we cannot unzip it..." % package.applicationInfo.packageName)
                    else:
                        raise
        else:
            package = self.packageManager().getPackageInfo(package, PackageManager.GET_PROVIDERS)
            try:
                uris = uris.union(self.__search_package(package))
                uid = package.applicationInfo.uid
            except ReflectionException as e:
                if "java.util.zip.ZipException: unknown format" in e.message:
                    self.stderr.write("Skipping package %s, because we cannot unzip it..." % package.applicationInfo.packageName)
                else:
                    raise

        return uris


    def __search_package(self, package):
        uris = set([])

        if package.providers != None:
            for provider in package.providers:
                if provider.authority != None:
                    paths = set([])

                    if provider.uriPermissionPatterns != None:
                        for pattern in provider.uriPermissionPatterns:
                            paths.add(pattern.getPath())
                    if provider.pathPermissions != None:
                        for permission in provider.pathPermissions:
                            paths.add(permission.getPath())

                    for authority in provider.authority.split(";"):
                        uris.add("content://%s/" % authority)
                        for path in paths:
                            uris.add("content://%s%s" % (authority, path))

        for (path, content_uris) in self.findContentUris(package.packageName):
            if len(content_uris) > 0:
                for uri in content_uris:
                    uris.add(uri[uri.upper().find("CONTENT"):])

        for uri in set(uris):
            if uri.endswith("/"):
                uris.add(uri[uri.upper().find("CONTENT"):-1])
            else:
                uris.add(uri[uri.upper().find("CONTENT"):] + "/")

        return sorted(uris)


