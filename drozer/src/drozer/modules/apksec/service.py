from pydiesel.reflection import ReflectionException
from drozer.modules import Module, common
from drozer.modules.common.package_manager import PackageManager
from drozer import android
from drozer.modules.apksec.logcat_logs import read_shell, cutoff_system_print
from drozer.modules.apksec.config import START_SERVICE
import os
import sys
import time

class Detect(Module, common.Filters, common.PackageManager, common.Provider, common.Strings, common.FileSystem, common.ZipFile):
    name = "Detect Service Security Hole"
    description = "Detect the services, find the security holes"
    examples = "run apksec.service.detect"
    date = "2015-10-14"
    author = "Xiaofang Huang"
    license = "MWR Code License"
    path = ["apksec","service"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", default = None, help = "specify the package to inspect")

    def execute(self, arguments):
        reload(sys)
        sys.setdefaultencoding('utf-8')

        shell = self.new("com.mwr.jdiesel.util.Shell")
        shell.write("su\n")
        shell.write("logcat ContextImplcheckPermission:E IntentExtra:E AndroidRuntime:E *:S")
        shell.write("logcat -d")
        shell.write("logcat -c")
        logs = read_shell(shell, 1)
        #self.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!logs before detecting is...\n%s\n" % logs)

        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package, PackageManager.GET_SERVICES | PackageManager.GET_PERMISSIONS)
            services = self.__get_services(package)

            count = 0
            service_detect_result = {} #20160317
            self.stdout.write("service detecting starts...\n")
            for service in services:
                shell.write("logcat ContextImplcheckPermission:E IntentExtra:E AndroidRuntime:E *:S")
                logs = read_shell(shell, 1)        

                count = count + 1
                self.stdout.write("  service No.%d: %s\n" % (count, service.name))

                time.sleep(1)
                # Serializable added 20151113
                start_components = self.new("com.mwr.dz.apksec.StartComponents")
                start_components.startcomponent(arguments.package, service.name, START_SERVICE, self.getContext())

                shell.write("logcat -d")
                logs = read_shell(shell, 1)
                logs = cutoff_system_print(logs)
                service_detect_result[service.name] = logs #20160317
                self.stdout.write("+++++++++++++++++++++++++++++++++++++++++LOGS of %s++++++++++++++++++++++++++++++++++++++++\n%s\n" % (service.name, logs))
                self.stdout.flush()
                shell.write("logcat -c")
                
            #20160317
            service_detect_result = str(service_detect_result)
            #self.stdout.write(service_detect_result)
                
        else:
            self.stdout.write("package could not be None\n'")

        shell.close()


    def __get_services(self, package):
        exported_services = self.match_filter(package.services, "exported", True)
        hidden_services = self.match_filter(package.services, "exported", False)

        return exported_services


