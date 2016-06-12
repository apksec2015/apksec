from drozer.modules import Module, common
from drozer.modules.common.package_manager import PackageManager
from drozer import android
from drozer.modules.apksec.logcat_logs import read_shell, cutoff_system_print
from drozer.modules.apksec.config import SEND_BROADCAST
import os
import sys
import time

class Detect(Module, common.Filters, common.PackageManager, common.Provider, common.Strings, common.FileSystem, common.ZipFile):
    name = "Detect Broadcast Security Hole"
    description = "Detect the services, find the security holes"
    examples = "run apksec.broadcast.detect"
    date = "2015-10-26"
    author = "Xiaofang Huang"
    license = "MWR Code License"
    path = ["apksec","broadcast"]
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
        #self.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!LOGS before detecting is :\n%s\n" % logs)

        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package, PackageManager.GET_RECEIVERS | PackageManager.GET_PERMISSIONS)
            receivers = self.__get_receivers(package)

            count = 0
            broadcast_detect_result = {} #20160317
            self.stdout.write("broadcast detecting starts...\n")
            
            for receiver in receivers:
		shell.write("logcat ContextImplcheckPermission:E IntentExtra:E AndroidRuntime:E *:S")
		logs = read_shell(shell, 1)
				
                count = count + 1
                self.stdout.write("  No.%d: %s\n" % (count, receiver.name))

                time.sleep(1)
                # Serializable added 20151113
                start_components = self.new("com.mwr.dz.apksec.StartComponents")
                start_components.startcomponent(arguments.package, receiver.name, SEND_BROADCAST, self.getContext())

		shell.write("logcat -d")
                logs = read_shell(shell, 1)
                logs = cutoff_system_print(logs)
                broadcast_detect_result[receiver.name] = logs #20160317
                self.stdout.write("++++++++++++++++++++++++++++++++++++++++LOGS of %s++++++++++++++++++++++++++++++++++++++++\n%s\n" % (receiver.name, logs))
                self.stdout.flush()
                shell.write("logcat -c")
            
            #20160317    
            broadcast_detect_result = str(broadcast_detect_result)
            #self.stdout.write(broadcast_detect_result)
                
        else:
            self.stdout.write("package could not be None\n'")

        shell.close()


    def __get_receivers(self, package):
        exported_receivers = self.match_filter(package.receivers, "exported", True)
        hidden_receivers = self.match_filter(package.receivers, "exported", False)

        return exported_receivers


