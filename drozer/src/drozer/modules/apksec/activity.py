from pydiesel.reflection import ReflectionException
from drozer.modules import Module, common
from drozer.modules.common.package_manager import PackageManager
from drozer import android
from drozer.modules.apksec.logcat_logs import init_logcat, read_shell, close_logcat, cutoff_system_print
from drozer.modules.apksec.config import START_ACTIVITY
import os
import sys
import traceback
import time
import string

class Detect(Module, common.Filters, common.PackageManager, common.IntentFilter):
    name = "Detect Activity Security Hole"
    description = "Detect the activites, find the security holes"
    examples = "run apksec.activity.detect -a com.mwr.example.sieve"
    date = "2015-10-23"
    author = "Xiaofang Huang"
    licence = "MWR Code Licence"
    path = ["apksec", "activity"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", default = None, help = "specify the package to inspect")

    def execute(self, arguments):
        #self.stdout.write("Successfully relize a new module named 'apksec.activity.detect'\n")

        reload(sys)
        sys.setdefaultencoding("utf-8")

        shell = self.new("com.mwr.jdiesel.util.Shell")
        init_logcat(shell)
        shell.write("logcat ContextImplcheckPermission:E IntentExtra:E AndroidRuntime:E *:S")
        logs = read_shell(shell, 1)
        #self.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!logs before detecting is...\n%s\n" % logs)

        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package, PackageManager.GET_ACTIVITIES)
            activites = self.__get_activities(package)

            self.stdout.write("activity detecting starts...\n")
            activity_detect_result = {}#20160317
            count = 0
            for activity in activites:
                count = count + 1
                self.stdout.write("  No.%d: %s\n" % (count, activity.name))

                time.sleep(1)
                
                # Serializable added 20151113 
                start_components = self.new("com.mwr.dz.apksec.StartComponents")
                start_components.startcomponent(arguments.package, activity.name, START_ACTIVITY, self.getContext())
                logs = read_shell(shell, 1)
                logs = cutoff_system_print(logs)
                activity_detect_result[activity.name] = logs#20160317
                self.stdout.write("+++++++++++++++++++++++++++++++++++++++++LOGS of %s++++++++++++++++++++++++++++++++++++++++\n%s\n" % (activity.name, logs))
                self.stdout.flush() #added 20151116
                
            #20160317    
            activity_detect_result = str(activity_detect_result)
            #self.stdout.write(activity_detect_result)
                
        else:
            self.stdout.write("package could not be None!\n")

        #logs = read_shell(shell, 1)
        #self.stdout.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~logs after activity detecting:\n%s" % logs)
        
        close_logcat(shell)
        #self.stdout.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~logs Finished!!!!\n")

    def __get_activities(self, package):
        exported_activities = self.match_filter(package.activities, 'exported', True)
        hidden_activities = self.match_filter(package.activities, 'exported', False )
        return exported_activities


