import time
import string

def init_logcat(shell):
	shell.write("su\n")
	shell.write("logcat -c")

def read_shell(shell, waiting_time):
	time.sleep(waiting_time)
	return shell.read()

def close_logcat(shell):
	shell.write("logcat -c")
	shell.close()

# cutoff the system print '--------- beginning of /dev/log/main' && '--------- beginning of /dev/log/system'
def cutoff_system_print(logs):
	if logs.find("--------- beginning of /dev/log/main") == 0:
		logs = logs[37:]
	if logs.find("--------- beginning of /dev/log/system") == 0:
		logs = logs[39:]
	return logs
