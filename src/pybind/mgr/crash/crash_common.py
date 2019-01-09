import os
import subprocess
import signal
import time
import datetime
import json
import errno
import logging

#crash_log = logging.getLogger(__name__)

def isNotEmpty(data_str):
    return bool(data_str and data_str.strip())


def isEmpty(data_str):
    return bool(not data_str and not data_str.strip())


def cmd_launcher(**kwargs):
    exec_string = kwargs.get('cmd', None)
    env_string = kwargs.get('env', None)
    timeout_string = kwargs.get('timeout', None)
    workdir_string = kwargs.get('cwd', None)
    workdir_original = None

    if isEmpty(env_string):
        env_string = os.environ

    if isEmpty(timeout_string):
        timeout_string = 30

    if isEmpty(exec_string):
        return 256, '', ''

    # Handling directory changes
    if isNotEmpty(workdir_string):
        workdir_original = os.getcwd()
        os.chdir(workdir_string)

    #crash_log.debug("Executing command " + exec_string)
    process = subprocess.Popen([exec_string],
                               shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               env=env_string,
                               bufsize=0)

    if isNotEmpty(workdir_original):
        os.chdir(workdir_original)

    process_counter = 0
    process_retcode = None
    handle_process = True
    stdout = ''
    stderr = ''
    while handle_process:
        process_counter += 1
        cout, cerr = process.communicate()
        stdout += cout
        stderr += cerr

        process.poll()
        process_retcode = process.returncode
        if process_retcode != None:
            break
        if process_counter == timeout_string:
            os.kill(process.pid, signal.SIGQUIT)
        if process_counter > timeout_string:
            os.kill(process.pid, signal.SIGKILL)
            process_retcode = -9
            break

        time.sleep(1)
    return (process_retcode, stdout, stderr)


def eval_launcher_returns(cmd,
                          check_cmd_success=False,
                          handout_err_msg=False):
    rc, stdout, stderr = cmd_launcher(cmd=cmd)
    # Only checks if the cmd is/was successful
    if check_cmd_success:
        return bool(rc)

    '''
        If not checking out success only, we still have the option to
        pass along the error msgs, or assert in case we are not handing
        out the errors to the caller.
    '''
    if not handout_err_msg:
        assert (rc == 0), 'Error while executing the command {}. \
                           Error message: {}'.format(cmd, stderr)
    return stdout, stderr


def does_file_exist(file_path):
    return (os.path.exists(file_path) and 
            os.path.isfile(file_path))


def does_dir_exist(dir_path):
    return (os.path.exists(dir_path) and 
            os.path.isdir(dir_path))


def does_tool_exist(tool_name):
    cmd = 'which {} | wc -l'.format(tool_name)

    rc, stdout, stderr = cmd_launcher(cmd=cmd)
    if rc != 0:
        raise Exception('Error while executing the command {}. \
                         Error message: {}'.format(cmd, stderr))
    return (int(stdout.strip()) >= 1)
