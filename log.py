import sys

def log_stdout(message):
    """
    Takes a string and writes it to stdout
    """
    sys.stdout.write("[+] %s\n"  % message)


def log_stderr(message):
    """
    Takes a string and writes it to stderr
    """
    sys.stderr.write("[-] %s\n" % message)
