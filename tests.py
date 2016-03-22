__author__ = 'bwall'
import spickle
import pickle
import new
import subprocess

"""
Here we attempt attacks against Pickle which should not work in spickle.
"""


# from http://www.securityfocus.com/bid/5257/exploit
def nasty(module, function, *args):
    return pickle.dumps(new.classobj(function, (), {
        '__getinitargs__': lambda self, arg = args: arg,
        '__module__': module
        }) ())

t = nasty("subprocess", "Popen", ("/bin/ls", "/tmp"))
print spickle.loads(t)


# from https://blog.nelhage.com/2011/03/exploiting-pickle/
class RunBinSh(object):
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/ls', "/tmp"),))


c = pickle.dumps(RunBinSh())
print spickle.loads(c)

