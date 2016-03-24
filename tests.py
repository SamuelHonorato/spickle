__author__ = 'bwall'
import spickle
import pickle
import new
import subprocess
import unittest

"""
Here we attempt attacks against Pickle which should not work in spickle.
"""


class Macavity(object):
    pass


class RunBinSh(object):
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/ls', "/tmp"),))


class LegitimateGlobalAssignment(object):
    def __init__(self):
        self.k = spickle.HIGHEST_PROTOCOL


class TestGetInitArgs(unittest.TestCase):
    # from http://www.securityfocus.com/bid/5257/exploit
    def test_sf_payload(self):
        with self.assertRaises(spickle.UnpicklingError):
            def nasty(module, function, *args):
                return pickle.dumps(new.classobj(function, (), {
                    '__getinitargs__': lambda self, arg = args: arg,
                    '__module__': module
                    }) ())

            t = nasty("subprocess", "Popen", ("/bin/ls", "/tmp"))
            spickle.loads(t)


class TestReduceAttack(unittest.TestCase):
    def test_basic_attack(self):
        c = pickle.dumps(RunBinSh())
        with self.assertRaises(spickle.UnpicklingError):
            spickle.loads(c)

    def test_functionality_remains(self):
        c = pickle.dumps(Macavity())
        self.assertEqual(spickle.loads(c).__class__, Macavity().__class__)


class TestWapiflapiAttack(unittest.TestCase):
    def test_legitimate_global_assignment(self):
        spickle.loads(spickle.dumps(LegitimateGlobalAssignment()))

    def test_global_assignment_attack(self):
        with self.assertRaises(spickle.UnpicklingError):
            spickle.loads("cspickle\n__dict__\nS'mloads'\ncos\nsystem\nsJ;ls;.")

# todo Investigate attacks directly against marshal


if __name__ == '__main__':
    unittest.main()