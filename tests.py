__author__ = 'bwall'
import spickle
import pickle
import new
import subprocess
import unittest
import StringIO

"""
Here we attempt attacks against Pickle which should not work in spickle.
"""


class Macavity(object):
    pass


class RunBinSh(object):
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/ls', "/tmp"),))


class ReconstructorWithMorePickling(object):
    def __reduce__(self):
        return (spickle._reconstructor, (pickle.Unpickler, str, StringIO.StringIO(
            "csubprocess\nPopen\np0\n((S'/bin/ls'\np1\nS'/tmp'\np2\ntp3\ntp4\nRp5.")))


class LegitimateGlobalAssignment(object):
    def __init__(self):
        self.k = spickle.HIGHEST_PROTOCOL


class HasDict(object):
    def __init__(self):
        self.d = {"a": 5, "b": "asdagf"}


class TestBasicFunctionality(unittest.TestCase):
    def test_integer(self):
        self.assertEqual(5, spickle.loads(pickle.dumps(5)))

    def test_string(self):
        self.assertEqual("ohai ;)", spickle.loads(pickle.dumps("ohai ;)")))

    def test_tuple(self):
        self.assertEqual((1, 3, ("hello", 5.0)), spickle.loads(pickle.dumps((1, 3, ("hello", 5.0)))))

    def test_list(self):
        l = [1, 2, 3, 4, 5, "hello", (9, 8, 3)]
        self.assertEqual(l, spickle.loads(pickle.dumps(l)))

    def test_dictionary(self):
        d = {"a": 1, "b": 2, "c": 3}
        self.assertEqual(d, spickle.loads(pickle.dumps(d)))

    def test_object_with_dict(self):
        d = HasDict()
        self.assertEqual(d.d, spickle.loads(pickle.dumps(d)).d)


class TestGetInitArgs(unittest.TestCase):
    # from http://www.securityfocus.com/bid/5257/exploit
    def test_sf_payload(self):
        with self.assertRaises(spickle.UnpicklingError):
            def nasty(module, function, *args):
                return pickle.dumps(new.classobj(function, (), {
                    '__getinitargs__': lambda self, arg=args: arg,
                    '__module__': module
                })())

            t = nasty("subprocess", "Popen", ("/bin/ls", "/tmp"))
            spickle.loads(t)


class TestReduceAttack(unittest.TestCase):
    def test_basic_attack(self):
        c = pickle.dumps(RunBinSh())
        with self.assertRaises(spickle.UnpicklingError):
            spickle.loads(c)

        # def test_attack_against_reconstructor(self):
        #        with self.assertRaises(spickle.UnpicklingError):
        #            spickle.loads(pickle.dumps(ReconstructorWithMorePickling()))

    def test_functionality_remains(self):
        c = pickle.dumps(Macavity())
        self.assertEqual(spickle.loads(c).__class__, Macavity().__class__)


class TestWapiflapiAttack(unittest.TestCase):
    def test_legitimate_global_assignment(self):
        spickle.loads(spickle.dumps(LegitimateGlobalAssignment()))

    def test_global_assignment_attack(self):
        with self.assertRaises(spickle.UnpicklingError):
            spickle.loads("cspickle\n__dict__\nS'mloads'\ncos\nsystem\nsJ;ls;.")

    def test_set_state_abuse(self):
        with self.assertRaises(spickle.UnpicklingError):
            spickle.loads("cspickle\nsys\n(}(S'__setstate__'\ncos\nsystem\ndtbS'ls'\nb.")

# todo Investigate attacks directly against marshal


if __name__ == '__main__':
    unittest.main()