# spickle
After finding quite a few implementations of Python projects continuing to use Pickle
despite the security concerns, it has become somewhat obvious that there needs to be a
safe implementation of Pickle.  By safe, I mean avoiding deserialization vulnerabilities
leading to trivial code execution in all cases.

This library is not yet vetted and is essentially in "pre-beta".  This code should not yet
be used with any expectation of security.

Please take your time in trying to break it and execute
code.  Folks who do manage to cause code execution through the deserialization process
will be recognized here.  Proof of concepts should be added to "tests.py".


This implementation is currently based on https://github.com/python/cpython/blob/2.7/Lib/pickle.py
The license for the original code can be found here: https://github.com/python/cpython/blob/master/LICENSE

# Hall of Fame
@wapiflapi - 2 vulnerability/exploit, 1 bug
