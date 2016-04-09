It is quite likely that Pickle would either need a drastic reduction in functionality, or radical changes, in order to fix the terrible mess the developers made in Pickle.  Unfortunately, I have to consider this project a failure at this point.

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
@wapiflapi - 3 vulnerability/exploit, 1 bug
