Using the CUDA language, implement a program that calculates a string. The program processes two strings as follows:

An arbitrary string (s1).
A SHA-1 hashed string (s2).
A third string (x) needs to be calculated such that the string s1, concatenated with the string x, results in a SHA-1 hash equal to s2. The GPU must be used for this computation, and the algorithm should be parallelized.

In other words: given SHA1(s1 + x) = s2, where s1 and s2 are read from the user, calculate x.
