INSTALLATION on Windows

Download and install MinGW and MSYS.  Install MinGW first.  To avoid
problems with spaces in file names, create a soft link to the DLL that
provides the TCG Software Stack.  (Hint, use completion to link this
file.)

$ ln -s /c/Program\ Files/NTRU\ Cryptosystems/NTRU\ TCG\ Software\
\ Stack/bin/Tsp1.dll" ..

Configure with:

$ ./configure LDFLAGS=-L.. LIBS=-lTsp1

$ make

$ make install

			   ****************

There is a bug in some versions of the autoconf tools.  If your
config.h does define WIN32, try running

$ autoreconf -if

to build a new version of the configuration scripts.
