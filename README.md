# LogPicker++

This project contains the prototype implementation of the LogPicker protocol.


## Main Artifacts

### Tests

With the default configuration a successful build will output three test artifacts at `build/test`.

`test_rsa_util`, `test_crypto`
: Simple tests which ensure that relic works as expected.

`test_lpp_local`
: A local LogPicker test with 200 logs. All steps are executed sequentially in a single thread to verify functionality of basic protocol building blocks.

To **run the tests** simply execute the command `ctest` in the current build directory. Ideally executing this command should yield output similar to the following.

```
user@mbp:~/lpp/build$ ctest
Test project /home/testuser/lpp/build
    Start 1: test_rsa_util
1/3 Test #1: test_rsa_util ....................   Passed    0.07 sec
    Start 2: test_crypto
2/3 Test #2: test_crypto ......................   Passed    0.09 sec
    Start 3: test_lpp_local
3/3 Test #3: test_lpp_local ...................   Passed   25.25 sec

100% tests passed, 0 tests failed out of 3

Total Test time (real) =  25.41 sec
```

### LPP Binaries

With the default configuration a successful build will output the main binaries of the LogPicker prototype at `build/bin`. They provide a simple command line interface as follows.

#### leader \<config\> \<cert\>

Simulates the *leader* in a LogPicker run. At runtime the program will print timing information from the protocol run to the command line. The data are printed as comma separated data with the columns \<n logs\> \<t_start\> \<t_end\> \<t_end - t_start\>, where timestamps are printed in milliseconds.

Arguments:

\<config\> The LogPicker config file.

\<cert\> The certificate to be logged.

#### log \<id\> \<config\>
Simulates one *log* in a LogPicker run.

Arguments:

\<id\> A log id listed in the config file.

\<config\> The LogPicker config file.

#### client \<count\> \<config\> \<cert\>
Simulates 200 LogPicker *client* requests, e.g. from a certificate issuing CA. Each client request will be attested by the message "Started logpicker run" printed into the terminal.

Arguments:

\<count\> The number of logs required for the LogPicker Proof.

\<config\> The LogPicker config file.

\<cert\> The certificate to be logged.

### Resources

#### Example Config

An example LogPicker config file is provided at `data/config.xml`. This file works fine for local test runs. If a more involved distributed test is desired the IP addresses have to be adjusted.

#### Test Certificate
An example certificate for testing purpose is provided at `data/github/DER/github.com`.


## Dependencies

### Third Party Libraries

The following dependencies are required to build this project.

1. [Boost](https://www.boost.org) (tested with 1.71 and 1.76)
2. [fmt](https://fmt.dev) (tested with 6.1.2 and 7.1.3)
3. [GMP](https://gmplib.org) (tested with 6.2.0 and 6.2.1)
4. [sodium](https://libsodium.org) (tested with 1.0.18)

### Tools

1. git
2. cmake (3.14 or higher)
3. gcc or clang

**Remark:** The relic toolkit seems to have issues if built with gcc 11. Please make sure you are building the project with **gcc < 11** or clang (tested with Version 12).

## Build

With properly installed dependencies the following commands should suffice to build the code from within the project root.

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -Wno-dev ..
cmake --build .
```

The steps above will download some additional dependencies at configuration time. Depending on your Internet connection this step may take a while.

**Remark:** Enforcing a specific compiler for a build, e.g. with clang can be achieved with the following command line

```bash
CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=Release -Wno-dev ..
```

### Example Setup

On a freshly installed and up-to-date Ubuntu Desktop (20.04.2) the following command line installs all required dependencies which should suffice for a successful build.

```bash
sudo apt install git cmake build-essential libsodium-dev libboost-dev libgmp-dev libfmt-dev
```

## Run

To execute a LogPicker test run the *leader*, *logs* and *client* have to be started manually. Please make sure to start the *leader* and *logs* before starting the *client*.

### Example Test Run

For the sake of illustration consider an experiment with 4 available logs. The experiment will be run on the local host. All commands are executed within the projects root directory after the project has been built as described above.

First of all the *leader* is started by running the following command line.

```bash
build/bin/leader data/config.xml data/github/DER/github.com
```
This should generate no output. Next the $n=4$ logs with IDs $0, \dots, n-1$ are initialized by running the following commands.

```bash
build/bin/log 0 data/config.xml
build/bin/log 1 data/config.xml
build/bin/log 2 data/config.xml
build/bin/log 3 data/config.xml
```

Each command should be executed in a separate terminal. Invoking this command should not produce any further output. Finally the experiment is started by invoking the client with the following command line.

```bash
build/bin/client 4 data/config.xml data/github/DER/github.com
```

In this example all initialized *logs* will be involved. It is also possible to utilize only a subset of the initialized logs by adjusting the `count` argument. In case the `count` has to be in the range $(2, \dots, n)$.

In a successful experiment the *leader* will print timing information to the terminal. This should look like this:
```
4,443123365,443123568,203
4,443123359,443123568,209
4,443123359,443123568,209
4,443123356,443123569,213
4,443123225,443123570,345
4,443123326,443123571,245
4,443123495,443123575,80
4,443123494,443123577,83
4,443123493,443123578,85
4,443123321,443123579,258
4,443123322,443123584,262
...
4,443123609,443123760,151
4,443123608,443123761,153
4,443123541,443123761,220
4,443123598,443123761,163
4,443123612,443123779,167
4,443123617,443123782,165
4,443123613,443123786,173
```

Further the *client* program should attest the invocation of each LogPicker run by printing messages like the following:
```
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
Started logpicker run
...
```



**Hint:** One might be tempted  to invoke the commands for the experiment as background jobs. For example by starting the *logs* in a simple for loop with the `&` operator from within the same terminal/bash instance. This is **not** recommended since we encountered unexpected behavior which made the experiments fail. Please start the commands in separate terminal/bash instances.




