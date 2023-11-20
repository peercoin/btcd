ppcd (beta) for peercoin

## This version is strictly beta quality.
## Expect it to break without notice.

#### Known issues / bugs

- Database format for storing and retrieving block meta is not final
- Script verification fails on 4 blocks on mainnet,  
  which means script verification has been disabled for those blocks currently
  - check `chaincfg/params.go#316` and `blockchain/validate.go#1235` for more details
- Protocol missmatch(es) compared to upstream  
  Not all protocol changes have been ported completely just yet
  - V12 isn't being checked for when disconnecting blocks
- RPC server is missing peercoin specific updates
- No support for sendcmpct or wtxidrelay

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Ensure Go was installed properly and is a supported version:

```bash
$ go version
$ go env GOROOT GOPATH
```

NOTE: The `GOROOT` and `GOPATH` above must not be the same path.  It is
recommended that `GOPATH` is set to a directory in your home directory such as
`~/goprojects` to avoid write permission issues.  It is also recommended to add
`$GOPATH/bin` to your `PATH` at this point.

- To simply build the binary, without installing it, the following command should suffice:

```bash
$ git clone https://github.com/peercoin/ppcd && cd ppcd
$ go build
# run it using ./ppcd
```

- Run the following commands to obtain ppcd, all dependencies, and install it:

```bash
$ cd $GOPATH/src/github.com/peercoin/ppcd
$ GO111MODULE=on go install -v . ./cmd/...
```

- ppcd (and utilities) will now be installed in ```$GOPATH/bin```.  If you did
  not already add the bin directory to your system path during Go installation,
  we recommend you do so now.

## Updating

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Run the following commands to update ppcd, all dependencies, and install it:

```bash
$ cd $GOPATH/src/github.com/peercoin/ppcd
$ git pull
$ GO111MODULE=on go install -v . ./cmd/...
```

## Getting Started

ppcd has several configuration options available to tweak how it runs, but all
of the basic operations described in the intro section work with zero
configuration.

#### Linux/BSD/POSIX/Source

```bash
$ ./ppcd
```

## License

ppcd is licensed under the [copyfree](http://copyfree.org) ISC License.
