# A QUIC handshake parameter grabber

quic-grabber grabs handshake paramter during a QUIC handshake.
It powers: https://quic.comsys.rwth-aachen.de

It uses a slightly modified [quic-go](https://github.com/lucas-clemente/quic-go) library.


## Guides

### Building the program

Fetch and update dependencies:

	go get -t -u ./...

We need customizations to the quic-go library to trace the connections:

Add them as a remote to the src/github.com/lucas-clemente/quic-go repositroy in your $GOPATH:

	https://github.com/konnykonny50/quic-go

and fetch the head

For details on how to do this see:

	https://splice.com/blog/contributing-open-source-git-repositories-go/

Now you can build the quic-grabber using
	go build


### Running the program
The program reads targets from stdin as linewise json objects and outputs scanned hosts as linewise json objects on stdout.

Each json input line can be an arbitrary json object, yet it must contain an "addr" and an "sni" field.
The address must be in the form of: "host:port" where host can be an IP or a DNS name and port is the port to connect to, "sni" must be a valid hostname that is presented to the server.

The program will add up to three fields to the json (and will otherwise mirror the input).
"rejTags", "shloTags", "error" containing key/value pairs of the handshake parameters or errors encountered.


You can use the decode_tags.py to decode the tags to useful values.
But to allow certificate decoding you require common certificate sets which can be obtained from the chromium source.
Use the gen_common_certs.sh to download and convert the certs to a python readable format.


## Example usage

	echo '{"addr": "www.google.com:443", "sni": "www.google.com"}' | ./quic-grabber | python ./decode_tags.py 